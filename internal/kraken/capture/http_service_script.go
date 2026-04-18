package capture

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

type httpServiceScriptBinding struct {
	script      scriptpkg.StoredScript
	hasRequest  bool
	hasResponse bool
}

type bufferedHTTPResponse struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newHTTPServiceHandler(
	base http.Handler,
	identity adoption.Identity,
	service string,
	port int,
	config map[string]string,
	binding *httpServiceScriptBinding,
	recordError func(error),
	clearError func(),
	localCertificate *scriptpkg.TLSCertificate,
) http.Handler {
	if base == nil || binding == nil {
		return base
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		scriptRequest, err := materializeScriptHTTPRequest(request)
		if err != nil {
			failHTTPServiceScript(writer, recordError, fmt.Errorf("read scripted request: %w", err))
			return
		}

		ctx := buildHTTPServiceScriptContext(identity, service, port, config, request, localCertificate)
		if binding.hasRequest {
			shortCircuit, err := scriptpkg.ExecuteHTTPRequest(binding.script, &scriptRequest, ctx, nil)
			if err != nil {
				failHTTPServiceScript(writer, recordError, err)
				return
			}
			if err := applyScriptHTTPRequest(request, scriptRequest); err != nil {
				failHTTPServiceScript(writer, recordError, err)
				return
			}
			if shortCircuit != nil {
				clearHTTPServiceScriptError(clearError)
				writeScriptHTTPResponse(writer, *shortCircuit)
				return
			}
		}

		if !binding.hasResponse {
			clearHTTPServiceScriptError(clearError)
			base.ServeHTTP(writer, request)
			return
		}

		recorder := newBufferedHTTPResponse()
		base.ServeHTTP(recorder, request)

		scriptResponse := scriptHTTPResponseFromBuffered(recorder)
		if err := scriptpkg.ExecuteHTTPResponse(binding.script, &scriptRequest, &scriptResponse, ctx, nil); err != nil {
			failHTTPServiceScript(writer, recordError, err)
			return
		}

		clearHTTPServiceScriptError(clearError)
		writeScriptHTTPResponse(writer, scriptResponse)
	})
}

func materializeScriptHTTPRequest(request *http.Request) (scriptpkg.HTTPRequest, error) {
	if request == nil {
		return scriptpkg.HTTPRequest{}, fmt.Errorf("request is required")
	}

	var body []byte
	if request.Body != nil {
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			return scriptpkg.HTTPRequest{}, err
		}
		body = payload
		if len(body) == 0 {
			request.Body = http.NoBody
		} else {
			request.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	target := request.RequestURI
	if target == "" && request.URL != nil {
		target = request.URL.RequestURI()
	}

	return scriptpkg.HTTPRequest{
		Method:  request.Method,
		Target:  target,
		Version: request.Proto,
		Host:    request.Host,
		Headers: scriptHeadersFromHTTPHeader(request.Header),
		Body:    body,
	}, nil
}

func applyScriptHTTPRequest(request *http.Request, scriptRequest scriptpkg.HTTPRequest) error {
	if request == nil {
		return fmt.Errorf("request is required")
	}
	if strings.TrimSpace(scriptRequest.Method) == "" {
		return fmt.Errorf("http.request.method is required")
	}
	if scriptRequest.Target == "" {
		return fmt.Errorf("http.request.target is required")
	}

	parsedURL, err := url.ParseRequestURI(scriptRequest.Target)
	if err != nil {
		return fmt.Errorf("http.request.target: %w", err)
	}

	request.Method = strings.TrimSpace(scriptRequest.Method)
	request.RequestURI = scriptRequest.Target
	request.URL = parsedURL
	request.Host = scriptRequest.Host
	request.Header = httpHeaderFromScriptHeaders(scriptRequest.Headers)
	request.ContentLength = int64(len(scriptRequest.Body))
	if len(scriptRequest.Body) == 0 {
		request.Body = http.NoBody
	} else {
		request.Body = io.NopCloser(bytes.NewReader(scriptRequest.Body))
	}
	if scriptRequest.Version != "" {
		major, minor, ok := http.ParseHTTPVersion(scriptRequest.Version)
		if !ok {
			return fmt.Errorf("http.request.version: unsupported HTTP version %q", scriptRequest.Version)
		}
		request.Proto = scriptRequest.Version
		request.ProtoMajor = major
		request.ProtoMinor = minor
	}

	return nil
}

func buildHTTPServiceScriptContext(identity adoption.Identity, service string, port int, config map[string]string, request *http.Request, localCertificate *scriptpkg.TLSCertificate) scriptpkg.HTTPExecutionContext {
	ctx := scriptpkg.HTTPExecutionContext{
		ScriptName: strings.TrimSpace(config["httpScriptName"]),
		Service: scriptpkg.HTTPServiceInfo{
			Name:          service,
			Port:          port,
			RootDirectory: strings.TrimSpace(config["rootDirectory"]),
			UseTLS:        httpServiceProtocol(config) == "https",
		},
	}
	if identity != nil {
		ctx.Adopted = scriptpkg.ExecutionIdentity{
			Label:          identity.Label(),
			IP:             identity.IP().String(),
			MAC:            identity.MAC().String(),
			InterfaceName:  identity.Interface().Name,
			DefaultGateway: common.IPString(identity.DefaultGateway()),
			MTU:            int(identity.MTU()),
		}
	}
	if request != nil {
		ctx.Connection.RemoteAddress = request.RemoteAddr
		ctx.TLS = buildHTTPServiceTLSInfo(request.TLS, localCertificate)
	}
	return ctx
}

func buildHTTPServiceTLSInfo(state *tls.ConnectionState, localCertificate *scriptpkg.TLSCertificate) scriptpkg.HTTPTLSInfo {
	if state == nil {
		return scriptpkg.HTTPTLSInfo{Enabled: false}
	}

	info := scriptpkg.HTTPTLSInfo{
		Enabled:            true,
		Version:            tlsVersionName(state.Version),
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		ServerName:         state.ServerName,
		NegotiatedProtocol: state.NegotiatedProtocol,
		LocalCertificate:   localCertificate,
	}
	if len(state.PeerCertificates) != 0 {
		info.PeerCertificates = make([]scriptpkg.TLSCertificate, 0, len(state.PeerCertificates))
		for _, item := range state.PeerCertificates {
			info.PeerCertificates = append(info.PeerCertificates, tlsCertificateFromX509(item))
		}
	}

	return info
}

func tlsCertificateFromX509(certificate *x509.Certificate) scriptpkg.TLSCertificate {
	if certificate == nil {
		return scriptpkg.TLSCertificate{}
	}

	info := scriptpkg.TLSCertificate{
		Subject:      certificate.Subject.String(),
		Issuer:       certificate.Issuer.String(),
		SerialNumber: certificate.SerialNumber.String(),
		DNSNames:     append([]string(nil), certificate.DNSNames...),
		NotBefore:    certificate.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter:     certificate.NotAfter.UTC().Format(time.RFC3339Nano),
	}
	if len(certificate.IPAddresses) != 0 {
		info.IPAddresses = make([]string, 0, len(certificate.IPAddresses))
		for _, item := range certificate.IPAddresses {
			info.IPAddresses = append(info.IPAddresses, item.String())
		}
	}
	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return strconv.FormatUint(uint64(version), 10)
	}
}

func scriptHeadersFromHTTPHeader(header http.Header) []scriptpkg.HTTPHeader {
	if len(header) == 0 {
		return nil
	}

	count := 0
	for _, values := range header {
		if len(values) == 0 {
			count++
			continue
		}
		count += len(values)
	}

	headers := make([]scriptpkg.HTTPHeader, 0, count)
	for name, values := range header {
		if len(values) == 0 {
			headers = append(headers, scriptpkg.HTTPHeader{Name: name, Value: ""})
			continue
		}
		for _, value := range values {
			headers = append(headers, scriptpkg.HTTPHeader{Name: name, Value: value})
		}
	}
	return headers
}

func httpHeaderFromScriptHeaders(headers []scriptpkg.HTTPHeader) http.Header {
	if len(headers) == 0 {
		return nil
	}

	values := make(http.Header, len(headers))
	for _, item := range headers {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		items := values[name]
		if items == nil {
			values[name] = []string{item.Value}
			continue
		}
		values[name] = append(items, item.Value)
	}
	return values
}

func newBufferedHTTPResponse() *bufferedHTTPResponse {
	return &bufferedHTTPResponse{
		header: make(http.Header),
	}
}

func (response *bufferedHTTPResponse) Header() http.Header {
	return response.header
}

func (response *bufferedHTTPResponse) Write(payload []byte) (int, error) {
	if response.statusCode == 0 {
		response.statusCode = http.StatusOK
	}
	return response.body.Write(payload)
}

func (response *bufferedHTTPResponse) WriteHeader(statusCode int) {
	if response.statusCode != 0 {
		return
	}
	response.statusCode = statusCode
}

func scriptHTTPResponseFromBuffered(response *bufferedHTTPResponse) scriptpkg.HTTPResponse {
	statusCode := http.StatusOK
	if response != nil && response.statusCode != 0 {
		statusCode = response.statusCode
	}

	body := []byte(nil)
	if response != nil {
		body = response.body.Bytes()
	}

	return scriptpkg.HTTPResponse{
		StatusCode: statusCode,
		Reason:     http.StatusText(statusCode),
		Version:    "HTTP/1.1",
		Headers:    scriptHeadersFromHTTPHeader(response.header),
		Body:       body,
	}
}

func writeScriptHTTPResponse(writer http.ResponseWriter, response scriptpkg.HTTPResponse) {
	if writer == nil {
		return
	}

	header := writer.Header()
	for key := range header {
		delete(header, key)
	}
	for key, values := range httpHeaderFromScriptHeaders(response.Headers) {
		for _, value := range values {
			header.Add(key, value)
		}
	}

	statusCode := response.StatusCode
	if statusCode <= 0 {
		statusCode = http.StatusOK
	}
	writer.WriteHeader(statusCode)
	_, _ = writer.Write(response.Body)
}

func writeHTTPServiceFailure(writer http.ResponseWriter) {
	if writer == nil {
		return
	}

	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusInternalServerError)
	_, _ = writer.Write([]byte("HTTP service script failed"))
}

func failHTTPServiceScript(writer http.ResponseWriter, recordError func(error), err error) {
	recordHTTPServiceScriptError(recordError, err)
	writeHTTPServiceFailure(writer)
}

func recordHTTPServiceScriptError(recordError func(error), err error) {
	if recordError == nil || err == nil {
		return
	}
	recordError(fmt.Errorf("HTTP service script: %w", err))
}

func clearHTTPServiceScriptError(clearError func()) {
	if clearError == nil {
		return
	}
	clearError()
}
