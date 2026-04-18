package script

import (
	"fmt"
	"net/http"
	"strings"

	"go.starlark.net/starlark"
)

func HTTPServiceHooks(script StoredScript) (bool, bool, error) {
	if err := validateExecutableScript(script, SurfaceHTTPService); err != nil {
		return false, false, err
	}

	_, globals, err := initScriptGlobals(script, nil, nil)
	if err != nil {
		return false, false, err
	}

	_, hasRequest := globals[httpServiceRequestHookName].(starlark.Callable)
	_, hasResponse := globals[httpServiceResponseHookName].(starlark.Callable)
	return hasRequest, hasResponse, nil
}

func ExecuteHTTPRequest(script StoredScript, request *HTTPRequest, ctx HTTPExecutionContext, logf LogFunc) (*HTTPResponse, error) {
	if err := validateExecutableScript(script, SurfaceHTTPService); err != nil {
		return nil, err
	}

	requestValue := newHTTPRequestValue(request)
	ctxValue, err := newHTTPContextValue(ctx)
	if err != nil {
		return nil, err
	}

	thread, globals, err := initScriptGlobals(script, logf, nil)
	if err != nil {
		return nil, err
	}

	callable, ok := globals[httpServiceRequestHookName].(starlark.Callable)
	if !ok {
		return nil, applyHTTPRequestValue(requestValue, request)
	}

	result, err := starlark.Call(thread, callable, starlark.Tuple{requestValue, ctxValue}, nil)
	if err != nil {
		return nil, normalizeRuntimeError(err)
	}
	if err := applyHTTPRequestValue(requestValue, request); err != nil {
		return nil, err
	}
	if isNone(result) {
		return nil, nil
	}

	response, err := httpResponseFromValue(result)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func ExecuteHTTPResponse(script StoredScript, request *HTTPRequest, response *HTTPResponse, ctx HTTPExecutionContext, logf LogFunc) error {
	if err := validateExecutableScript(script, SurfaceHTTPService); err != nil {
		return err
	}

	requestValue := newHTTPRequestValue(request)
	responseValue := newHTTPResponseValue(response)
	ctxValue, err := newHTTPContextValue(ctx)
	if err != nil {
		return err
	}

	thread, globals, err := initScriptGlobals(script, logf, nil)
	if err != nil {
		return err
	}

	callable, ok := globals[httpServiceResponseHookName].(starlark.Callable)
	if !ok {
		return nil
	}

	result, err := starlark.Call(thread, callable, starlark.Tuple{requestValue, responseValue, ctxValue}, nil)
	if err != nil {
		return normalizeRuntimeError(err)
	}
	if !isNone(result) {
		updated, err := httpResponseFromValue(result)
		if err != nil {
			return err
		}
		*response = updated
		return nil
	}

	return applyHTTPResponseValue(responseValue, response)
}

func newHTTPContextValue(ctx HTTPExecutionContext) (starlark.Value, error) {
	fields := starlark.StringDict{
		"scriptName": starlark.String(ctx.ScriptName),
		"adopted": newScriptObject("ctx.adopted", false, starlark.StringDict{
			"label":          starlark.String(ctx.Adopted.Label),
			"ip":             starlark.String(ctx.Adopted.IP),
			"mac":            starlark.String(ctx.Adopted.MAC),
			"interfaceName":  starlark.String(ctx.Adopted.InterfaceName),
			"defaultGateway": starlark.String(ctx.Adopted.DefaultGateway),
			"mtu":            starlark.MakeInt(ctx.Adopted.MTU),
		}),
		"service": newScriptObject("ctx.service", false, starlark.StringDict{
			"name":          starlark.String(ctx.Service.Name),
			"port":          starlark.MakeInt(ctx.Service.Port),
			"rootDirectory": starlark.String(ctx.Service.RootDirectory),
			"useTLS":        starlark.Bool(ctx.Service.UseTLS),
		}),
		"connection": newScriptObject("ctx.connection", false, starlark.StringDict{
			"remoteAddress": starlark.String(ctx.Connection.RemoteAddress),
		}),
		"tls": starlark.None,
	}

	tlsValue, err := newHTTPTLSValue(ctx.TLS)
	if err != nil {
		return nil, err
	}
	fields["tls"] = tlsValue

	return newScriptObject("ctx", false, fields), nil
}

func newHTTPTLSValue(info HTTPTLSInfo) (starlark.Value, error) {
	peerCertificates := make([]starlark.Value, 0, len(info.PeerCertificates))
	for index, item := range info.PeerCertificates {
		value, err := newTLSCertificateValue(item)
		if err != nil {
			return nil, fmt.Errorf("ctx.tls.peerCertificates[%d]: %w", index, err)
		}
		peerCertificates = append(peerCertificates, value)
	}

	localCertificate := starlark.Value(starlark.None)
	if info.LocalCertificate != nil {
		value, err := newTLSCertificateValue(*info.LocalCertificate)
		if err != nil {
			return nil, fmt.Errorf("ctx.tls.localCertificate: %w", err)
		}
		localCertificate = value
	}

	return newScriptObject("ctx.tls", false, starlark.StringDict{
		"enabled":            starlark.Bool(info.Enabled),
		"version":            starlark.String(info.Version),
		"cipherSuite":        starlark.String(info.CipherSuite),
		"serverName":         starlark.String(info.ServerName),
		"negotiatedProtocol": starlark.String(info.NegotiatedProtocol),
		"peerCertificates":   starlark.NewList(peerCertificates),
		"localCertificate":   localCertificate,
	}), nil
}

func newTLSCertificateValue(item TLSCertificate) (starlark.Value, error) {
	dnsNames := make([]starlark.Value, 0, len(item.DNSNames))
	for _, value := range item.DNSNames {
		dnsNames = append(dnsNames, starlark.String(value))
	}

	ipAddresses := make([]starlark.Value, 0, len(item.IPAddresses))
	for _, value := range item.IPAddresses {
		ipAddresses = append(ipAddresses, starlark.String(value))
	}

	return newScriptObject("ctx.tls.certificate", false, starlark.StringDict{
		"subject":      starlark.String(item.Subject),
		"issuer":       starlark.String(item.Issuer),
		"serialNumber": starlark.String(item.SerialNumber),
		"dnsNames":     starlark.NewList(dnsNames),
		"ipAddresses":  starlark.NewList(ipAddresses),
		"notBefore":    starlark.String(item.NotBefore),
		"notAfter":     starlark.String(item.NotAfter),
	}), nil
}

func newHTTPRequestValue(request *HTTPRequest) *scriptObject {
	if request == nil {
		request = &HTTPRequest{}
	}

	return newScriptObject("http.request", true, starlark.StringDict{
		"method":  starlark.String(request.Method),
		"target":  starlark.String(request.Target),
		"version": starlark.String(request.Version),
		"host":    starlark.String(request.Host),
		"headers": newHTTPHeaderListValue(request.Headers),
		"body":    newBorrowedByteBuffer(request.Body),
	})
}

func newHTTPResponseValue(response *HTTPResponse) *scriptObject {
	if response == nil {
		response = &HTTPResponse{}
	}

	return newScriptObject("http.response", true, starlark.StringDict{
		"statusCode": starlark.MakeInt(response.StatusCode),
		"reason":     starlark.String(response.Reason),
		"version":    starlark.String(response.Version),
		"headers":    newHTTPHeaderListValue(response.Headers),
		"body":       newBorrowedByteBuffer(response.Body),
	})
}

func newHTTPHeaderListValue(headers []HTTPHeader) starlark.Value {
	items := make([]starlark.Value, 0, len(headers))
	for _, item := range headers {
		items = append(items, newScriptObject("http.header", true, starlark.StringDict{
			"name":  starlark.String(item.Name),
			"value": starlark.String(item.Value),
		}))
	}
	return starlark.NewList(items)
}

func applyHTTPRequestValue(value starlark.Value, request *HTTPRequest) error {
	if request == nil || isNone(value) {
		return nil
	}

	methodValue, err := attrOrNone(value, "method")
	if err != nil {
		return fmt.Errorf("http.request.method: %w", err)
	}
	targetValue, err := attrOrNone(value, "target")
	if err != nil {
		return fmt.Errorf("http.request.target: %w", err)
	}
	versionValue, err := attrOrNone(value, "version")
	if err != nil {
		return fmt.Errorf("http.request.version: %w", err)
	}
	hostValue, err := attrOrNone(value, "host")
	if err != nil {
		return fmt.Errorf("http.request.host: %w", err)
	}
	headersValue, err := attrOrNone(value, "headers")
	if err != nil {
		return fmt.Errorf("http.request.headers: %w", err)
	}
	bodyValue, err := attrOrNone(value, "body")
	if err != nil {
		return fmt.Errorf("http.request.body: %w", err)
	}

	method := strings.TrimSpace(starlarkStringValue(methodValue))
	target := starlarkStringValue(targetValue)
	if method == "" {
		return fmt.Errorf("http.request.method is required")
	}
	if target == "" {
		return fmt.Errorf("http.request.target is required")
	}

	headers, err := httpHeadersFromValue(headersValue)
	if err != nil {
		return fmt.Errorf("http.request.headers: %w", err)
	}
	body, err := parseOptionalBytes(bodyValue)
	if err != nil {
		return fmt.Errorf("http.request.body: %w", err)
	}

	request.Method = method
	request.Target = target
	request.Version = strings.TrimSpace(starlarkStringValue(versionValue))
	request.Host = starlarkStringValue(hostValue)
	request.Headers = fromHTTPHeaderFields(headers)
	request.Body = append(request.Body[:0], body...)
	return nil
}

func applyHTTPResponseValue(value starlark.Value, response *HTTPResponse) error {
	if response == nil || isNone(value) {
		return nil
	}

	statusCodeValue, err := attrOrNone(value, "statusCode")
	if err != nil {
		return fmt.Errorf("http.response.statusCode: %w", err)
	}
	reasonValue, err := attrOrNone(value, "reason")
	if err != nil {
		return fmt.Errorf("http.response.reason: %w", err)
	}
	versionValue, err := attrOrNone(value, "version")
	if err != nil {
		return fmt.Errorf("http.response.version: %w", err)
	}
	headersValue, err := attrOrNone(value, "headers")
	if err != nil {
		return fmt.Errorf("http.response.headers: %w", err)
	}
	bodyValue, err := attrOrNone(value, "body")
	if err != nil {
		return fmt.Errorf("http.response.body: %w", err)
	}

	headers, err := httpHeadersFromValue(headersValue)
	if err != nil {
		return fmt.Errorf("http.response.headers: %w", err)
	}
	body, err := parseOptionalBytes(bodyValue)
	if err != nil {
		return fmt.Errorf("http.response.body: %w", err)
	}

	if !isNone(statusCodeValue) {
		statusCode, err := integerValue(statusCodeValue)
		if err != nil || statusCode < 0 || statusCode > 999 {
			return fmt.Errorf("http.response.statusCode must be between 0 and 999")
		}
		response.StatusCode = int(statusCode)
	}
	response.Reason = starlarkStringValue(reasonValue)
	response.Version = strings.TrimSpace(starlarkStringValue(versionValue))
	response.Headers = fromHTTPHeaderFields(headers)
	response.Body = append(response.Body[:0], body...)
	return nil
}

func httpResponseFromValue(value starlark.Value) (HTTPResponse, error) {
	response := HTTPResponse{
		StatusCode: http.StatusOK,
		Reason:     http.StatusText(http.StatusOK),
		Version:    "HTTP/1.1",
	}
	if err := applyHTTPResponseValue(value, &response); err != nil {
		return HTTPResponse{}, err
	}
	if response.StatusCode <= 0 {
		response.StatusCode = http.StatusOK
	}
	if response.Version == "" {
		response.Version = "HTTP/1.1"
	}
	if response.Reason == "" {
		response.Reason = http.StatusText(response.StatusCode)
	}
	return response, nil
}

func fromHTTPHeaderFields(fields []httpHeaderField) []HTTPHeader {
	headers := make([]HTTPHeader, 0, len(fields))
	for _, item := range fields {
		headers = append(headers, HTTPHeader{
			Name:  item.name,
			Value: item.value,
		})
	}
	return headers
}
