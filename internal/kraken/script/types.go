package script

import (
	"errors"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

const (
	storedScriptFolder           = "scripts"
	entryPointName               = "main"
	packetScriptSurfaceName      = "packet"
	httpServiceScriptSurfaceName = "http_service"
	httpServiceRequestHookName   = "on_request"
	httpServiceResponseHookName  = "on_response"
)

var (
	ErrStoredScriptNotFound = errors.New("stored script was not found")
	ErrStoredScriptInvalid  = errors.New("stored script is invalid")
)

type Surface string

const (
	SurfacePacket      Surface = packetScriptSurfaceName
	SurfaceHTTPService Surface = httpServiceScriptSurfaceName
)

var allScriptSurfaces = []Surface{
	SurfacePacket,
	SurfaceHTTPService,
}

type StoredScript struct {
	Name         string          `json:"name"`
	Surface      Surface         `json:"surface"`
	Source       string          `json:"source"`
	Available    bool            `json:"available"`
	CompileError string          `json:"compileError,omitempty"`
	UpdatedAt    string          `json:"updatedAt,omitempty"`
	compiled     *compiledScript `json:"-"`
}

type compiledScript struct {
	program *starlark.Program
}

type StoredScriptSummary struct {
	Name         string  `json:"name"`
	Surface      Surface `json:"surface"`
	Available    bool    `json:"available"`
	CompileError string  `json:"compileError,omitempty"`
	UpdatedAt    string  `json:"updatedAt,omitempty"`
}

type StoredScriptRef struct {
	Name    string  `json:"name"`
	Surface Surface `json:"surface"`
}

type SaveStoredScriptRequest struct {
	Name    string  `json:"name"`
	Surface Surface `json:"surface"`
	Source  string  `json:"source"`
}

type LogFunc func(level, message string)

type ExecutionContext struct {
	ScriptName string                 `json:"scriptName"`
	Adopted    ExecutionIdentity      `json:"adopted"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type HTTPExecutionContext struct {
	ScriptName string            `json:"scriptName"`
	Adopted    ExecutionIdentity `json:"adopted"`
	Service    HTTPServiceInfo   `json:"service"`
	Connection HTTPConnection    `json:"connection"`
	TLS        HTTPTLSInfo       `json:"tls"`
}

type ExecutionIdentity struct {
	Label          string `json:"label"`
	IP             string `json:"ip"`
	MAC            string `json:"mac"`
	InterfaceName  string `json:"interfaceName"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
}

type HTTPServiceInfo struct {
	Name          string `json:"name"`
	Port          int    `json:"port"`
	RootDirectory string `json:"rootDirectory,omitempty"`
	UseTLS        bool   `json:"useTLS"`
}

type HTTPConnection struct {
	RemoteAddress string `json:"remoteAddress,omitempty"`
}

type HTTPHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HTTPRequest struct {
	Method  string       `json:"method"`
	Target  string       `json:"target"`
	Version string       `json:"version"`
	Host    string       `json:"host,omitempty"`
	Headers []HTTPHeader `json:"headers,omitempty"`
	Body    []byte       `json:"body,omitempty"`
}

type HTTPResponse struct {
	StatusCode int          `json:"statusCode"`
	Reason     string       `json:"reason,omitempty"`
	Version    string       `json:"version,omitempty"`
	Headers    []HTTPHeader `json:"headers,omitempty"`
	Body       []byte       `json:"body,omitempty"`
}

type HTTPTLSInfo struct {
	Enabled            bool             `json:"enabled"`
	Version            string           `json:"version,omitempty"`
	CipherSuite        string           `json:"cipherSuite,omitempty"`
	ServerName         string           `json:"serverName,omitempty"`
	NegotiatedProtocol string           `json:"negotiatedProtocol,omitempty"`
	PeerCertificates   []TLSCertificate `json:"peerCertificates,omitempty"`
	LocalCertificate   *TLSCertificate  `json:"localCertificate,omitempty"`
}

type TLSCertificate struct {
	Subject      string   `json:"subject,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	SerialNumber string   `json:"serialNumber,omitempty"`
	DNSNames     []string `json:"dnsNames,omitempty"`
	IPAddresses  []string `json:"ipAddresses,omitempty"`
	NotBefore    string   `json:"notBefore,omitempty"`
	NotAfter     string   `json:"notAfter,omitempty"`
}

func NormalizeSurface(surface Surface) (Surface, error) {
	switch Surface(strings.TrimSpace(string(surface))) {
	case "", SurfacePacket:
		return SurfacePacket, nil
	case SurfaceHTTPService:
		return SurfaceHTTPService, nil
	default:
		return "", fmt.Errorf("unsupported script surface %q", surface)
	}
}
