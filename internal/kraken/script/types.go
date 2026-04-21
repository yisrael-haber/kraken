package script

import (
	"errors"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

const (
	storedScriptFolder       = "scripts"
	entryPointName           = "main"
	transportScriptSurface   = "transport"
	applicationScriptSurface = "application"
)

var (
	ErrStoredScriptNotFound = errors.New("stored script was not found")
	ErrStoredScriptInvalid  = errors.New("stored script is invalid")
)

type Surface string

const (
	SurfaceTransport   Surface = transportScriptSurface
	SurfaceApplication Surface = applicationScriptSurface
)

var allScriptSurfaces = []Surface{
	SurfaceTransport,
	SurfaceApplication,
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

type StreamExecutionContext struct {
	ScriptName string                 `json:"scriptName"`
	Adopted    ExecutionIdentity      `json:"adopted"`
	Service    StreamServiceInfo      `json:"service"`
	Connection StreamConnection       `json:"connection"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type StreamServiceInfo struct {
	Name          string `json:"name"`
	Port          int    `json:"port"`
	Protocol      string `json:"protocol,omitempty"`
	RootDirectory string `json:"rootDirectory,omitempty"`
	UseTLS        bool   `json:"useTLS,omitempty"`
}

type StreamConnection struct {
	LocalAddress  string `json:"localAddress,omitempty"`
	RemoteAddress string `json:"remoteAddress,omitempty"`
}

type StreamData struct {
	Direction string `json:"direction"`
	Payload   []byte `json:"payload,omitempty"`
}

type ExecutionIdentity struct {
	Label          string `json:"label"`
	IP             string `json:"ip"`
	MAC            string `json:"mac"`
	InterfaceName  string `json:"interfaceName"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

func NormalizeSurface(surface Surface) (Surface, error) {
	switch Surface(strings.TrimSpace(string(surface))) {
	case "", "packet", SurfaceTransport:
		return SurfaceTransport, nil
	case "http_service", "tls_service", "ssh_service", SurfaceApplication:
		return SurfaceApplication, nil
	default:
		return "", fmt.Errorf("unsupported script surface %q", surface)
	}
}
