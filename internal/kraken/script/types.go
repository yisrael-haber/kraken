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

type ApplicationContext struct {
	ScriptName string                 `json:"scriptName"`
	Adopted    ExecutionIdentity      `json:"adopted"`
	Service    ApplicationServiceInfo `json:"service"`
	Connection ApplicationConnection  `json:"connection"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ApplicationServiceInfo struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

type ApplicationConnection struct {
	LocalAddress  string `json:"localAddress,omitempty"`
	RemoteAddress string `json:"remoteAddress,omitempty"`
	Transport     string `json:"transport,omitempty"`
}

type ApplicationData struct {
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
	case "", SurfaceTransport:
		return SurfaceTransport, nil
	case SurfaceApplication:
		return SurfaceApplication, nil
	default:
		return "", fmt.Errorf("unsupported script surface %q", surface)
	}
}
