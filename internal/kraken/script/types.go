package script

import (
	"errors"

	"go.starlark.net/starlark"
)

const (
	entryPointName = "main"
)

var (
	ErrScriptInvalid = errors.New("script is invalid")
)

type Surface string

const (
	SurfaceTransport   Surface = "transport"
	SurfaceApplication Surface = "application"
)

type CompiledScript struct {
	name    string
	surface Surface
	program *starlark.Program
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

func (script *CompiledScript) Name() string {
	if script == nil {
		return ""
	}
	return script.name
}

func (script *CompiledScript) Surface() Surface {
	if script == nil {
		return ""
	}
	return script.surface
}
