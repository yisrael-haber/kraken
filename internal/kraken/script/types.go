package script

import "go.starlark.net/starlark"

const (
	entryPointName = "main"
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
	ScriptName string
	Adopted    ExecutionIdentity
	Service    ApplicationServiceInfo
	Connection ApplicationConnection
	Metadata   map[string]any
}

type ApplicationServiceInfo struct {
	Name     string
	Port     int
	Protocol string
}

type ApplicationConnection struct {
	LocalAddress  string
	RemoteAddress string
	Transport     string
}

type ApplicationData struct {
	Direction string
	Payload   []byte
}

type ExecutionIdentity struct {
	Label          string
	IP             string
	MAC            string
	InterfaceName  string
	DefaultGateway string
	MTU            int
}

func (script *CompiledScript) Name() string {
	if script == nil {
		return ""
	}
	return script.name
}
