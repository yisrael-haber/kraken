package script

import "go.starlark.net/starlark"

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

type ExecutionContext struct {
	ScriptName string
	Adopted    ExecutionIdentity
	Metadata   map[string]string
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
