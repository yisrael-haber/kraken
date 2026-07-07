package script

import (
	"context"
	"net"

	"go.starlark.net/starlark"
)

type CompiledScript struct {
	name    string
	program *starlark.Program
	kind    ScriptKind
}

type ScriptKind string

const (
	ScriptKindTransport ScriptKind = "transport"
	ScriptKindGeneric   ScriptKind = "generic"
)

type ExecutionContext struct {
	ScriptName string
	Adopted    ExecutionIdentity
	Identities []ExecutionIdentity
	Metadata   map[string]string
	RunContext context.Context
	Stdout     func(string)
	Stderr     func(string)
}

type ExecutionIdentity struct {
	Label          string
	IP             string
	MAC            string
	InterfaceName  string
	DefaultGateway string
	MTU            int
	SocketIdentity SocketIdentity
}

type SocketOptions struct {
	TTL        *int
	NoDelay    *bool
	KeepAlive  *bool
	ReuseAddr  *bool
	RecvBuffer *int
	SendBuffer *int
}

type SocketIdentity interface {
	DialScriptTCP(context.Context, net.IP, int, SocketOptions) (net.Conn, error)
	DialScriptUDP(net.IP, int, SocketOptions) (net.Conn, error)
}

type SocketOptionSetter interface {
	SetScriptSocketOptions(SocketOptions) error
}

func (script *CompiledScript) Name() string {
	if script == nil {
		return ""
	}
	return script.name
}

func (script *CompiledScript) Kind() ScriptKind {
	if script == nil {
		return ""
	}
	return script.kind
}
