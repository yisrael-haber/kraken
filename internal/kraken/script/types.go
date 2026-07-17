package script

import (
	"context"
	"net"
	"sync"

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
	ScriptName  string
	Adopted     ExecutionIdentity
	Identities  []ExecutionIdentity
	Metadata    map[string]string
	RunContext  context.Context
	Stdout      func(string)
	Stderr      func(string)
	connections *scriptConnections
	context     *contextValues
}

type scriptConnections struct {
	mu     sync.Mutex
	closed bool
	items  map[net.Conn]struct{}
}

func newScriptConnections() *scriptConnections {
	return &scriptConnections{items: make(map[net.Conn]struct{})}
}

func (connections *scriptConnections) Add(conn net.Conn) {
	connections.mu.Lock()
	if connections.closed {
		connections.mu.Unlock()
		_ = conn.Close()
		return
	}
	connections.items[conn] = struct{}{}
	connections.mu.Unlock()
}

func (connections *scriptConnections) Remove(conn net.Conn) {
	connections.mu.Lock()
	delete(connections.items, conn)
	connections.mu.Unlock()
}

func (connections *scriptConnections) Close() {
	connections.mu.Lock()
	if connections.closed {
		connections.mu.Unlock()
		return
	}
	connections.closed = true
	items := make([]net.Conn, 0, len(connections.items))
	for conn := range connections.items {
		items = append(items, conn)
	}
	clear(connections.items)
	connections.mu.Unlock()
	for _, conn := range items {
		_ = conn.Close()
	}
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

func (script *CompiledScript) Name() string { return script.name }
