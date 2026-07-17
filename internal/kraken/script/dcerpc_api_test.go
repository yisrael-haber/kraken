package script

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestDCERPCTakesTCPSocketOwnership(t *testing.T) {
	compiled, err := CompileGeneric("dcerpc", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
    conn = socket.tcp(ctx.identities["10.0.0.1"], "10.0.0.5:135")
    dcerpc.tcp(conn).close()
    conn.close()
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGenericWithContext(context.Background(), compiled, ExecutionContext{Identities: []ExecutionIdentity{{
		IP:             "10.0.0.1",
		SocketIdentity: dcerpcTestIdentity{},
	}}})
	if err == nil || !strings.Contains(result.Stderr, "socket.connection is owned by dcerpc.client") {
		t.Fatalf("expected transferred connection error, got %v\n%s", err, result.Stderr)
	}
}

func TestDCERPCTCPRejectsUDPSocket(t *testing.T) {
	compiled, err := CompileGeneric("dcerpc", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
    dcerpc.tcp(socket.udp(ctx.identities["10.0.0.1"], "10.0.0.5:135"))
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGenericWithContext(context.Background(), compiled, ExecutionContext{Identities: []ExecutionIdentity{{
		IP:             "10.0.0.1",
		SocketIdentity: dcerpcTestIdentity{},
	}}})
	if err == nil || !strings.Contains(result.Stderr, "dcerpc.tcp requires a TCP connection from kraken/socket.tcp") {
		t.Fatalf("expected UDP rejection, got %v\n%s", err, result.Stderr)
	}
}

type dcerpcTestIdentity struct{}

func (dcerpcTestIdentity) DialScriptTCP(context.Context, net.IP, int, SocketOptions) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (dcerpcTestIdentity) DialScriptUDP(net.IP, int, SocketOptions) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}
