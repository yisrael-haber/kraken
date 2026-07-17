package script

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExecuteGenericExposesIdentities(t *testing.T) {
	compiled, err := CompileGeneric("generic", `
def main(ctx):
	print(ctx.identities["10.0.0.1"].ip)
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGenericWithContext(context.Background(), compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{IP: "10.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("execute generic script: %v", err)
	}
	if result.Stdout != "10.0.0.1\n" {
		t.Fatalf("unexpected output %q", result.Stdout)
	}
}

func TestCompileTransportRejectsGlobalNetworkModules(t *testing.T) {
	for _, module := range []struct{ path, name string }{{"kraken/socket", "socket"}, {"kraken/windows", "windows"}, {"kraken/dcerpc", "dcerpc"}} {
		t.Run(module.path, func(t *testing.T) {
			_, err := CompileTransport("transport", "load(\""+module.path+"\", \""+module.name+"\")\n\ndef main(packet, ctx):\n    pass\n")
			if err == nil {
				t.Fatal("expected transport script to reject global-only module")
			}
		})
	}
}

func TestExecuteGenericMissingIdentityReturnsError(t *testing.T) {
	compiled, err := CompileGeneric("generic", `
def main(ctx):
	print(ctx.identities["10.0.0.2"].ip)
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	_, err = ExecuteGenericWithContext(context.Background(), compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{IP: "10.0.0.1"}},
	})
	if err == nil {
		t.Fatal("expected missing identity error")
	}
}

func TestExecuteGenericCanCancelSleep(t *testing.T) {
	compiled, err := CompileGeneric("generic", `
load("kraken/time", "time")

def main(ctx):
	time.sleep(10000)
	print("after")
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	result, err := ExecuteGenericWithContext(ctx, compiled, ExecutionContext{})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if time.Since(started) > time.Second {
		t.Fatal("generic script cancellation took too long")
	}
	if strings.Contains(result.Stdout, "after") {
		t.Fatalf("script continued after cancellation: %q", result.Stdout)
	}
}

func TestExecuteGenericCancelClosesBlockingSocketRead(t *testing.T) {
	compiled, err := CompileGeneric("generic", `
load("kraken/socket", "socket")

def main(ctx):
	conn = socket.tcp(ctx.identities["10.0.0.1"], "10.0.0.2:80")
	conn.recv(1)
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	client, server := net.Pipe()
	defer server.Close()
	identity := &blockingSocketIdentity{conn: client, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := ExecuteGenericWithContext(ctx, compiled, ExecutionContext{Identities: []ExecutionIdentity{{
			IP:             "10.0.0.1",
			SocketIdentity: identity,
		}}})
		finished <- err
	}()

	select {
	case <-identity.started:
	case <-time.After(time.Second):
		t.Fatal("script did not open its socket")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("expected cancelled socket read to stop the script")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled socket read did not return promptly")
	}
}

type blockingSocketIdentity struct {
	conn    net.Conn
	started chan struct{}
}

func (identity *blockingSocketIdentity) DialScriptTCP(context.Context, net.IP, int, SocketOptions) (net.Conn, error) {
	close(identity.started)
	return identity.conn, nil
}

func (*blockingSocketIdentity) DialScriptUDP(net.IP, int, SocketOptions) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
