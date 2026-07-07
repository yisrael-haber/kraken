package script

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCompileUndefinedNameReturnsError(t *testing.T) {
	_, err := Compile("bad", `
def main(packet, ctx):
	return missing_name
`)
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "undefined: missing_name") {
		t.Fatalf("expected undefined name error, got %v", err)
	}
}

func TestExecuteGenericExposesIdentities(t *testing.T) {
	compiled, err := CompileGeneric("generic", `
def main(ctx):
	print(ctx.identities["10.0.0.1"].ip)
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{IP: "10.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("execute generic script: %v", err)
	}
	if result.Output != "10.0.0.1\n" {
		t.Fatalf("unexpected output %q", result.Output)
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

	_, err = ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{IP: "10.0.0.1"}},
	})
	if err == nil {
		t.Fatal("expected missing identity error")
	}
	if !strings.Contains(err.Error(), "key \"10.0.0.2\" not in dict") {
		t.Fatalf("expected missing identity error, got %v", err)
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
