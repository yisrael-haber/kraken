package script

import (
	"strings"
	"testing"
)

func TestCompileUndefinedNameReturnsError(t *testing.T) {
	_, err := Compile("bad", SurfaceTransport, `
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
