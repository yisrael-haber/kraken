package operations

import (
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"gvisor.dev/gvisor/pkg/buffer"
)

func TestStartHTTPServiceStopReleasesPort(t *testing.T) {
	identity := fakeIdentity{
		Label:         "web",
		IP:            net.IPv4(192, 168, 56, 10),
		Interface:     net.Interface{Name: "eth0"},
		InterfaceName: "eth0",
		MAC:           adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := identity.EnsureEngine(nil, func(_ *adoption.Identity, frame buffer.Buffer) error {
		frame.Release()
		return nil
	}); err != nil {
		t.Fatalf("new identity engine: %v", err)
	}
	defer identity.CloseEngine()

	config := map[string]string{
		"port":          "8080",
		"protocol":      "http",
		"rootDirectory": t.TempDir(),
	}

	first, err := startManagedService(&identity, serviceHTTPID, config, nil)
	if err != nil {
		t.Fatalf("start first HTTP service: %v", err)
	}
	first.stop()

	second, err := startManagedService(&identity, serviceHTTPID, config, nil)
	if err != nil {
		t.Fatalf("expected HTTP service stop to release the port, got %v", err)
	}
	second.stop()
}

func TestManagedServiceSnapshotRedactsSecretFields(t *testing.T) {
	service := newManagedService(serviceSSHID, map[string]string{
		"port":          "2222",
		"password":      "secret",
		"authorizedKey": "ssh-ed25519 AAAA",
		"allowPty":      "true",
	}, 2222)

	snapshot := service.snapshot()
	if snapshot.Config["password"] == "secret" {
		t.Fatal("expected password to be redacted")
	}
	if snapshot.Config["password"] != "configured" {
		t.Fatalf("expected configured password marker, got %q", snapshot.Config["password"])
	}
	if snapshot.Config["authorizedKey"] != "ssh-ed25519 AAAA" {
		t.Fatalf("expected non-secret key field to be preserved, got %q", snapshot.Config["authorizedKey"])
	}
}

func TestManagedServiceSnapshotIncludesScriptRuntimeError(t *testing.T) {
	service := newManagedService(serviceEchoID, map[string]string{"port": "7007"}, 7007)

	service.recordScriptError(adoption.ScriptRuntimeError{
		ScriptName: "mutate",
		Surface:    "application",
		Stage:      "echo",
		Direction:  "inbound",
		LastError:  "boom",
	})

	snapshot := service.snapshot()
	if snapshot.ScriptError == nil {
		t.Fatal("expected script error snapshot")
	}
	if snapshot.ScriptError.ScriptName != "mutate" || snapshot.LastError != "boom" {
		t.Fatalf("unexpected script error snapshot: %+v", snapshot)
	}
}
