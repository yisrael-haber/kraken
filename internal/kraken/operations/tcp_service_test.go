package operations

import (
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
)

func TestStartHTTPServiceStopReleasesPort(t *testing.T) {
	group, err := newAdoptedEngine(netruntime.EngineConfig{
		InterfaceName: "eth0",
		MAC:           net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, func(_ *adoptedEngine, frame []byte) error { return nil })
	if err != nil {
		t.Fatalf("new adopted engine: %v", err)
	}
	defer group.close()

	identity := fakeIdentity{
		Label:     "web",
		IP:        net.IPv4(192, 168, 56, 10),
		Interface: net.Interface{Name: "eth0"},
		MAC:       adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := group.addIdentity(identity); err != nil {
		t.Fatalf("add identity: %v", err)
	}

	spec := serviceSpec{
		service: listenerServiceHTTPID,
		config: map[string]string{
			"port":          "8080",
			"protocol":      "http",
			"rootDirectory": t.TempDir(),
		},
	}

	first, err := startManagedService(group, identity, spec, nil)
	if err != nil {
		t.Fatalf("start first HTTP service: %v", err)
	}
	first.stop()

	second, err := startManagedService(group, identity, spec, nil)
	if err != nil {
		t.Fatalf("expected HTTP service stop to release the port, got %v", err)
	}
	second.stop()
}

func TestManagedServiceSnapshotRedactsSecretFields(t *testing.T) {
	service := newManagedService(serviceSpec{
		service: listenerServiceSSHID,
		config: map[string]string{
			"port":          "2222",
			"password":      "secret",
			"authorizedKey": "ssh-ed25519 AAAA",
			"allowPty":      "true",
		},
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
	service := newManagedService(serviceSpec{
		service: listenerServiceEchoID,
		config:  map[string]string{"port": "7007"},
	}, 7007)

	service.recordScriptError(adoption.ScriptRuntimeError{
		ScriptName: "mutate",
		Surface:    "application",
		Stage:      "echo",
		Direction:  "inbound",
		LastError:  "boom",
		UpdatedAt:  "2026-04-23T00:00:00Z",
	})

	snapshot := service.snapshot()
	if snapshot.ScriptError == nil {
		t.Fatal("expected script error snapshot")
	}
	if snapshot.ScriptError.ScriptName != "mutate" || snapshot.LastError != "boom" {
		t.Fatalf("unexpected script error snapshot: %+v", snapshot)
	}
}
