package operations

import (
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
)

func TestStartHTTPServiceStopReleasesPort(t *testing.T) {
	identity := fakeIdentity{
		Label:         "web",
		IP:            net.IPv4(192, 168, 56, 10),
		Interface:     net.Interface{Name: "eth0"},
		InterfaceName: "eth0",
		MAC:           adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := identity.Init(&adoptionListener{
		packetIO: netruntime.NewInterfacePacketIO(nil, func([]byte) error { return nil }),
	}); err != nil {
		t.Fatalf("new identity engine: %v", err)
	}
	defer identity.CloseEngine()

	config := map[string]string{
		"port":          "8080",
		"protocol":      "http",
		"rootDirectory": t.TempDir(),
	}

	first, err := startTestManagedService(&identity, serviceHTTPID, config, nil)
	if err != nil {
		t.Fatalf("start first HTTP service: %v", err)
	}
	first.Stop()

	second, err := startTestManagedService(&identity, serviceHTTPID, config, nil)
	if err != nil {
		t.Fatalf("expected HTTP service stop to release the port, got %v", err)
	}
	second.Stop()
}

func TestManagedServiceSnapshotRedactsSecretFields(t *testing.T) {
	definition, _ := serviceByID(serviceSSHID)
	config := map[string]string{
		"port":          "2222",
		"password":      "secret",
		"authorizedKey": "ssh-ed25519 AAAA",
		"allowPty":      "true",
	}
	service := adoption.NewManagedService(adoption.ServiceStatus{
		Service: serviceSSHID,
		Port:    2222,
		Config:  redactedServiceConfig(definition, config),
	})

	snapshot := service.Snapshot()
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
	service := adoption.NewManagedService(adoption.ServiceStatus{
		Service: serviceEchoID,
		Port:    7007,
		Config:  map[string]string{"port": "7007"},
	})

	service.RecordScriptError(adoption.ScriptRuntimeError{
		ScriptName: "mutate",
		Surface:    "application",
		Stage:      "echo",
		Direction:  "inbound",
		LastError:  "boom",
	})

	snapshot := service.Snapshot()
	if snapshot.ScriptError == nil {
		t.Fatal("expected script error snapshot")
	}
	if snapshot.ScriptError.ScriptName != "mutate" || snapshot.LastError != "boom" {
		t.Fatalf("unexpected script error snapshot: %+v", snapshot)
	}
}

func startTestManagedService(identity *adoption.Identity, service string, rawConfig map[string]string, lookup adoption.ScriptLookupFunc) (*adoption.ManagedService, error) {
	definition, _ := serviceByID(service)
	config, err := normalizeServiceConfig(definition, rawConfig)
	if err != nil {
		return nil, err
	}
	port, err := servicePort(definition, config)
	if err != nil {
		return nil, err
	}
	managed := adoption.NewManagedService(adoption.ServiceStatus{Service: definition.ID, Port: port, Config: config})
	process, err := startServiceProcess(identity, managed, definition.ID, config, lookup)
	if err != nil {
		return nil, err
	}
	managed.Start(process)
	return managed, nil
}
