package capture

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestStartHTTPServiceStopReleasesPort(t *testing.T) {
	group, err := newAdoptedEngine(adoptedEngineConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, func(_ *adoptedEngine, pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	if err != nil {
		t.Fatalf("new adopted engine: %v", err)
	}
	defer group.close()

	identity := fakeIdentity{
		label: "web",
		ip:    net.IPv4(192, 168, 56, 10),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
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

	group.mu.RLock()
	remainingPorts := len(group.managedHTTPPorts)
	group.mu.RUnlock()
	if remainingPorts != 0 {
		t.Fatalf("expected managed HTTP ports to be released, got %d", remainingPorts)
	}
}
