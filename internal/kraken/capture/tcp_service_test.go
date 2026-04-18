package capture

import (
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestStartHTTPTCPServiceStopReleasesPort(t *testing.T) {
	group, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, func(_ *adoptedEngineGroup, pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	if err != nil {
		t.Fatalf("new adopted engine group: %v", err)
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

	spec := tcpServiceSpec{
		service:       adoption.TCPServiceHTTP,
		port:          8080,
		rootDirectory: t.TempDir(),
	}

	first, err := startHTTPTCPService(group, identity, spec, nil)
	if err != nil {
		t.Fatalf("start first HTTP service: %v", err)
	}
	first.stop()

	second, err := startHTTPTCPService(group, identity, spec, nil)
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
