package netruntime

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestBuildNetstackRoutesAddsDefaultGatewayWhenConfigured(t *testing.T) {
	routes := buildNetstackRoutes([]net.IPNet{
		{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		},
	}, net.IPv4(192, 168, 56, 1))
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if routes[1].Gateway != tcpip.AddrFrom4([4]byte{192, 168, 56, 1}) {
		t.Fatalf("expected gateway route to use 192.168.56.1, got %v", routes[1].Gateway)
	}
}

func TestNewEngineEnablesIPv4Forwarding(t *testing.T) {
	engine, err := NewEngine(EngineConfig{
		IP:            net.IPv4(192, 168, 56, 10),
		InterfaceName: "eth0",
		MAC:           net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		PacketIO:      &InterfacePacketIO{},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer engine.Close()

	forwarding, tcpErr := engine.stack.NICForwarding(adoptedNetstackNICID, ipv4.ProtocolNumber)
	if tcpErr != nil {
		t.Fatalf("read forwarding flag: %v", tcpErr)
	}
	if !forwarding {
		t.Fatal("expected IPv4 forwarding to be enabled")
	}
}
