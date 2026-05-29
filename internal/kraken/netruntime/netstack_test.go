package netruntime

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestBuildNetstackRoutesAddsDefaultGatewayWhenConfigured(t *testing.T) {
	routes := buildNetstackRoutes(net.IPv4(192, 168, 56, 10), net.CIDRMask(24, 32), net.IPv4(192, 168, 56, 1))
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if routes[1].Gateway != tcpip.AddrFrom4([4]byte{192, 168, 56, 1}) {
		t.Fatalf("expected gateway route to use 192.168.56.1, got %v", routes[1].Gateway)
	}
}

func TestNewEngineEnablesIPv4Forwarding(t *testing.T) {
	engine, err := NewEngine(EngineConfig{
		IP:             net.IPv4(192, 168, 56, 10),
		InterfaceName:  "eth0",
		MAC:            net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		SubnetMask:     net.CIDRMask(24, 32),
		MTU:            1500,
		PacketEndpoint: &InterfacePacketIO{},
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

func TestPrepareInjectedFramePreservesEthernetFrame(t *testing.T) {
	raw := make([]byte, header.EthernetMinimumSize+header.ARPSize)
	raw[12], raw[13] = 0x08, 0x06
	frame := buffer.MakeWithData(raw)
	defer frame.Release()

	if !new(Engine).prepareInjectedFrame(&frame) {
		t.Fatal("expected ethernet ARP frame to be accepted")
	}
	got := frame.Flatten()
	if len(got) != len(raw) || header.Ethernet(got).Type() != header.ARPProtocolNumber {
		t.Fatalf("expected unchanged ethernet ARP frame, got len=%d type=%d", len(got), header.Ethernet(got).Type())
	}
}
