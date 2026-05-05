package netruntime

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gvisor.dev/gvisor/pkg/buffer"
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
	}, func(frame buffer.Buffer) error {
		frame.Release()
		return nil
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

func TestEngineForwardingResolvesGatewayWithARP(t *testing.T) {
	outbound := make(chan []byte, 4)
	engine, err := NewEngine(EngineConfig{
		IP:             net.IPv4(192, 168, 56, 10),
		InterfaceName:  "eth0",
		MAC:            net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		DefaultGateway: net.IPv4(192, 168, 56, 1),
		Routes: []net.IPNet{{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		}},
	}, func(frame buffer.Buffer) error {
		outbound <- append([]byte(nil), frame.Flatten()...)
		frame.Release()
		return nil
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer engine.Close()

	engine.InjectFrame(buffer.MakeWithData(testIPv4Frame(t,
		net.IPv4(192, 168, 56, 20),
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)))

	select {
	case frame := <-outbound:
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		layer := packet.Layer(layers.LayerTypeARP)
		if layer == nil {
			t.Fatalf("expected forwarded packet to trigger ARP, got %v", packet.Layers())
		}
		arp := layer.(*layers.ARP)
		if got := net.IP(arp.DstProtAddress).String(); got != "192.168.56.1" {
			t.Fatalf("expected ARP for gateway 192.168.56.1, got %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwarded ARP")
	}
}

func testIPv4Frame(t *testing.T, sourceIP, targetIP net.IP, sourceMAC, targetMAC net.HardwareAddr) []byte {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	ipv4Layer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    sourceIP,
		DstIP:    targetIP,
	}
	udpLayer := &layers.UDP{
		SrcPort: 10000,
		DstPort: 10001,
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		t.Fatalf("set UDP checksum layer: %v", err)
	}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		ipv4Layer,
		udpLayer,
	); err != nil {
		t.Fatalf("serialize IPv4 frame: %v", err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}
