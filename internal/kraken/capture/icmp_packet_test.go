package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestMarshalICMPEchoFrameProducesExpectedLayers(t *testing.T) {
	payload := []byte{0x10, 0x11, 0x12, 0x13}
	frame := marshalICMPEchoFrame(
		make([]byte, 14+20+8+len(payload)),
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		3,
		payload,
	)

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	ethernet, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok {
		t.Fatal("expected ethernet layer")
	}
	if got := ethernet.SrcMAC.String(); got != "02:00:00:00:00:10" {
		t.Fatalf("expected ethernet source MAC, got %s", got)
	}
	if got := ethernet.DstMAC.String(); got != "02:00:00:00:00:01" {
		t.Fatalf("expected ethernet destination MAC, got %s", got)
	}

	ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		t.Fatal("expected ipv4 layer")
	}
	if got := ipv4.SrcIP.String(); got != "192.168.56.10" {
		t.Fatalf("expected IPv4 source IP, got %s", got)
	}
	if got := ipv4.DstIP.String(); got != "192.168.56.1" {
		t.Fatalf("expected IPv4 destination IP, got %s", got)
	}
	if ipv4.Protocol != layers.IPProtocolICMPv4 {
		t.Fatalf("expected ICMPv4 protocol, got %v", ipv4.Protocol)
	}

	icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok {
		t.Fatal("expected icmpv4 layer")
	}
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
		t.Fatalf("expected echo reply type, got %v", icmp.TypeCode.Type())
	}
	if icmp.Id != 7 || icmp.Seq != 3 {
		t.Fatalf("expected id=7 seq=3, got id=%d seq=%d", icmp.Id, icmp.Seq)
	}
	if string(icmp.Payload) != string(payload) {
		t.Fatalf("expected payload %v, got %v", payload, icmp.Payload)
	}
}
