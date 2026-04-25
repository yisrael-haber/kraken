package script

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNewMutableICMPEchoPacketClonesInputs(t *testing.T) {
	sourceIP := net.ParseIP("192.168.56.10").To4()
	sourceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	targetIP := net.ParseIP("192.168.56.1").To4()
	targetMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	payload := []byte{0x10, 0x11}

	packet, err := NewMutableICMPEchoPacket(
		sourceIP,
		sourceMAC,
		targetIP,
		targetMAC,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		payload,
	)
	if err != nil {
		t.Fatalf("new ICMP echo packet: %v", err)
	}
	defer packet.Release()

	sourceIP[3] = 99
	sourceMAC[5] = 0xaa
	targetIP[3] = 77
	targetMAC[5] = 0xbb
	payload[0] = 0xff

	decoded := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	ethernet := decoded.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ipv4 := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmp := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

	if got := ipv4.SrcIP.String(); got != "192.168.56.10" {
		t.Fatalf("expected cloned source IP, got %s", got)
	}
	if got := ethernet.SrcMAC.String(); got != "02:00:00:00:00:10" {
		t.Fatalf("expected cloned source MAC, got %s", got)
	}
	if got := ipv4.DstIP.String(); got != "192.168.56.1" {
		t.Fatalf("expected cloned target IP, got %s", got)
	}
	if got := ethernet.DstMAC.String(); got != "02:00:00:00:00:01" {
		t.Fatalf("expected cloned target MAC, got %s", got)
	}
	if len(icmp.Payload) != 2 || icmp.Payload[0] != 0x10 {
		t.Fatalf("expected cloned payload, got %v", icmp.Payload)
	}
}

func TestNewMutableARPRequestPacketClonesInputs(t *testing.T) {
	sourceIP := net.ParseIP("192.168.56.10").To4()
	sourceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	targetIP := net.ParseIP("192.168.56.1").To4()

	packet, err := NewMutableARPRequestPacket(sourceIP, sourceMAC, targetIP)
	if err != nil {
		t.Fatalf("new ARP request packet: %v", err)
	}
	defer packet.Release()

	sourceIP[3] = 99
	sourceMAC[5] = 0xaa
	targetIP[3] = 77

	decoded := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	arp := decoded.Layer(layers.LayerTypeARP).(*layers.ARP)

	if got := net.IP(arp.SourceProtAddress).String(); got != "192.168.56.10" {
		t.Fatalf("expected cloned source IP, got %s", got)
	}
	if got := net.HardwareAddr(arp.SourceHwAddress).String(); got != "02:00:00:00:00:10" {
		t.Fatalf("expected cloned source MAC, got %s", got)
	}
	if got := net.IP(arp.DstProtAddress).String(); got != "192.168.56.1" {
		t.Fatalf("expected cloned target IP, got %s", got)
	}
}
