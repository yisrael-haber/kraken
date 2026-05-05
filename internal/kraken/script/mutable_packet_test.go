package script

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPacketIPv4OptionsMutationUpdatesFrame(t *testing.T) {
	compiled := mustCompileTransport(t, `load("kraken/bytes", "bytes")

def main(packet, ctx):
    packet.ipv4.options = [
        {"optionType": 1},
        {"optionType": 1},
    ]
    packet.ipv4.padding = bytes.fromHex("0000")
`)
	packet := mustICMPPacket(t, []byte("abc"))
	defer packet.Release()

	if _, err := Execute(compiled, packet, ExecutionContext{}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	ipv4 := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipv4.IHL != 6 {
		t.Fatalf("expected IPv4 IHL 6, got %d", ipv4.IHL)
	}
	if len(ipv4.Options) < 2 || ipv4.Options[0].OptionType != 1 || ipv4.Options[1].OptionType != 1 {
		t.Fatalf("expected two NOP options, got %#v", ipv4.Options)
	}
}

func TestPacketARPAllowsNonEthernetIPv4AddressSizes(t *testing.T) {
	compiled := mustCompileTransport(t, `load("kraken/bytes", "bytes")

def main(packet, ctx):
    packet.fixLengths = False
    packet.arp.hwAddressSize = 1
    packet.arp.protAddressSize = 2
    packet.arp.sourceHwAddress = bytes.fromHex("aa")
    packet.arp.sourceProtAddress = bytes.fromHex("0102")
    packet.arp.dstHwAddress = bytes.fromHex("bb")
    packet.arp.dstProtAddress = bytes.fromHex("0304")
`)
	packet, err := NewMutableARPRequestPacket(
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
	)
	if err != nil {
		t.Fatalf("new mutable ARP packet: %v", err)
	}
	defer packet.Release()

	if _, err := Execute(compiled, packet, ExecutionContext{}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	const wantARP = "0001080001020001aa0102bb0304"
	gotARP := hex.EncodeToString(packet.Bytes()[14 : 14+len(wantARP)/2])
	if gotARP != wantARP {
		t.Fatalf("expected ARP %s, got %s", wantARP, gotARP)
	}
}

func mustCompileTransport(t *testing.T, source string) *CompiledScript {
	t.Helper()
	compiled, err := Compile(t.Name(), SurfaceTransport, source, false)
	if err != nil {
		t.Fatalf("compile script: %v", err)
	}
	return compiled
}

func mustICMPPacket(t *testing.T, payload []byte) *MutablePacket {
	t.Helper()
	packet, err := NewMutableICMPEchoPacket(
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		1,
		payload,
	)
	if err != nil {
		t.Fatalf("new mutable packet: %v", err)
	}
	return packet
}
