package script

import (
	"encoding/hex"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPacketIPv4OptionsMutationUpdatesFrame(t *testing.T) {
	compiled := mustCompileTransport(t, `
def main(packet, ctx):
    packet.ipv4.options = [
        {"optionType": 1},
        {"optionType": 1},
    ]
    packet.ipv4.ihl = 6
    packet.ipv4.padding = b"\x00\x00"
`)
	frame, err := hex.DecodeString("02000000000102000000001008004500001f0000000040018982c0a8380ac0a838010800339500070001616263")
	if err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	out, err := ExecuteTransport(compiled, frame, ExecutionContext{}, nil)
	if err != nil {
		t.Fatalf("execute script: %v", err)
	}

	ipv4 := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipv4.IHL != 6 {
		t.Fatalf("expected IPv4 IHL 6, got %d", ipv4.IHL)
	}
	if len(ipv4.Options) < 2 || ipv4.Options[0].OptionType != 1 || ipv4.Options[1].OptionType != 1 {
		t.Fatalf("expected two NOP options, got %#v", ipv4.Options)
	}
}

func TestPacketARPAllowsNonEthernetIPv4AddressSizes(t *testing.T) {
	compiled := mustCompileTransport(t, `
def main(packet, ctx):
    packet.arp.hwAddressSize = 1
    packet.arp.protAddressSize = 2
    packet.arp.sourceHwAddress = b"\xaa"
    packet.arp.sourceProtAddress = b"\x01\x02"
    packet.arp.dstHwAddress = b"\xbb"
    packet.arp.dstProtAddress = b"\x03\x04"
`)
	frame, err := hex.DecodeString("ffffffffffff02000000001008060001080006040001020000000010c0a8380a000000000000c0a83801")
	if err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	out, err := ExecuteTransport(compiled, frame, ExecutionContext{}, nil)
	if err != nil {
		t.Fatalf("execute script: %v", err)
	}

	const wantARP = "0001080001020001aa0102bb0304"
	gotARP := hex.EncodeToString(out[14 : 14+len(wantARP)/2])
	if gotARP != wantARP {
		t.Fatalf("expected ARP %s, got %s", wantARP, gotARP)
	}
}

func mustCompileTransport(t *testing.T, source string) *CompiledScript {
	t.Helper()
	compiled, err := Compile(t.Name(), SurfaceTransport, source)
	if err != nil {
		t.Fatalf("compile script: %v", err)
	}
	return compiled
}
