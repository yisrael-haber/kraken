package script

import (
	"encoding/hex"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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
    packet.send()
`)
	frame := mustDecodeFrame(t)
	out := executeOneTransport(t, compiled, frame)

	ipv4 := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipv4.IHL != 6 {
		t.Fatalf("expected IPv4 IHL 6, got %d", ipv4.IHL)
	}
	if len(ipv4.Options) < 2 || ipv4.Options[0].OptionType != 1 || ipv4.Options[1].OptionType != 1 {
		t.Fatalf("expected two NOP options, got %#v", ipv4.Options)
	}
}

func TestPacketSendChecksumDefaultsAndOptOut(t *testing.T) {
	compiled := mustCompileTransport(t, `
def main(packet, ctx):
    fixed = packet.copy()
    fixed.ipv4.ttl = 99
    fixed.send()
    packet.ipv4.ttl = 99
    packet.send(fix_checksums=False)
`)
	sent := executeTransport(t, compiled, mustDecodeFrame(t))
	if len(sent) != 2 {
		t.Fatalf("expected two sent packets, got %d", len(sent))
	}
	if !header.IPv4(sent[0][14:]).IsChecksumValid() {
		t.Fatal("expected default send to fix checksum")
	}
	if header.IPv4(sent[1][14:]).IsChecksumValid() {
		t.Fatal("expected checksum to remain stale when fixing is disabled")
	}
}

func TestPacketSendControlsOutput(t *testing.T) {
	if sent := executeTransport(t, mustCompileTransport(t, "def main(packet, ctx):\n    pass\n"), mustDecodeFrame(t)); len(sent) != 0 {
		t.Fatalf("expected no sent packets, got %d", len(sent))
	}
	sent := executeTransport(t, mustCompileTransport(t, `
def main(packet, ctx):
    packet.send()
    packet.ipv4.ttl = 99
    packet.send()
`), mustDecodeFrame(t))
	if len(sent) != 2 || sent[0][22] != 64 || sent[1][22] != 99 {
		t.Fatalf("expected sent TTLs [64 99], got %d packets", len(sent))
	}
}

func TestPacketSendCanFixLengthsAndChecksums(t *testing.T) {
	compiled := mustCompileTransport(t, `
def main(packet, ctx):
    packet.payload = b"abcd"
    packet.send()
`)
	frame := mustDecodeFrame(t)
	out := executeOneTransport(t, compiled, frame)

	ipv4 := header.IPv4(out[14:])
	if got, want := int(ipv4.TotalLength()), 32; got != want {
		t.Fatalf("expected IPv4 length %d, got %d", want, got)
	}
	if !ipv4.IsChecksumValid() {
		t.Fatalf("expected valid IPv4 checksum 0x%04x", ipv4.Checksum())
	}
}

func TestPacketPayloadLifetimeHelpers(t *testing.T) {
	compiled := mustCompileTransport(t, `
def main(packet, ctx):
    padded = packet.copy()
    padded.pad_payload(5, byte=65)
    padded.send()
    packet.truncate_payload(2)
    packet.send()
`)
	sent := executeTransport(t, compiled, mustDecodeFrame(t))
	if len(sent) != 2 {
		t.Fatalf("expected two sent packets, got %d", len(sent))
	}
	if got := string(sent[0][42:47]); got != "abcAA" {
		t.Fatalf("expected padded payload abcAA, got %q", got)
	}
	if got := string(sent[1][42:44]); got != "ab" {
		t.Fatalf("expected truncated payload ab, got %q", got)
	}
}

func TestPacketCreateFragmentsReturnsIndependentPackets(t *testing.T) {
	compiled := mustCompileTransport(t, `
load("kraken/bytes", "bytes")

def main(packet, ctx):
    payload = b""
    for _ in range(160):
        payload = bytes.concat(payload, b"a")
    packet.payload = payload
    for fragment in packet.create_fragments(100):
        fragment.send()
`)
	sent := executeTransport(t, compiled, mustDecodeFrame(t))
	if len(sent) != 3 {
		t.Fatalf("expected three fragments, got %d", len(sent))
	}

	expectedOffsets := []uint16{0, 80, 160}
	expectedLengths := []uint16{100, 100, 28}
	for index, frame := range sent {
		ipv4 := header.IPv4(frame[14:])
		if got := ipv4.TotalLength(); got != expectedLengths[index] {
			t.Fatalf("fragment %d length: expected %d, got %d", index, expectedLengths[index], got)
		}
		if got := ipv4.FragmentOffset(); got != expectedOffsets[index] {
			t.Fatalf("fragment %d offset: expected %d, got %d", index, expectedOffsets[index], got)
		}
		if got, want := ipv4.More(), index < len(sent)-1; got != want {
			t.Fatalf("fragment %d more flag: expected %v, got %v", index, want, got)
		}
		if !ipv4.IsChecksumValid() {
			t.Fatalf("fragment %d has invalid IPv4 checksum", index)
		}
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
    packet.send()
`)
	frame, err := hex.DecodeString("ffffffffffff02000000001008060001080006040001020000000010c0a8380a000000000000c0a83801")
	if err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	out := executeOneTransport(t, compiled, frame)

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

func executeOneTransport(t *testing.T, compiled *CompiledScript, frame []byte) []byte {
	t.Helper()
	sent := executeTransport(t, compiled, frame)
	if len(sent) != 1 {
		t.Fatalf("expected one sent packet, got %d", len(sent))
	}
	return sent[0]
}

func executeTransport(t *testing.T, compiled *CompiledScript, frame []byte) [][]byte {
	t.Helper()
	var sent [][]byte
	if err := ExecuteTransport(compiled, frame, ExecutionContext{}, func(out []byte) error {
		sent = append(sent, out)
		return nil
	}); err != nil {
		t.Fatalf("execute script: %v", err)
	}
	return sent
}

func mustDecodeFrame(t *testing.T) []byte {
	t.Helper()
	frame, err := hex.DecodeString("02000000000102000000001008004500001f0000000040018982c0a8380ac0a838010800339500070001616263")
	if err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	return frame
}
