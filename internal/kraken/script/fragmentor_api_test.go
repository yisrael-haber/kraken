package script

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

func TestExecutePacketScriptFragmentsDispatchesAndDrops(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "fragment-order",
		Surface: SurfaceTransport,
		Source: `fragmentor = require("kraken/fragmentor")

def main(packet, ctx):
    frags = fragmentor.fragment(packet, 16)
    fragmentor.dispatch(frags[1])
    fragmentor.dispatch(frags[0])
    packet.drop()
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceTransport})
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	frame := testSerializedFrame(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		1,
		[]byte("abcdefghijklmnopqrstuvwx"),
	))
	packet, err := NewMutablePacket(frame)
	if err != nil {
		t.Fatalf("new mutable packet: %v", err)
	}
	defer packet.Release()

	result, err := Execute(storedScript, packet, ExecutionContext{
		ScriptName: storedScript.Name,
		Adopted: ExecutionIdentity{
			Label:         "icmp",
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
			MTU:           1500,
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute script: %v", err)
	}

	if !result.DropOriginal {
		t.Fatal("expected original packet to be dropped")
	}
	if len(result.DispatchedFrames) != 2 {
		t.Fatalf("expected 2 dispatched fragments, got %d", len(result.DispatchedFrames))
	}

	firstOffset := fragmentOffset(t, result.DispatchedFrames[0])
	secondOffset := fragmentOffset(t, result.DispatchedFrames[1])
	if firstOffset <= secondOffset {
		t.Fatalf("expected reordered fragments, got offsets %d then %d", firstOffset, secondOffset)
	}
	if moreFragments(t, result.DispatchedFrames[0]) {
		t.Fatal("expected last fragment to be dispatched first")
	}
	if !moreFragments(t, result.DispatchedFrames[1]) {
		t.Fatal("expected first fragment to retain MF flag")
	}
}

func testSerializedFrame(t *testing.T, packet *packetpkg.OutboundPacket) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBufferExpectedSize(64, len(packet.Payload))
	if err := packet.SerializeValidatedInto(buffer); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func fragmentOffset(t *testing.T, frame []byte) uint16 {
	t.Helper()
	if len(frame) < 34 {
		t.Fatalf("fragment too short: %d", len(frame))
	}
	return binary.BigEndian.Uint16(frame[20:22]) & 0x1fff
}

func moreFragments(t *testing.T, frame []byte) bool {
	t.Helper()
	if len(frame) < 34 {
		t.Fatalf("fragment too short: %d", len(frame))
	}
	return binary.BigEndian.Uint16(frame[20:22])&(1<<13) != 0
}
