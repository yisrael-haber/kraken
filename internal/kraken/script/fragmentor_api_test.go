package script

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestExecutePacketScriptFragmentsDispatchesAndDrops(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "fragment-order",
		Surface: SurfaceTransport,
		Source: `load("kraken/fragmentor", "fragmentor")

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

	packet, err := NewMutableICMPEchoPacket(
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		1,
		[]byte("abcdefghijklmnopqrstuvwx"),
	)
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

func TestExecutePacketScriptDispatchesFragmentsBeforeScriptReturn(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "fragment-sleep-order",
		Surface: SurfaceTransport,
		Source: `load("kraken/fragmentor", "fragmentor")
load("kraken/time", "time")

def main(packet, ctx):
    frags = fragmentor.fragment(packet, 16)
    fragmentor.dispatch(frags[1])
    time.sleep(40)
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

	packet, err := NewMutableICMPEchoPacket(
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		1,
		[]byte("abcdefghijklmnopqrstuvwx"),
	)
	if err != nil {
		t.Fatalf("new mutable packet: %v", err)
	}
	defer packet.Release()

	var dispatchTimes []time.Time
	result, err := ExecuteWithDispatch(storedScript, packet, ExecutionContext{
		ScriptName: storedScript.Name,
		Adopted: ExecutionIdentity{
			Label:         "icmp",
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
			MTU:           1500,
		},
	}, nil, func(frame []byte) error {
		dispatchTimes = append(dispatchTimes, time.Now())
		return nil
	})
	if err != nil {
		t.Fatalf("execute script: %v", err)
	}

	if !result.DropOriginal {
		t.Fatal("expected original packet to be dropped")
	}
	if len(dispatchTimes) != 2 {
		t.Fatalf("expected 2 synchronous dispatches, got %d", len(dispatchTimes))
	}
	if elapsed := dispatchTimes[1].Sub(dispatchTimes[0]); elapsed < 30*time.Millisecond {
		t.Fatalf("expected dispatches to be separated by sleep, got %s", elapsed)
	}
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
