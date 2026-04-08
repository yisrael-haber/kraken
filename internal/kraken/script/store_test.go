package script

import (
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

func TestStoredScriptStoreSaveAndLookup(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "TTL Clamp",
		Source: `function main(packet, ctx) {
    packet.ipv4.ttl = 32;
}`,
	})
	if err != nil {
		t.Fatalf("save stored script: %v", err)
	}
	if !saved.Available {
		t.Fatalf("expected saved script to be available, compileError=%q", saved.CompileError)
	}
	if saved.EntryPoint != entryPointName {
		t.Fatalf("expected entry point %q, got %q", entryPointName, saved.EntryPoint)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored scripts: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 stored script, got %d", len(items))
	}
	if items[0].Name != saved.Name {
		t.Fatalf("expected stored script %q, got %q", saved.Name, items[0].Name)
	}

	loaded, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup stored script: %v", err)
	}
	if loaded.Name != saved.Name {
		t.Fatalf("expected loaded script %q, got %q", saved.Name, loaded.Name)
	}
	if loaded.compiled == nil || loaded.compiled.program == nil {
		t.Fatal("expected compiled program to be cached on lookup")
	}
}

func TestStoredScriptStoreMarksInvalidScriptsUnavailable(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name:   "Broken Script",
		Source: `function main(packet, ctx) { packet.ipv4.ttl = ; }`,
	})
	if err != nil {
		t.Fatalf("save broken script: %v", err)
	}
	if saved.Available {
		t.Fatal("expected broken script to be unavailable")
	}
	if saved.CompileError == "" {
		t.Fatal("expected broken script compile error")
	}

	_, err = store.Lookup(saved.Name)
	if !errors.Is(err, ErrStoredScriptInvalid) {
		t.Fatalf("expected invalid script lookup error, got %v", err)
	}
}

func TestExecuteMutatesPacketFieldsAndPayload(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Mutate Echo Reply",
		Source: `function main(packet, ctx) {
    packet.ipv4.ttl = 12;
    packet.icmpv4.seq = packet.icmpv4.seq + 3;
    packet.payload[0] = 0x41;
}`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		[]byte{0x10, 0x11},
	)

	err = Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		SendPath:   "icmp-echo-reply",
		Protocol:   "icmpv4",
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute script: %v", err)
	}

	if packet.IPv4.TTL != 12 {
		t.Fatalf("expected IPv4 TTL 12, got %d", packet.IPv4.TTL)
	}
	if packet.ICMPv4.Seq != 4 {
		t.Fatalf("expected ICMP sequence 4, got %d", packet.ICMPv4.Seq)
	}
	if len(packet.Payload) != 2 || packet.Payload[0] != 0x41 {
		t.Fatalf("expected payload mutation to persist, got %v", packet.Payload)
	}
}
