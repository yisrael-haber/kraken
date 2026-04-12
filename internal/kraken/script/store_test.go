package script

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

func TestStoredScriptStoreSaveAndLookup(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "TTL Clamp",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 32
`,
	})
	if err != nil {
		t.Fatalf("save stored script: %v", err)
	}
	if !saved.Available {
		t.Fatalf("expected saved script to be available, compileError=%q", saved.CompileError)
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
		Name: "Broken Script",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl =
`,
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

func TestStoredScriptStoreTimesOutTopLevelInfiniteLoop(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Busy Loop",
		Source: `while True:
    pass

def main(packet, ctx):
    pass
`,
	})
	if err != nil {
		t.Fatalf("save busy-loop script: %v", err)
	}
	if saved.Available {
		t.Fatal("expected busy-loop script to be unavailable")
	}
	if !strings.Contains(saved.CompileError, "validation timed out") {
		t.Fatalf("expected timeout compile error, got %q", saved.CompileError)
	}
}

func TestStoredScriptStoreRefreshReloadsExternalChanges(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	if _, err := store.Save(SaveStoredScriptRequest{
		Name: "Alpha",
		Source: `def main(packet, ctx):
    pass
`,
	}); err != nil {
		t.Fatalf("save alpha script: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list scripts: %v", err)
	}
	if len(items) != 1 || items[0].Name != "Alpha" {
		t.Fatalf("expected [Alpha], got %+v", items)
	}

	path, err := pathForStoredScript(store.dir, "Beta")
	if err != nil {
		t.Fatalf("path for beta: %v", err)
	}
	if err := os.WriteFile(path, []byte("def main(packet, ctx):\n    pass\n"), 0o644); err != nil {
		t.Fatalf("write beta script: %v", err)
	}

	items, err = store.List()
	if err != nil {
		t.Fatalf("list scripts after external write: %v", err)
	}
	if len(items) != 1 || items[0].Name != "Alpha" {
		t.Fatalf("expected cached [Alpha], got %+v", items)
	}

	items, err = store.Refresh()
	if err != nil {
		t.Fatalf("refresh scripts: %v", err)
	}
	if len(items) != 2 || items[0].Name != "Alpha" || items[1].Name != "Beta" {
		t.Fatalf("expected [Alpha Beta], got %+v", items)
	}
}

func TestStoredScriptStoreIgnoresLegacyJavaScriptFiles(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	if err := os.WriteFile(filepath.Join(store.dir, "legacy.js"), []byte("def main(packet, ctx):\n    pass\n"), 0o644); err != nil {
		t.Fatalf("write legacy script: %v", err)
	}
	path, err := pathForStoredScript(store.dir, "Alpha")
	if err != nil {
		t.Fatalf("path for alpha: %v", err)
	}
	if err := os.WriteFile(path, []byte("def main(packet, ctx):\n    pass\n"), 0o644); err != nil {
		t.Fatalf("write alpha script: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list scripts: %v", err)
	}
	if len(items) != 1 || items[0].Name != "Alpha" {
		t.Fatalf("expected only Alpha to load, got %+v", items)
	}

	if _, err := store.Get("legacy"); !errors.Is(err, ErrStoredScriptNotFound) {
		t.Fatalf("expected legacy .js file to be ignored, got %v", err)
	}
}

func TestExecuteMutatesPacketFieldsAndPayload(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Mutate Echo Reply",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 12
    packet.icmpv4.seq = packet.icmpv4.seq + 3
    packet.payload[0] = 0x41
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		[]byte{0x10, 0x11},
	))

	if err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	ipv4Layer := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if ipv4Layer.TTL != 12 {
		t.Fatalf("expected IPv4 TTL 12, got %d", ipv4Layer.TTL)
	}
	if icmpLayer.Seq != 4 {
		t.Fatalf("expected ICMP sequence 4, got %d", icmpLayer.Seq)
	}
	if payload := icmpLayer.Payload; len(payload) != 2 || payload[0] != 0x41 {
		t.Fatalf("expected payload mutation to persist, got %v", payload)
	}
}

func TestExecuteBytesModuleBuildsPayloadFromContext(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Bytes Payload",
		Source: `bytes = require("kraken/bytes")

def main(packet, ctx):
    packet.payload = bytes.concat(
        bytes.fromASCII("PING:"),
        bytes.fromUTF8(ctx.scriptName),
        bytes.fromHex("00 ff"),
    )
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if err := Execute(script, packet, ExecutionContext{
		ScriptName: "Bytes Payload",
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	want := []byte("PING:Bytes Payload\x00\xff")
	if got := icmpPayload(t, packet); len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("expected payload %v, got %v", want, got)
	}
}

func TestExecuteGlobalBytesHelperBuildsPayloadFromContext(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Global Bytes Payload",
		Source: `def main(packet, ctx):
    packet.payload = bytes.fromUTF8(ctx.scriptName)
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if err := Execute(script, packet, ExecutionContext{
		ScriptName: "icmp_shift",
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	want := []byte("icmp_shift")
	if got := icmpPayload(t, packet); len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("expected payload %v, got %v", want, got)
	}
}

func TestExecuteSupportsHeaderMutationAndSerializationControls(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Header Mutation",
		Source: `bytes = require("kraken/bytes")

def main(packet, ctx):
    packet.serialization.fixLengths = False
    packet.serialization.computeChecksums = False
    packet.ethernet.ethernetType = 0x88b5
    packet.ipv4.length = 77
    packet.ipv4.id = 0x1010
    packet.ipv4.protocol = 253
    packet.ipv4.checksum = 0x1111
    packet.icmpv4.type = 13
    packet.icmpv4.code = 7
    packet.icmpv4.checksum = 0x2222
    packet.icmpv4.id = 0x3333
    packet.icmpv4.seq = 0x4444
    packet.payload = bytes.fromHex("DE AD BE EF")
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	frame := packet.Bytes()
	if got := uint16(frame[12])<<8 | uint16(frame[13]); got != 0x88b5 {
		t.Fatalf("expected ethernet type 0x88b5, got 0x%04x", got)
	}
	if got := uint16(frame[16])<<8 | uint16(frame[17]); got != 77 {
		t.Fatalf("expected ipv4 length 77, got %d", got)
	}
	if got := uint16(frame[18])<<8 | uint16(frame[19]); got != 0x1010 {
		t.Fatalf("expected ipv4 id 0x1010, got 0x%04x", got)
	}
	if got := frame[23]; got != 253 {
		t.Fatalf("expected protocol 253, got %d", got)
	}
	if got := uint16(frame[24])<<8 | uint16(frame[25]); got != 0x1111 {
		t.Fatalf("expected ipv4 checksum 0x1111, got 0x%04x", got)
	}
	if got := frame[34]; got != 13 || frame[35] != 7 {
		t.Fatalf("expected icmp type/code 13/7, got %d/%d", got, frame[35])
	}
	if got := uint16(frame[36])<<8 | uint16(frame[37]); got != 0x2222 {
		t.Fatalf("expected icmp checksum 0x2222, got 0x%04x", got)
	}
	if got := uint16(frame[38])<<8 | uint16(frame[39]); got != 0x3333 {
		t.Fatalf("expected icmp id 0x3333, got 0x%04x", got)
	}
	if got := uint16(frame[40])<<8 | uint16(frame[41]); got != 0x4444 {
		t.Fatalf("expected icmp seq 0x4444, got 0x%04x", got)
	}
	if got := frame[42:]; len(got) != 4 || got[0] != 0xde || got[3] != 0xef {
		t.Fatalf("expected payload override, got %v", got)
	}
}

func TestExecuteSupportsNumericICMPTypeCodeShorthand(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Numeric TypeCode",
		Source: `def main(packet, ctx):
    packet.icmpv4.typeCode = "13/7"
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	icmpLayer := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmpLayer.TypeCode.Type() != 13 || icmpLayer.TypeCode.Code() != 7 {
		t.Fatalf("expected numeric typeCode shorthand to apply, got %v", icmpLayer.TypeCode)
	}
}

func TestExecuteSupportsARPFieldMutation(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "ARP Mutation",
		Source: `def main(packet, ctx):
    packet.arp.addrType = 99
    packet.arp.protocol = 0x88b5
    packet.arp.operation = 7
    packet.arp.sourceHwAddress = "aa:bb:cc:dd:ee:ff"
    packet.arp.sourceProtAddress = "10.0.0.7"
    packet.arp.dstHwAddress = "11:22:33:44:55:66"
    packet.arp.dstProtAddress = "10.0.0.8"
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildARPRequestPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	))

	if err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	arpLayer := decoded.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arpLayer.AddrType != layers.LinkType(99) || arpLayer.Protocol != layers.EthernetType(0x88b5) || arpLayer.Operation != 7 {
		t.Fatalf("expected ARP scalar overrides, got %+v", *arpLayer)
	}
	if got := net.HardwareAddr(arpLayer.SourceHwAddress).String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected source hw override, got %s", got)
	}
	if got := net.IP(arpLayer.SourceProtAddress).String(); got != "10.0.0.7" {
		t.Fatalf("expected source protocol override, got %s", got)
	}
	if got := net.HardwareAddr(arpLayer.DstHwAddress).String(); got != "11:22:33:44:55:66" {
		t.Fatalf("expected target hw override, got %s", got)
	}
	if got := net.IP(arpLayer.DstProtAddress).String(); got != "10.0.0.8" {
		t.Fatalf("expected target protocol override, got %s", got)
	}
}

func mustMutablePacketFromOutboundPacket(t *testing.T, outbound *packetpkg.OutboundPacket) *MutablePacket {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := outbound.SerializeValidatedInto(buffer); err != nil {
		t.Fatalf("serialize outbound packet: %v", err)
	}

	packet, err := NewMutablePacket(append([]byte(nil), buffer.Bytes()...))
	if err != nil {
		t.Fatalf("new mutable packet: %v", err)
	}
	return packet
}

func decodeMutablePacket(packet *MutablePacket) gopacket.Packet {
	return gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.NoCopy)
}

func icmpPayload(t *testing.T, packet *MutablePacket) []byte {
	t.Helper()

	decoded := decodeMutablePacket(packet)
	icmpLayer, _ := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmpLayer == nil {
		t.Fatalf("expected ICMPv4 layer, got %v", decoded.Layers())
	}
	return append([]byte(nil), icmpLayer.Payload...)
}
