package script

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

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

func TestStoredScriptStoreLookupOnlyCompilesChosenScript(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	if _, err := store.Save(SaveStoredScriptRequest{
		Name: "Healthy Script",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 16
`,
	}); err != nil {
		t.Fatalf("save healthy script: %v", err)
	}
	if _, err := store.Save(SaveStoredScriptRequest{
		Name: "Broken Script",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl =
`,
	}); err != nil {
		t.Fatalf("save broken script: %v", err)
	}

	store = NewStoreAtDir(store.dir)

	names, err := store.ListNames()
	if err != nil {
		t.Fatalf("list stored script names: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d (%v)", len(names), names)
	}

	script, err := store.Lookup("Healthy Script")
	if err != nil {
		t.Fatalf("lookup healthy script: %v", err)
	}
	if script.Name != "Healthy Script" {
		t.Fatalf("expected healthy script, got %q", script.Name)
	}

	if _, err := store.Lookup("Broken Script"); !errors.Is(err, ErrStoredScriptInvalid) {
		t.Fatalf("expected broken script lookup to fail, got %v", err)
	}
}

func TestStoredScriptStoreListNamesReadsDiskEachTime(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	if _, err := store.Save(SaveStoredScriptRequest{
		Name: "Alpha",
		Source: `def main(packet, ctx):
    pass
`,
	}); err != nil {
		t.Fatalf("save alpha script: %v", err)
	}

	names, err := store.ListNames()
	if err != nil {
		t.Fatalf("list names: %v", err)
	}
	if len(names) != 1 || names[0] != "Alpha" {
		t.Fatalf("expected [Alpha], got %v", names)
	}

	path, err := pathForStoredScript(store.dir, "Beta")
	if err != nil {
		t.Fatalf("path for beta: %v", err)
	}
	if err := os.WriteFile(path, []byte("def main(packet, ctx):\n    pass\n"), 0o644); err != nil {
		t.Fatalf("write beta script: %v", err)
	}

	names, err = store.ListNames()
	if err != nil {
		t.Fatalf("list names after external write: %v", err)
	}
	if len(names) != 2 || names[0] != "Alpha" || names[1] != "Beta" {
		t.Fatalf("expected [Alpha Beta], got %v", names)
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

	packet := packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	)

	err = Execute(script, packet, ExecutionContext{
		ScriptName: "Bytes Payload",
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

	want := []byte("PING:Bytes Payload\x00\xff")
	if len(packet.Payload) != len(want) {
		t.Fatalf("expected payload length %d, got %d (%v)", len(want), len(packet.Payload), packet.Payload)
	}
	for index := range want {
		if packet.Payload[index] != want[index] {
			t.Fatalf("expected payload %v, got %v", want, packet.Payload)
		}
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

	packet := packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	)

	err = Execute(script, packet, ExecutionContext{
		ScriptName: "icmp_shift",
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

	want := []byte("icmp_shift")
	if len(packet.Payload) != len(want) {
		t.Fatalf("expected payload length %d, got %d (%v)", len(want), len(packet.Payload), packet.Payload)
	}
	for index := range want {
		if packet.Payload[index] != want[index] {
			t.Fatalf("expected payload %v, got %v", want, packet.Payload)
		}
	}
}

func TestExecuteSupportsFullICMPHeaderMutationAndSerializationControls(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Full Header Mutation",
		Source: `bytes = require("kraken/bytes")

def main(packet, ctx):
    packet.serialization.fixLengths = False
    packet.serialization.computeChecksums = False
    packet.ethernet.ethernetType = 0x88b5
    packet.ethernet.length = 44
    packet.ipv4.version = 5
    packet.ipv4.ihl = 7
    packet.ipv4.length = 77
    packet.ipv4.flags = 5
    packet.ipv4.fragOffset = 11
    packet.ipv4.protocol = 253
    packet.ipv4.checksum = 0x1111
    packet.ipv4.options = [
        struct(optionType=7, optionLength=4, optionData=bytes.fromHex("AA BB")),
    ]
    packet.ipv4.padding = bytes.fromHex("00 00")
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

	packet := packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
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

	if packet.Ethernet.EthernetType != layers.EthernetType(0x88b5) || packet.Ethernet.Length != 44 {
		t.Fatalf("expected Ethernet overrides, got %+v", *packet.Ethernet)
	}
	if packet.IPv4.Version != 5 || packet.IPv4.IHL != 7 || packet.IPv4.Length != 77 || packet.IPv4.Flags != layers.IPv4Flag(5) || packet.IPv4.FragOffset != 11 || packet.IPv4.Protocol != layers.IPProtocol(253) || packet.IPv4.Checksum != 0x1111 {
		t.Fatalf("expected IPv4 overrides, got %+v", *packet.IPv4)
	}
	if len(packet.IPv4.Options) != 1 || packet.IPv4.Options[0].OptionType != 7 || packet.IPv4.Options[0].OptionLength != 4 || len(packet.IPv4.Padding) != 2 {
		t.Fatalf("expected IPv4 options and padding override, got options=%+v padding=%v", packet.IPv4.Options, packet.IPv4.Padding)
	}
	if packet.ICMPv4.TypeCode.Type() != 13 || packet.ICMPv4.TypeCode.Code() != 7 || packet.ICMPv4.Checksum != 0x2222 || packet.ICMPv4.Id != 0x3333 || packet.ICMPv4.Seq != 0x4444 {
		t.Fatalf("expected ICMP overrides, got %+v", *packet.ICMPv4)
	}
	if got := packet.SerializationOptions(); got.FixLengths || got.ComputeChecksums {
		t.Fatalf("expected serialization fixups to be disabled, got %+v", got)
	}
	if len(packet.Payload) != 4 || packet.Payload[0] != 0xde || packet.Payload[3] != 0xef {
		t.Fatalf("expected payload override, got %v", packet.Payload)
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

	packet := packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
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

	if packet.ICMPv4.TypeCode.Type() != 13 || packet.ICMPv4.TypeCode.Code() != 7 {
		t.Fatalf("expected numeric typeCode shorthand to apply, got %v", packet.ICMPv4.TypeCode)
	}
}

func TestExecuteSupportsRawARPFieldMutation(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Raw ARP Mutation",
		Source: `def main(packet, ctx):
    packet.arp.addrType = 99
    packet.arp.protocol = 0x88b5
    packet.arp.hwAddressSize = 2
    packet.arp.protAddressSize = 3
    packet.arp.operation = 7
    packet.arp.sourceHwAddress = "AA BB"
    packet.arp.sourceProtAddress = "DE AD BE"
    packet.arp.dstHwAddress = "CC DD"
    packet.arp.dstProtAddress = "EF 01 02"
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(saved.Name)
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := packetpkg.BuildARPRequestPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	)

	err = Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		SendPath:   "arp-request",
		Protocol:   "arp",
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute script: %v", err)
	}

	if packet.ARP.AddrType != layers.LinkType(99) || packet.ARP.Protocol != layers.EthernetType(0x88b5) || packet.ARP.HwAddressSize != 2 || packet.ARP.ProtAddressSize != 3 || packet.ARP.Operation != 7 {
		t.Fatalf("expected ARP scalar overrides, got %+v", *packet.ARP)
	}
	if len(packet.ARP.SourceHwAddress) != 2 || packet.ARP.SourceHwAddress[0] != 0xaa || len(packet.ARP.SourceProtAddress) != 3 || packet.ARP.DstProtAddress[2] != 0x02 {
		t.Fatalf("expected ARP raw bytes override, got srcHw=%v srcProt=%v dstHw=%v dstProt=%v", packet.ARP.SourceHwAddress, packet.ARP.SourceProtAddress, packet.ARP.DstHwAddress, packet.ARP.DstProtAddress)
	}
}

func TestExecuteExposesHyphenatedSendPathContext(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "SendPath Echo",
		Source: `bytes = require("kraken/bytes")

def main(packet, ctx):
    packet.payload = bytes.fromUTF8(ctx.sendPath)
`,
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
		nil,
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

	want := []byte("icmp-echo-reply")
	if string(packet.Payload) != string(want) {
		t.Fatalf("expected sendPath payload %q, got %q", string(want), string(packet.Payload))
	}
}
