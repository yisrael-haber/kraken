package capture

import (
	"net"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	adoptionpkg "github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

func benchmarkEchoReply(b *testing.B, scriptName string, resolve adoptionpkg.ScriptLookupFunc) {
	listener := &pcapAdoptionListener{
		resolveScript: resolve,
		serializeBufferPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBufferExpectedSize(64, 64)
			},
		},
	}
	sourceIP := net.IPv4(192, 168, 30, 150)
	sourceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x96}
	targetIP := net.IPv4(192, 168, 30, 20)
	targetMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}
	payload := make([]byte, 32)
	buffer := listener.serializeBufferPool.Get().(gopacket.SerializeBuffer)
	defer listener.serializeBufferPool.Put(buffer)
	identity := fakeIdentity{
		label: "bench-host",
		ip:    sourceIP,
		iface: net.Interface{Name: "eth0"},
		mac:   sourceMAC,
		bindings: adoptionpkg.AdoptedIPAddressScriptBindings{
			adoptionpkg.SendPathICMPEchoReply: scriptName,
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if scriptName == "" {
			frame := listener.takeICMPEchoFrame(len(payload))
			frame = marshalICMPEchoFrame(
				frame,
				sourceIP,
				sourceMAC,
				targetIP,
				targetMAC,
				layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
				1,
				1,
				payload,
			)
			listener.releaseICMPEchoFrame(frame)
			continue
		}

		pooledPacket := listener.takeICMPEchoPacket()
		packet := pooledPacket.init(
			sourceIP,
			sourceMAC,
			targetIP,
			targetMAC,
			layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
			1,
			1,
			payload,
		)
		if err := listener.prepareReadyPacket(packet, buildBoundPacketScript(identity, adoptionpkg.SendPathICMPEchoReply, "icmpv4")); err != nil {
			listener.releaseICMPEchoPacket(pooledPacket)
			b.Fatal(err)
		}
		if err := packet.SerializeValidatedInto(buffer); err != nil {
			listener.releaseICMPEchoPacket(pooledPacket)
			b.Fatal(err)
		}
		listener.releaseICMPEchoPacket(pooledPacket)
	}
}

func BenchmarkEchoReplyHotPath_NoScript(b *testing.B) {
	benchmarkEchoReply(b, "", nil)
}

func BenchmarkEchoReplyHotPath_WithScript(b *testing.B) {
	store := scriptpkg.NewStoreAtDir(b.TempDir())
	saved, err := store.Save(scriptpkg.SaveStoredScriptRequest{
		Name: "ttl-clamp",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 80
`,
	})
	if err != nil {
		b.Fatal(err)
	}
	if !saved.Available {
		b.Fatalf("expected benchmark script to compile, compileError=%q", saved.CompileError)
	}

	benchmarkEchoReply(b, saved.Name, func(name string) (scriptpkg.StoredScript, error) {
		if name != saved.Name {
			return scriptpkg.StoredScript{}, scriptpkg.ErrStoredScriptNotFound
		}

		return store.Lookup(name)
	})
}
