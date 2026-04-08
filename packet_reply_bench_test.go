package main

import (
	"net"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func benchmarkEchoReply(b *testing.B, overrideName string, resolve packetOverrideLookup) {
	listener := &pcapAdoptionListener{
		resolveOverride: resolve,
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

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		packet := buildICMPEchoPacket(
			sourceIP,
			sourceMAC,
			targetIP,
			targetMAC,
			layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
			1,
			1,
			payload,
		)
		if err := listener.prepareReadyPacket(packet, overrideName); err != nil {
			b.Fatal(err)
		}
		if err := packet.serializeValidatedInto(buffer); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEchoReplyHotPath_NoOverride(b *testing.B) {
	benchmarkEchoReply(b, "", nil)
}

func BenchmarkEchoReplyHotPath_TTLOverride(b *testing.B) {
	ttl := 80
	override, err := normalizeStoredPacketOverride(StoredPacketOverride{
		Name: "TTL Override",
		Layers: PacketOverrideLayers{
			IPv4: &PacketOverrideIPv4{
				TTL: &ttl,
			},
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	benchmarkEchoReply(b, override.Name, func(name string) (StoredPacketOverride, bool) {
		return override, name == override.Name
	})
}
