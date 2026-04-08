package main

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestOutboundPacketApplyOverrideDoesNotRequireReadyPacket(t *testing.T) {
	packet := buildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		nil,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		1,
		nil,
	)

	err := packet.applyOverride(StoredPacketOverride{
		Name: "TTL Override",
		Layers: PacketOverrideLayers{
			IPv4: &PacketOverrideIPv4{
				TTL: intPointer(80),
			},
		},
	})
	if err != nil {
		t.Fatalf("apply override to partial packet: %v", err)
	}
	if packet.IPv4.TTL != 80 {
		t.Fatalf("expected IPv4 TTL 80 after override, got %d", packet.IPv4.TTL)
	}
}

func TestSerializeReadyPacketRejectsPartialPacketBeforeOverride(t *testing.T) {
	listener := &pcapAdoptionListener{
		resolveOverride: func(name string) (StoredPacketOverride, bool) {
			return StoredPacketOverride{
				Name: "TTL Override",
				Layers: PacketOverrideLayers{
					IPv4: &PacketOverrideIPv4{
						TTL: intPointer(80),
					},
				},
			}, true
		},
	}

	packet := buildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		nil,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		1,
		nil,
	)

	_, err := listener.serializeReadyPacket(packet, "TTL Override")
	if err == nil {
		t.Fatal("expected partial packet serialization to fail before applying override")
	}
	if err.Error() != "Ethernet.DstMAC is required" {
		t.Fatalf("expected partial packet validation error, got %v", err)
	}
}

func TestSerializeReadyPacketAppliesOverrideToReadyPacket(t *testing.T) {
	targetMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	listener := &pcapAdoptionListener{
		resolveOverride: func(name string) (StoredPacketOverride, bool) {
			return StoredPacketOverride{
				Name: "TTL Override",
				Layers: PacketOverrideLayers{
					IPv4: &PacketOverrideIPv4{
						TTL: intPointer(80),
					},
				},
			}, true
		},
	}

	packet := buildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		targetMAC,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		1,
		nil,
	)

	frame, err := listener.serializeReadyPacket(packet, "TTL Override")
	if err != nil {
		t.Fatalf("serialize ready packet with override: %v", err)
	}
	if len(frame) == 0 {
		t.Fatal("expected serialized frame bytes")
	}
	if packet.IPv4.TTL != 80 {
		t.Fatalf("expected IPv4 TTL 80 after override, got %d", packet.IPv4.TTL)
	}
	if !bytes.Equal(packet.Ethernet.DstMAC, targetMAC) {
		t.Fatalf("expected destination MAC %s to be preserved, got %s", targetMAC, packet.Ethernet.DstMAC)
	}
}
