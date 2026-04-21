package capture

import (
	"maps"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type benchmarkForwardingListener struct {
	forwardingProbeListener
}

func (listener *benchmarkForwardingListener) InjectFrame([]byte) error {
	listener.injected++
	return nil
}

func (listener *benchmarkForwardingListener) RouteFrame(adoption.Identity, routingpkg.StoredRoute, []byte) error {
	listener.routed++
	return nil
}

func BenchmarkClassifyInboundFrameARP(b *testing.B) {
	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildARPRequestPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		_, _ = classifyInboundFrame(frame)
	}
}

func BenchmarkClassifyInboundFrameICMP(b *testing.B) {
	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		_, _ = classifyInboundFrame(frame)
	}
}

func BenchmarkAppendPacketBufferTo(b *testing.B) {
	benchmarks := map[string]*stack.PacketBuffer{
		"contiguous": benchmarkContiguousTCPPacket(8080, 50505, []byte("hello")),
		"split":      benchmarkSplitRawPacket([]byte("header"), []byte("payload")),
	}
	for _, packet := range benchmarks {
		defer packet.DecRef()
	}

	for name, packet := range benchmarks {
		b.Run(name+"/pooled", func(b *testing.B) {
			frame := make([]byte, 0, packet.Size())
			b.ReportAllocs()
			b.SetBytes(int64(packet.Size()))
			for i := 0; i < b.N; i++ {
				frame = appendPacketBufferTo(frame[:0], packet)
			}
		})

		b.Run(name+"/grow", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(packet.Size()))
			for i := 0; i < b.N; i++ {
				frame := appendPacketBufferTo(nil, packet)
				if len(frame) != packet.Size() {
					b.Fatalf("expected frame size %d, got %d", packet.Size(), len(frame))
				}
			}
		})
	}
}

func BenchmarkPacketBufferSlice(b *testing.B) {
	b.Run("contiguous", func(b *testing.B) {
		packet := benchmarkContiguousRawPacket([]byte("hello"))
		defer packet.DecRef()

		b.ReportAllocs()
		b.SetBytes(int64(packet.Size()))
		for i := 0; i < b.N; i++ {
			frame, ok := packetBufferSlice(packet)
			if !ok || len(frame) != packet.Size() {
				b.Fatalf("expected contiguous packet buffer slice")
			}
		}
	})

	b.Run("split", func(b *testing.B) {
		packet := benchmarkSplitRawPacket([]byte("head"), []byte("tail"))
		defer packet.DecRef()

		b.ReportAllocs()
		b.SetBytes(int64(packet.Size()))
		for i := 0; i < b.N; i++ {
			if frame, ok := packetBufferSlice(packet); ok || frame != nil {
				b.Fatal("expected split packet buffer to require copy")
			}
		}
	})
}

func BenchmarkIdentitySnapshot(b *testing.B) {
	group := &adoptedEngine{}
	group.stateV.Store(adoptedEngineState{
		identity: fakeIdentity{
			label: "bench",
			ip:    net.IPv4(192, 168, 56, 10),
			mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		},
	})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if group.identitySnapshot() == nil {
			b.Fatal("expected identity snapshot")
		}
	}
}

func BenchmarkIsManagedHTTPPacket(b *testing.B) {
	packet := benchmarkContiguousTCPPacket(8080, 50505, nil)
	defer packet.DecRef()

	b.Run("miss-no-managed-ports", func(b *testing.B) {
		group := &adoptedEngine{managedHTTPPorts: make(map[uint16]int)}
		group.managedHTTPPortsV.Store(make(map[uint16]int))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if group.isManagedHTTPPacket(packet) {
				b.Fatal("expected no managed HTTP match")
			}
		}
	})

	b.Run("hit", func(b *testing.B) {
		group := &adoptedEngine{managedHTTPPorts: map[uint16]int{8080: 1}}
		group.managedHTTPPortsV.Store(maps.Clone(group.managedHTTPPorts))
		group.managedHTTPPortCount.Store(1)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !group.isManagedHTTPPacket(packet) {
				b.Fatal("expected managed HTTP match")
			}
		}
	})
}

func BenchmarkRememberPeerStable(b *testing.B) {
	group, err := newAdoptedEngine(adoptedEngineConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, func(_ *adoptedEngine, pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	if err != nil {
		b.Fatalf("new adopted engine: %v", err)
	}
	defer group.close()

	ip := compactIPv4FromIP(net.IPv4(192, 168, 56, 20))
	mac := compactMACFromSlice([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		group.rememberPeer(ip, mac)
	}
}

func BenchmarkDispatchInboundFrameICMP(b *testing.B) {
	outbound := 0
	group, identity := benchmarkInboundGroup(b, &outbound)
	defer group.close()

	listener := &pcapAdoptionListener{
		engines: map[compactIPv4]*adoptedEngine{compactIPv4FromIP(identity.ip): group},
	}
	listener.enginesV.Store(maps.Clone(listener.engines))

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.ip,
		identity.mac,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))
	group.rememberPeer(
		compactIPv4FromIP(net.IPv4(192, 168, 56, 20)),
		compactMACFromSlice([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}),
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		listener.dispatchInboundFrame(frame)
	}
	if outbound == 0 {
		b.Fatal("expected inbound ICMP to trigger outbound work")
	}
}

func BenchmarkDispatchInboundFrameForwardedDirect(b *testing.B) {
	target := &benchmarkForwardingListener{}
	listener := &pcapAdoptionListener{
		forward: func(destinationIP net.IP) (adoption.ForwardingDecision, bool) {
			return adoption.ForwardingDecision{
				Listener: target,
				Identity: fakeIdentity{ip: destinationIP},
			}, true
		},
	}
	listener.enginesV.Store(map[compactIPv4]*adoptedEngine{})

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		listener.dispatchInboundFrame(frame)
	}
	if target.injected == 0 {
		b.Fatal("expected direct forwarding work")
	}
}

func BenchmarkDispatchInboundFrameForwardedRoute(b *testing.B) {
	target := &benchmarkForwardingListener{}
	route := routingpkg.StoredRoute{
		Label:           "lab-segment",
		DestinationCIDR: "10.0.0.0/24",
		ViaAdoptedIP:    "192.168.56.10",
	}
	listener := &pcapAdoptionListener{
		forward: func(destinationIP net.IP) (adoption.ForwardingDecision, bool) {
			return adoption.ForwardingDecision{
				Listener: target,
				Identity: fakeIdentity{ip: net.IPv4(192, 168, 56, 10)},
				Route:    route,
				Routed:   true,
			}, destinationIP != nil
		},
	}
	listener.enginesV.Store(map[compactIPv4]*adoptedEngine{})

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		listener.dispatchInboundFrame(frame)
	}
	if target.routed == 0 {
		b.Fatal("expected routed forwarding work")
	}
}

func BenchmarkInjectFrameICMP(b *testing.B) {
	outbound := 0
	group, identity := benchmarkInboundGroup(b, &outbound)
	defer group.close()

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.ip,
		identity.mac,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))
	peerIP := compactIPv4FromIP(net.IPv4(192, 168, 56, 20))
	peerMAC := compactMACFromSlice([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20})

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		group.rememberPeer(peerIP, peerMAC)
		group.injectFrame(frame)
	}
	if outbound == 0 {
		b.Fatal("expected inbound ICMP to trigger outbound work")
	}
}

func benchmarkContiguousTCPPacket(sourcePort, targetPort uint16, payload []byte) *stack.PacketBuffer {
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	packet.TransportProtocolNumber = tcp.ProtocolNumber
	packet.NetworkProtocolNumber = ipv4.ProtocolNumber
	packet.EgressRoute.LocalAddress = tcpip.AddrFrom4Slice(net.IPv4(192, 168, 56, 10).To4())

	tcpHeader := header.TCP(packet.TransportHeader().Push(header.TCPMinimumSize))
	tcpHeader.Encode(&header.TCPFields{
		SrcPort:    sourcePort,
		DstPort:    targetPort,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		WindowSize: 64240,
	})

	ipHeader := header.IPv4(packet.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.TCPMinimumSize + len(payload)),
		TTL:         64,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 56, 10).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 56, 20).To4()),
	})

	return packet
}

func benchmarkContiguousRawPacket(payload []byte) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
}

func benchmarkSplitRawPacket(parts ...[]byte) *stack.PacketBuffer {
	if len(parts) == 0 {
		return stack.NewPacketBuffer(stack.PacketBufferOptions{})
	}

	headerPart := parts[0]
	payloadSize := 0
	for _, part := range parts[1:] {
		payloadSize += len(part)
	}
	payload := make([]byte, 0, payloadSize)
	for _, part := range parts[1:] {
		payload = append(payload, part...)
	}

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: len(headerPart),
		Payload:            buffer.MakeWithData(payload),
	})
	copy(packet.LinkHeader().Push(len(headerPart)), headerPart)
	return packet
}

func benchmarkInboundGroup(b *testing.B, outbound *int) (*adoptedEngine, fakeIdentity) {
	b.Helper()

	group, err := newAdoptedEngine(adoptedEngineConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		routes: []net.IPNet{{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		}},
	}, func(_ *adoptedEngine, pkts stack.PacketBufferList) (int, tcpip.Error) {
		if outbound != nil {
			*outbound += pkts.Len()
		}
		return pkts.Len(), nil
	})
	if err != nil {
		b.Fatalf("new adopted engine: %v", err)
	}

	identity := fakeIdentity{
		label: "bench",
		ip:    net.IPv4(192, 168, 56, 10),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := group.addIdentity(identity); err != nil {
		group.close()
		b.Fatalf("add identity: %v", err)
	}

	return group, identity
}

func serializeBenchmarkOutboundPacket(b *testing.B, packet *packetpkg.OutboundPacket) []byte {
	b.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := packet.SerializeValidatedInto(buffer); err != nil {
		b.Fatalf("serialize outbound packet: %v", err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}
