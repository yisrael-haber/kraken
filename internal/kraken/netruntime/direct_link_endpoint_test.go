package netruntime

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type fakeNetworkDispatcher struct {
	networkPackets int
	linkPackets    int
}

func (dispatcher *fakeNetworkDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	dispatcher.networkPackets++
}

func (dispatcher *fakeNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	dispatcher.linkPackets++
}

func TestDirectLinkEndpointDeliversAttachedInboundPackets(t *testing.T) {
	endpoint := NewDirectLinkEndpoint(1500, "", func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	dispatcher := &fakeNetworkDispatcher{}
	endpoint.Attach(dispatcher)

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer packet.DecRef()

	endpoint.InjectInbound(0, packet)

	if dispatcher.networkPackets != 1 {
		t.Fatalf("expected one delivered network packet, got %d", dispatcher.networkPackets)
	}
}

func TestDirectLinkEndpointWritePacketsFailsAfterClose(t *testing.T) {
	endpoint := NewDirectLinkEndpoint(1500, "", func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	endpoint.Close()

	if _, err := endpoint.WritePackets(stack.PacketBufferList{}); err == nil {
		t.Fatal("expected closed endpoint to reject packet writes")
	}
}

func BenchmarkDirectLinkEndpointInjectInbound(b *testing.B) {
	endpoint := NewDirectLinkEndpoint(1500, "", func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	dispatcher := &fakeNetworkDispatcher{}
	endpoint.Attach(dispatcher)

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer packet.DecRef()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		endpoint.InjectInbound(0, packet)
	}
}

func BenchmarkDirectLinkEndpointWritePackets(b *testing.B) {
	endpoint := NewDirectLinkEndpoint(1500, "", func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer packet.DecRef()
	var packets stack.PacketBufferList
	packets.PushBack(packet)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := endpoint.WritePackets(packets); err != nil {
			b.Fatalf("write packets: %v", err)
		}
	}
}
