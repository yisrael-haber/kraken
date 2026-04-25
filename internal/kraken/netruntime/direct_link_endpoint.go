package netruntime

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type dispatcherState struct {
	dispatcher stack.NetworkDispatcher
}

type DirectLinkEndpoint struct {
	dispatcher   atomic.Value
	closed       atomic.Bool
	linkAddr     atomic.Value
	mtu          atomic.Uint32
	writePackets func(stack.PacketBufferList) (int, tcpip.Error)
}

func NewDirectLinkEndpoint(mtu uint32, linkAddr tcpip.LinkAddress, writePackets func(stack.PacketBufferList) (int, tcpip.Error)) *DirectLinkEndpoint {
	endpoint := &DirectLinkEndpoint{
		writePackets: writePackets,
	}
	endpoint.dispatcher.Store(dispatcherState{})
	endpoint.linkAddr.Store(linkAddr)
	endpoint.mtu.Store(mtu)
	return endpoint
}

func (endpoint *DirectLinkEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	dispatcher, _ := endpoint.dispatcher.Load().(dispatcherState)
	if endpoint.closed.Load() || dispatcher.dispatcher == nil {
		return
	}
	dispatcher.dispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (endpoint *DirectLinkEndpoint) MTU() uint32 {
	return endpoint.mtu.Load()
}

func (endpoint *DirectLinkEndpoint) SetMTU(mtu uint32) {
	endpoint.mtu.Store(mtu)
}

func (*DirectLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (endpoint *DirectLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	addr, _ := endpoint.linkAddr.Load().(tcpip.LinkAddress)
	return addr
}

func (endpoint *DirectLinkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	endpoint.linkAddr.Store(addr)
}

func (*DirectLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (endpoint *DirectLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	endpoint.closed.Store(false)
	endpoint.dispatcher.Store(dispatcherState{dispatcher: dispatcher})
}

func (endpoint *DirectLinkEndpoint) IsAttached() bool {
	dispatcher, _ := endpoint.dispatcher.Load().(dispatcherState)
	return !endpoint.closed.Load() && dispatcher.dispatcher != nil
}

func (*DirectLinkEndpoint) Wait() {}

func (*DirectLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (*DirectLinkEndpoint) AddHeader(*stack.PacketBuffer) {}

func (*DirectLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

func (endpoint *DirectLinkEndpoint) Close() {
	endpoint.closed.Store(true)
	endpoint.dispatcher.Store(dispatcherState{})
}

func (*DirectLinkEndpoint) SetOnCloseAction(func()) {}

func (endpoint *DirectLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if endpoint.closed.Load() || endpoint.writePackets == nil {
		return 0, &tcpip.ErrClosedForSend{}
	}
	return endpoint.writePackets(pkts)
}
