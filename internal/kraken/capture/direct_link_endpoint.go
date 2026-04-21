package capture

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type dispatcherState struct {
	dispatcher stack.NetworkDispatcher
}

type directLinkEndpoint struct {
	dispatcher   atomic.Value
	closed       atomic.Bool
	linkAddr     atomic.Value
	mtu          atomic.Uint32
	writePackets func(stack.PacketBufferList) (int, tcpip.Error)
}

func newDirectLinkEndpoint(mtu uint32, linkAddr tcpip.LinkAddress, writePackets func(stack.PacketBufferList) (int, tcpip.Error)) *directLinkEndpoint {
	endpoint := &directLinkEndpoint{
		writePackets: writePackets,
	}
	endpoint.dispatcher.Store(dispatcherState{})
	endpoint.linkAddr.Store(linkAddr)
	endpoint.mtu.Store(mtu)
	return endpoint
}

func (endpoint *directLinkEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	dispatcher, _ := endpoint.dispatcher.Load().(dispatcherState)
	if endpoint.closed.Load() || dispatcher.dispatcher == nil {
		return
	}
	dispatcher.dispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (endpoint *directLinkEndpoint) MTU() uint32 {
	return endpoint.mtu.Load()
}

func (endpoint *directLinkEndpoint) SetMTU(mtu uint32) {
	endpoint.mtu.Store(mtu)
}

func (*directLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (endpoint *directLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	addr, _ := endpoint.linkAddr.Load().(tcpip.LinkAddress)
	return addr
}

func (endpoint *directLinkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	endpoint.linkAddr.Store(addr)
}

func (*directLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (endpoint *directLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	endpoint.closed.Store(false)
	endpoint.dispatcher.Store(dispatcherState{dispatcher: dispatcher})
}

func (endpoint *directLinkEndpoint) IsAttached() bool {
	dispatcher, _ := endpoint.dispatcher.Load().(dispatcherState)
	return !endpoint.closed.Load() && dispatcher.dispatcher != nil
}

func (*directLinkEndpoint) Wait() {}

func (*directLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (*directLinkEndpoint) AddHeader(*stack.PacketBuffer) {}

func (*directLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

func (endpoint *directLinkEndpoint) Close() {
	endpoint.closed.Store(true)
	endpoint.dispatcher.Store(dispatcherState{})
}

func (*directLinkEndpoint) SetOnCloseAction(func()) {}

func (endpoint *directLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if endpoint.closed.Load() || endpoint.writePackets == nil {
		return 0, &tcpip.ErrClosedForSend{}
	}
	return endpoint.writePackets(pkts)
}
