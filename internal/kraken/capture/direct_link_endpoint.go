package capture

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type dispatcherState struct {
	dispatcher stack.NetworkDispatcher
}

type directLinkEndpoint struct {
	stateMu sync.RWMutex

	dispatcher    atomic.Value
	closed        atomic.Bool
	linkAddr      tcpip.LinkAddress
	mtu           uint32
	writePackets  func(stack.PacketBufferList) (int, tcpip.Error)
	onCloseAction func()
}

func newDirectLinkEndpoint(mtu uint32, linkAddr tcpip.LinkAddress, writePackets func(stack.PacketBufferList) (int, tcpip.Error)) *directLinkEndpoint {
	endpoint := &directLinkEndpoint{
		linkAddr:     linkAddr,
		mtu:          mtu,
		writePackets: writePackets,
	}
	endpoint.dispatcher.Store(dispatcherState{})
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
	endpoint.stateMu.RLock()
	defer endpoint.stateMu.RUnlock()
	return endpoint.mtu
}

func (endpoint *directLinkEndpoint) SetMTU(mtu uint32) {
	endpoint.stateMu.Lock()
	defer endpoint.stateMu.Unlock()
	endpoint.mtu = mtu
}

func (*directLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (endpoint *directLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	endpoint.stateMu.RLock()
	defer endpoint.stateMu.RUnlock()
	return endpoint.linkAddr
}

func (endpoint *directLinkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	endpoint.stateMu.Lock()
	defer endpoint.stateMu.Unlock()
	endpoint.linkAddr = addr
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
	endpoint.stateMu.Lock()
	onClose := endpoint.onCloseAction
	endpoint.stateMu.Unlock()
	endpoint.closed.Store(true)
	endpoint.dispatcher.Store(dispatcherState{})

	if onClose != nil {
		onClose()
	}
}

func (endpoint *directLinkEndpoint) SetOnCloseAction(action func()) {
	endpoint.stateMu.Lock()
	defer endpoint.stateMu.Unlock()
	endpoint.onCloseAction = action
}

func (endpoint *directLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if endpoint.closed.Load() || endpoint.writePackets == nil {
		return 0, &tcpip.ErrClosedForSend{}
	}
	return endpoint.writePackets(pkts)
}
