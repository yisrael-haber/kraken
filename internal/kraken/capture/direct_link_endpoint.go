package capture

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type directLinkEndpoint struct {
	mu sync.RWMutex

	dispatcher    stack.NetworkDispatcher
	linkAddr      tcpip.LinkAddress
	mtu           uint32
	writePackets  func(stack.PacketBufferList) (int, tcpip.Error)
	onCloseAction func()
}

func newDirectLinkEndpoint(mtu uint32, linkAddr tcpip.LinkAddress, writePackets func(stack.PacketBufferList) (int, tcpip.Error)) *directLinkEndpoint {
	return &directLinkEndpoint{
		linkAddr:     linkAddr,
		mtu:          mtu,
		writePackets: writePackets,
	}
}

func (endpoint *directLinkEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	endpoint.mu.RLock()
	dispatcher := endpoint.dispatcher
	endpoint.mu.RUnlock()
	if dispatcher == nil {
		return
	}

	dispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (endpoint *directLinkEndpoint) MTU() uint32 {
	endpoint.mu.RLock()
	defer endpoint.mu.RUnlock()
	return endpoint.mtu
}

func (endpoint *directLinkEndpoint) SetMTU(mtu uint32) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.mtu = mtu
}

func (*directLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (endpoint *directLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	endpoint.mu.RLock()
	defer endpoint.mu.RUnlock()
	return endpoint.linkAddr
}

func (endpoint *directLinkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.linkAddr = addr
}

func (*directLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (endpoint *directLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.dispatcher = dispatcher
}

func (endpoint *directLinkEndpoint) IsAttached() bool {
	endpoint.mu.RLock()
	defer endpoint.mu.RUnlock()
	return endpoint.dispatcher != nil
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
	endpoint.mu.Lock()
	onClose := endpoint.onCloseAction
	endpoint.dispatcher = nil
	endpoint.mu.Unlock()

	if onClose != nil {
		onClose()
	}
}

func (endpoint *directLinkEndpoint) SetOnCloseAction(action func()) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.onCloseAction = action
}

func (endpoint *directLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	endpoint.mu.RLock()
	writePackets := endpoint.writePackets
	endpoint.mu.RUnlock()
	if writePackets == nil {
		return 0, &tcpip.ErrClosedForSend{}
	}
	return writePackets(pkts)
}
