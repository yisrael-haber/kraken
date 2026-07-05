package netruntime

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const adoptedNetstackNICID = tcpip.NICID(1)
const listenBacklog = 4096

type EngineConfig struct {
	IP             net.IP
	Label          string
	InterfaceName  string
	MAC            net.HardwareAddr
	SubnetPrefix   int
	DefaultGateway net.IP
	MTU            uint32
	PacketEndpoint PacketEndpoint
}

type PacketEndpoint interface {
	Write(*buffer.Buffer) error
}

type transportScript struct {
	compiled *script.CompiledScript
	ctx      script.ExecutionContext
}

type Engine struct {
	dispatcher      atomic.Pointer[stack.NetworkDispatcher]
	closed          atomic.Bool
	stack           *stack.Stack
	address         tcpip.Address
	linkAddr        tcpip.LinkAddress
	mtu             uint32
	packetEndpoint  PacketEndpoint
	scriptIdentity  script.ExecutionIdentity
	scriptMu        sync.RWMutex
	transportScript transportScript
}

func NewEngine(config EngineConfig) (*Engine, error) {
	address := tcpip.AddrFrom4Slice(config.IP)
	defaultGateway := ""
	if config.DefaultGateway != nil {
		defaultGateway = config.DefaultGateway.String()
	}

	engine := &Engine{
		address:        address,
		linkAddr:       tcpip.LinkAddress(config.MAC),
		mtu:            config.MTU,
		packetEndpoint: config.PacketEndpoint,
		scriptIdentity: script.ExecutionIdentity{
			Label:          config.Label,
			IP:             config.IP.String(),
			MAC:            config.MAC.String(),
			InterfaceName:  config.InterfaceName,
			DefaultGateway: defaultGateway,
			MTU:            int(config.MTU),
		},
	}
	stackEP := ethernet.New(engine)
	netstack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			arp.NewProtocol,
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	if err := netstack.CreateNICWithOptions(adoptedNetstackNICID, stackEP, stack.NICOptions{
		Name:               config.InterfaceName,
		DeliverLinkPackets: false,
	}); err != nil {
		return nil, fmt.Errorf("create adopted netstack NIC: %s", err)
	}
	if err := netstack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		netstack.Close()
		netstack.Wait()
		return nil, fmt.Errorf("enable adopted netstack IPv4 forwarding: %s", err)
	}

	routeMask := net.CIDRMask(config.SubnetPrefix, 32)
	subnet, _ := tcpip.NewSubnet(
		tcpip.AddrFrom4Slice(config.IP.Mask(routeMask)),
		tcpip.MaskFromBytes(routeMask),
	)
	routes := []tcpip.Route{
		{
			Destination: subnet,
			NIC:         adoptedNetstackNICID,
		},
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         adoptedNetstackNICID,
		},
	}
	if config.DefaultGateway != nil {
		routes[1].Gateway = tcpip.AddrFrom4Slice(config.DefaultGateway)
	}
	netstack.SetRouteTable(routes)
	if err := netstack.AddProtocolAddress(adoptedNetstackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: address, PrefixLen: config.SubnetPrefix},
	}, stack.AddressProperties{}); err != nil {
		netstack.Close()
		netstack.Wait()
		return nil, fmt.Errorf("assign adopted IPv4 address: %s", err)
	}

	engine.stack = netstack
	return engine, nil
}

func (engine *Engine) InjectFrame(frame buffer.Buffer) {
	ok := engine.prepareInjectedFrame(&frame)
	if !ok {
		frame.Release()
		return
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: frame,
	})
	defer packet.DecRef()
	dispatcher := engine.dispatcher.Load()
	if engine.closed.Load() || dispatcher == nil {
		return
	}
	(*dispatcher).DeliverNetworkPacket(0, packet)
}

func (engine *Engine) prepareInjectedFrame(frame *buffer.Buffer) bool {
	if view, ok := frame.PullUp(0, header.EthernetMinimumSize); ok {
		switch ethernetType := header.Ethernet(view.AsSlice()).Type(); ethernetType {
		case header.IPv4ProtocolNumber, header.ARPProtocolNumber:
			return true
		}
	}
	view, ok := frame.PullUp(0, header.IPv4MinimumSize)
	if !ok || !header.IPv4(view.AsSlice()).IsValid(int(frame.Size())) {
		return false
	}
	eth := make([]byte, header.EthernetMinimumSize)
	header.Ethernet(eth).Encode(&header.EthernetFields{
		SrcAddr: engine.linkAddr,
		DstAddr: engine.linkAddr,
		Type:    header.IPv4ProtocolNumber,
	})
	_ = frame.Prepend(buffer.NewViewWithData(eth))
	return true
}

func (engine *Engine) Close() {
	if engine.closed.Swap(true) {
		return
	}
	engine.stack.Close()
	engine.stack.Wait()
}

func (engine *Engine) MTU() uint32 { return engine.mtu }

func (engine *Engine) SetMTU(mtu uint32) {
	engine.mtu = mtu

	engine.scriptMu.Lock()
	engine.scriptIdentity.MTU = int(mtu)
	if engine.transportScript.compiled != nil {
		engine.transportScript.ctx.Adopted = engine.scriptIdentity
	}
	engine.scriptMu.Unlock()
}

func (*Engine) MaxHeaderLength() uint16 { return 0 }

func (engine *Engine) LinkAddress() tcpip.LinkAddress { return engine.linkAddr }

func (engine *Engine) SetLinkAddress(addr tcpip.LinkAddress) { engine.linkAddr = addr }

func (*Engine) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (engine *Engine) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		engine.dispatcher.Store(nil)
		return
	}
	engine.dispatcher.Store(&dispatcher)
}

func (engine *Engine) IsAttached() bool {
	return !engine.closed.Load() && engine.dispatcher.Load() != nil
}

func (*Engine) Wait() {}

func (*Engine) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

func (*Engine) AddHeader(*stack.PacketBuffer) {}

func (*Engine) ParseHeader(*stack.PacketBuffer) bool { return true }

func (*Engine) SetOnCloseAction(func()) {}

func (engine *Engine) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if engine.closed.Load() {
		return 0, &tcpip.ErrClosedForSend{}
	}
	sent := 0
	for _, pkt := range pkts.AsSlice() {
		if err := engine.emitFrame(pkt.ToBuffer()); err != nil {
			if sent == 0 {
				return 0, &tcpip.ErrAborted{}
			}
			return sent, nil
		}
		sent++
	}
	return sent, nil
}

func (engine *Engine) UpdateTransportScript(compiled *script.CompiledScript) {
	next := transportScript{compiled: compiled}
	engine.scriptMu.Lock()
	if compiled != nil {
		next.ctx = script.ExecutionContext{
			ScriptName: compiled.Name(),
			Adopted:    engine.scriptIdentity,
			Metadata: map[string]string{
				"direction": "outbound",
				"handler":   "transport",
			},
		}
	}
	engine.transportScript = next
	engine.scriptMu.Unlock()
}

func (engine *Engine) ScriptName() string {
	engine.scriptMu.RLock()
	transportScriptName := engine.transportScript.compiled.Name()
	engine.scriptMu.RUnlock()
	return transportScriptName
}

func (engine *Engine) ListenTCP(port int) (net.Listener, error) {
	addr := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: engine.address,
		Port: uint16(port),
	}
	listener, err := listenReusableTCP(engine.stack, addr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func listenReusableTCP(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (net.Listener, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, fmt.Errorf("%s", err.String())
	}

	ep.SocketOptions().SetReuseAddress(true)
	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "bind",
			Net:  "tcp",
			Addr: fullTCPAddr(addr),
			Err:  fmt.Errorf("%s", err.String()),
		}
	}

	if err := ep.Listen(listenBacklog); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "listen",
			Net:  "tcp",
			Addr: fullTCPAddr(addr),
			Err:  fmt.Errorf("%s", err.String()),
		}
	}

	return gonet.NewTCPListener(s, &wq, ep), nil
}

func fullTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IP(addr.Addr.AsSlice()),
		Port: int(addr.Port),
	}
}

func (engine *Engine) DialTCP(ctx context.Context, remoteIP net.IP, remotePort int) (net.Conn, error) {
	remoteIP = remoteIP.To4()
	local := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: engine.address,
	}
	remote := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(remoteIP),
		Port: uint16(remotePort),
	}
	return gonet.DialTCPWithBind(ctx, engine.stack, local, remote, ipv4.ProtocolNumber)
}

func (engine *Engine) DialUDP(remoteIP net.IP, remotePort int) (net.Conn, error) {
	remoteIP = remoteIP.To4()
	local := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: engine.address,
	}
	remote := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(remoteIP),
		Port: uint16(remotePort),
	}
	return gonet.DialUDP(engine.stack, &local, &remote, ipv4.ProtocolNumber)
}

func (engine *Engine) emitFrame(frame buffer.Buffer) error {
	engine.scriptMu.RLock()
	transportScript := engine.transportScript
	engine.scriptMu.RUnlock()
	if transportScript.compiled == nil {
		return engine.packetEndpoint.Write(&frame)
	}
	defer frame.Release()

	return script.ExecuteTransport(transportScript.compiled, mutableBufferBytes(&frame), transportScript.ctx, func(outFrame []byte) error {
		out := buffer.MakeWithData(outFrame)
		return engine.packetEndpoint.Write(&out)
	})
}

func mutableBufferBytes(frame *buffer.Buffer) []byte {
	view, ok := frame.PullUp(0, int(frame.Size()))
	if !ok {
		return nil
	}
	return view.AsSlice()
}
