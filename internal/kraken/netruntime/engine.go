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
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
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
	Write([]byte) error
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
	ipMTU           atomic.Uint32
	packetEndpoint  PacketEndpoint
	scriptIdentity  script.ExecutionIdentity
	scriptMu        sync.RWMutex
	transportScript transportScript
}

func NewEngine(config EngineConfig) (engine *Engine, err error) {
	address := tcpip.AddrFrom4Slice(config.IP)
	defaultGateway := ""
	if config.DefaultGateway != nil {
		defaultGateway = config.DefaultGateway.String()
	}

	engine = &Engine{
		address:        address,
		linkAddr:       tcpip.LinkAddress(config.MAC),
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
	engine.ipMTU.Store(config.MTU)
	engine.scriptIdentity.SocketIdentity = engine
	stackEP := ethernet.New(engine)
	netstack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			arp.NewProtocol,
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			icmp.NewProtocol4,
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	defer func() {
		if err != nil {
			netstack.Destroy()
		}
	}()

	if err := netstack.CreateNICWithOptions(adoptedNetstackNICID, stackEP, stack.NICOptions{
		Name:               config.InterfaceName,
		DeliverLinkPackets: false,
	}); err != nil {
		return nil, fmt.Errorf("create adopted netstack NIC: %s", err)
	}
	if err := netstack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
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
		return nil, fmt.Errorf("assign adopted IPv4 address: %s", err)
	}

	engine.stack = netstack
	return engine, nil
}

func (engine *Engine) InjectFrame(frame buffer.Buffer) {
	dispatcher := engine.dispatcher.Load()
	if engine.closed.Load() || dispatcher == nil {
		frame.Release()
		return
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: frame,
	})
	defer packet.DecRef()
	(*dispatcher).DeliverNetworkPacket(0, packet)
}

func (engine *Engine) Shutdown() {
	if engine.closed.Swap(true) {
		return
	}
	engine.stack.Destroy()
}

func (engine *Engine) MTU() uint32 { return engine.ipMTU.Load() + header.EthernetMinimumSize }

func (engine *Engine) SetMTU(mtu uint32) {
	engine.ipMTU.Store(mtu)
	engine.scriptMu.Lock()
	engine.scriptIdentity.MTU = int(mtu)
	engine.transportScript = engine.newTransportScript(engine.transportScript.compiled)
	engine.scriptMu.Unlock()
}

func (*Engine) MaxHeaderLength() uint16 { return 0 }

func (engine *Engine) LinkAddress() tcpip.LinkAddress { return engine.linkAddr }

func (*Engine) SetLinkAddress(tcpip.LinkAddress) {}

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

func (engine *Engine) Close() { engine.closed.Store(true) }

func (*Engine) SetOnCloseAction(func()) {}

func (engine *Engine) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if engine.closed.Load() {
		return 0, &tcpip.ErrClosedForSend{}
	}
	packets := pkts.AsSlice()
	for index, pkt := range packets {
		if err := engine.emitFrame(pkt.ToBuffer()); err != nil {
			if index == 0 {
				return 0, &tcpip.ErrAborted{}
			}
			return index, nil
		}
	}
	return len(packets), nil
}

func (engine *Engine) UpdateTransportScript(compiled *script.CompiledScript) {
	engine.scriptMu.Lock()
	engine.transportScript = engine.newTransportScript(compiled)
	engine.scriptMu.Unlock()
}

func (engine *Engine) newTransportScript(compiled *script.CompiledScript) transportScript {
	if compiled == nil {
		return transportScript{}
	}
	return transportScript{
		compiled: compiled,
		ctx: script.PrepareTransportContext(script.ExecutionContext{
			ScriptName: compiled.Name(),
			Adopted:    engine.scriptIdentity,
			Identities: []script.ExecutionIdentity{engine.scriptIdentity},
			Metadata:   map[string]string{"direction": "outbound", "handler": "transport"},
		}),
	}
}

func (engine *Engine) ScriptName() string {
	engine.scriptMu.RLock()
	compiled := engine.transportScript.compiled
	engine.scriptMu.RUnlock()
	if compiled == nil {
		return ""
	}
	return compiled.Name()
}

func (engine *Engine) ScriptIdentity() script.ExecutionIdentity {
	engine.scriptMu.RLock()
	defer engine.scriptMu.RUnlock()
	return engine.scriptIdentity
}

func (engine *Engine) ListenTCP(port int) (net.Listener, error) {
	addr := engine.localAddress(uint16(port))
	var wq waiter.Queue
	ep, err := engine.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, fmt.Errorf("%s", err.String())
	}

	ep.SocketOptions().SetReuseAddress(true)
	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, socketOpError("bind", "tcp", fullTCPAddr(addr), err)
	}

	if err := ep.Listen(listenBacklog); err != nil {
		ep.Close()
		return nil, socketOpError("listen", "tcp", fullTCPAddr(addr), err)
	}

	return gonet.NewTCPListener(engine.stack, &wq, ep), nil
}

func fullTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IP(addr.Addr.AsSlice()),
		Port: int(addr.Port),
	}
}

func fullUDPAddr(addr tcpip.FullAddress) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(addr.Addr.AsSlice()),
		Port: int(addr.Port),
	}
}

func socketOpError(op, network string, addr net.Addr, err tcpip.Error) error {
	return &net.OpError{Op: op, Net: network, Addr: addr, Err: fmt.Errorf("%s", err.String())}
}

func (engine *Engine) localAddress(port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: engine.address,
		Port: port,
	}
}

func remoteAddress(ip net.IP, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(ip),
		Port: port,
	}
}

func (engine *Engine) DialTCP(ctx context.Context, remoteIP net.IP, remotePort int) (net.Conn, error) {
	return gonet.DialTCPWithBind(ctx, engine.stack, engine.localAddress(0), remoteAddress(remoteIP, uint16(remotePort)), ipv4.ProtocolNumber)
}

func (engine *Engine) DialScriptTCP(ctx context.Context, remoteIP net.IP, remotePort int, options script.SocketOptions) (net.Conn, error) {
	local := engine.localAddress(0)
	remote := remoteAddress(remoteIP, uint16(remotePort))
	ep, wq, err := engine.newScriptSocketEndpoint(tcp.ProtocolNumber, true, options)
	if err != nil {
		return nil, err
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		ep.Close()
		return nil, ctx.Err()
	default:
	}

	if bindErr := ep.Bind(local); bindErr != nil {
		ep.Close()
		return nil, socketOpError("bind", "tcp", fullTCPAddr(local), bindErr)
	}

	connectErr := ep.Connect(remote)
	if _, ok := connectErr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}
		connectErr = ep.LastError()
	}
	if connectErr != nil {
		ep.Close()
		return nil, socketOpError("connect", "tcp", fullTCPAddr(remote), connectErr)
	}

	return &scriptSocketConn{Conn: gonet.NewTCPConn(wq, ep), ep: ep, tcp: true}, nil
}

func (engine *Engine) DialUDP(remoteIP net.IP, remotePort int) (net.Conn, error) {
	local := engine.localAddress(0)
	remote := remoteAddress(remoteIP, uint16(remotePort))
	return gonet.DialUDP(engine.stack, &local, &remote, ipv4.ProtocolNumber)
}

func (engine *Engine) OpenICMPv4(remoteIP net.IP, identifier uint16) (net.Conn, error) {
	var wq waiter.Queue
	ep, err := engine.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, fmt.Errorf("create ICMP endpoint: %s", err.String())
	}
	local := engine.localAddress(identifier)
	if err := ep.Bind(local); err != nil {
		ep.Close()
		return nil, fmt.Errorf("bind ICMP endpoint: %s", err.String())
	}
	remote := remoteAddress(remoteIP, 0)
	if err := ep.Connect(remote); err != nil {
		ep.Close()
		return nil, fmt.Errorf("connect ICMP endpoint: %s", err.String())
	}
	return gonet.NewUDPConn(&wq, ep), nil
}

func (engine *Engine) DialScriptUDP(remoteIP net.IP, remotePort int, options script.SocketOptions) (net.Conn, error) {
	local := engine.localAddress(0)
	remote := remoteAddress(remoteIP, uint16(remotePort))
	ep, wq, err := engine.newScriptSocketEndpoint(udp.ProtocolNumber, false, options)
	if err != nil {
		return nil, err
	}
	if bindErr := ep.Bind(local); bindErr != nil {
		ep.Close()
		return nil, socketOpError("bind", "udp", fullUDPAddr(local), bindErr)
	}
	if connectErr := ep.Connect(remote); connectErr != nil {
		ep.Close()
		return nil, socketOpError("connect", "udp", fullUDPAddr(remote), connectErr)
	}
	return &scriptSocketConn{Conn: gonet.NewUDPConn(wq, ep), ep: ep}, nil
}

func (engine *Engine) newScriptSocketEndpoint(protocol tcpip.TransportProtocolNumber, tcp bool, options script.SocketOptions) (tcpip.Endpoint, *waiter.Queue, error) {
	wq := new(waiter.Queue)
	ep, err := engine.stack.NewEndpoint(protocol, ipv4.ProtocolNumber, wq)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", err.String())
	}
	if err := applyScriptSocketOptions(ep, tcp, options); err != nil {
		ep.Close()
		return nil, nil, err
	}
	return ep, wq, nil
}

type scriptSocketConn struct {
	net.Conn
	ep  tcpip.Endpoint
	tcp bool
}

func (conn *scriptSocketConn) SetScriptSocketOptions(options script.SocketOptions) error {
	return applyScriptSocketOptions(conn.ep, conn.tcp, options)
}

func applyScriptSocketOptions(ep tcpip.Endpoint, tcp bool, options script.SocketOptions) error {
	if !tcp {
		if options.KeepAlive != nil {
			return fmt.Errorf("socket option keepalive requires TCP")
		}
		if options.NoDelay != nil {
			return fmt.Errorf("socket option nodelay requires TCP")
		}
	}
	socketOptions := ep.SocketOptions()
	if options.ReuseAddr != nil {
		socketOptions.SetReuseAddress(*options.ReuseAddr)
	}
	if options.KeepAlive != nil {
		socketOptions.SetKeepAlive(*options.KeepAlive)
	}
	if options.NoDelay != nil {
		socketOptions.SetDelayOption(!*options.NoDelay)
	}
	if options.RecvBuffer != nil {
		socketOptions.SetReceiveBufferSize(int64(*options.RecvBuffer), true)
	}
	if options.SendBuffer != nil {
		socketOptions.SetSendBufferSize(int64(*options.SendBuffer), true)
	}
	if options.TTL != nil {
		if err := ep.SetSockOptInt(tcpip.IPv4TTLOption, *options.TTL); err != nil {
			return fmt.Errorf("set socket option ttl: %s", err.String())
		}
	}
	return nil
}

func (engine *Engine) emitFrame(frame buffer.Buffer) error {
	engine.scriptMu.RLock()
	transportScript := engine.transportScript
	engine.scriptMu.RUnlock()
	defer frame.Release()
	if transportScript.compiled == nil {
		views := frame.AsViewList()
		view := views.Front()
		if view != nil && view.Next() == nil {
			return engine.packetEndpoint.Write(view.AsSlice())
		}
		return engine.packetEndpoint.Write(frame.Flatten())
	}
	view, _ := frame.PullUp(0, int(frame.Size()))

	return script.ExecuteTransport(transportScript.compiled, view.AsSlice(), transportScript.ctx, func(outFrame []byte) error {
		return engine.packetEndpoint.Write(outFrame)
	})
}
