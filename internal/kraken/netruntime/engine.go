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
)

type EngineConfig struct {
	IP                net.IP
	Label             string
	InterfaceName     string
	MAC               net.HardwareAddr
	SubnetMask        net.IPMask
	DefaultGateway    net.IP
	MTU               uint32
	TransportScript   *script.CompiledScript
	ApplicationScript *script.CompiledScript
	PacketEndpoint    PacketEndpoint
}

type PacketEndpoint interface {
	Close()
	PacketIO() *InterfacePacketIO
}

type transportScript struct {
	compiled *script.CompiledScript
	ctx      script.ExecutionContext
}

type Engine struct {
	dispatcher        atomic.Pointer[stack.NetworkDispatcher]
	closed            atomic.Bool
	stack             *stack.Stack
	address           tcpip.Address
	linkAddr          tcpip.LinkAddress
	mtu               uint32
	packetIO          *InterfacePacketIO
	packetEndpoint    PacketEndpoint
	scriptIdentity    script.ExecutionIdentity
	scriptMu          sync.RWMutex
	transportScript   transportScript
	applicationScript *script.CompiledScript
}

func NewEngine(config EngineConfig) (*Engine, error) {
	ip := config.IP.To4()
	address := tcpip.AddrFrom4Slice(ip)

	engine := &Engine{
		address:        address,
		linkAddr:       tcpip.LinkAddress(config.MAC),
		mtu:            config.MTU,
		packetIO:       config.PacketEndpoint.PacketIO(),
		packetEndpoint: config.PacketEndpoint,
		scriptIdentity: buildExecutionIdentity(config),
	}
	engine.UpdateTransportScript(config.TransportScript)
	engine.UpdateApplicationScript(config.ApplicationScript)

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

	netstack.SetRouteTable(buildNetstackRoutes(ip, config.SubnetMask, config.DefaultGateway))
	if err := netstack.AddProtocolAddress(adoptedNetstackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: address.WithPrefix(),
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
	engine.packetEndpoint.Close()
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

func (engine *Engine) UpdateApplicationScript(compiled *script.CompiledScript) {
	engine.scriptMu.Lock()
	engine.applicationScript = compiled
	engine.scriptMu.Unlock()
}

func (engine *Engine) TransportScriptName() string {
	engine.scriptMu.RLock()
	name := engine.transportScript.compiled.Name()
	engine.scriptMu.RUnlock()
	return name
}

func (engine *Engine) ApplicationScriptName() string {
	engine.scriptMu.RLock()
	name := engine.applicationScript.Name()
	engine.scriptMu.RUnlock()
	return name
}

func (engine *Engine) ListenTCP(port int) (net.Listener, error) {
	return gonet.ListenTCP(engine.stack, tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: engine.address,
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
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
		return engine.packetIO.Write(&frame)
	}
	defer frame.Release()

	outFrame, err := script.ExecuteTransport(transportScript.compiled, mutableBufferBytes(&frame), transportScript.ctx, nil)
	if err != nil {
		return err
	}

	out := buffer.MakeWithData(outFrame)
	return engine.packetIO.Write(&out)
}

func mutableBufferBytes(frame *buffer.Buffer) []byte {
	view, ok := frame.PullUp(0, int(frame.Size()))
	if !ok {
		return nil
	}
	return view.AsSlice()
}

func buildExecutionIdentity(config EngineConfig) script.ExecutionIdentity {
	return script.ExecutionIdentity{
		Label:          config.Label,
		IP:             config.IP.String(),
		MAC:            config.MAC.String(),
		InterfaceName:  config.InterfaceName,
		DefaultGateway: ipString(config.DefaultGateway),
		MTU:            int(config.MTU),
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
