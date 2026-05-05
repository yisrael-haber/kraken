package netruntime

import (
	"context"
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type EngineConfig struct {
	IP             net.IP
	InterfaceName  string
	MAC            net.HardwareAddr
	DefaultGateway net.IP
	Routes         []net.IPNet
	MTU            uint32
}

type OutboundHandler func(frame buffer.Buffer) error

type Engine struct {
	stack   *stack.Stack
	linkEP  *directLinkEndpoint
	address tcpip.Address
}

func NewEngine(config EngineConfig, outbound OutboundHandler) (*Engine, error) {
	if len(config.MAC) == 0 {
		return nil, fmt.Errorf("adopted engine requires a hardware address")
	}
	if outbound == nil {
		return nil, fmt.Errorf("adopted engine requires an outbound handler")
	}
	ip := config.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("adopted engine requires a valid IPv4 identity")
	}
	address := tcpip.AddrFrom4Slice(ip)

	engine := &Engine{address: address}
	engine.linkEP = newDirectLinkEndpoint(adoptedNetstackMTU(config.MTU), tcpip.LinkAddress(config.MAC), func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return engine.emitOutbound(pkts, outbound)
	})

	stackEP := ethernet.New(engine.linkEP)
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

	netstack.SetRouteTable(buildNetstackRoutes(config.Routes, config.DefaultGateway))
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
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: frame,
	})
	defer packet.DecRef()
	engine.linkEP.InjectInbound(0, packet)
}

func (engine *Engine) Close() {
	engine.linkEP.Close()
	engine.stack.Close()
	engine.stack.Wait()
}

func (engine *Engine) ListenTCP(port int) (*gonet.TCPListener, error) {
	return gonet.ListenTCP(engine.stack, tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: engine.address,
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
}

func (engine *Engine) DialTCP(ctx context.Context, remoteIP net.IP, remotePort int) (net.Conn, error) {
	remoteIP = remoteIP.To4()
	if remoteIP == nil {
		return nil, fmt.Errorf("dial TCP requires a valid IPv4 remote address")
	}

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
	if remoteIP == nil {
		return nil, fmt.Errorf("dial UDP requires a valid IPv4 remote address")
	}

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

func (engine *Engine) emitOutbound(pkts stack.PacketBufferList, outbound OutboundHandler) (int, tcpip.Error) {
	sent := 0
	for _, pkt := range pkts.AsSlice() {
		if err := outbound(pkt.ToBuffer()); err != nil {
			if sent == 0 {
				return 0, &tcpip.ErrAborted{}
			}
			return sent, nil
		}
		sent++
	}
	return sent, nil
}
