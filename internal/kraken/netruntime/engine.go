package netruntime

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type EngineConfig struct {
	InterfaceName  string
	MAC            net.HardwareAddr
	DefaultGateway net.IP
	Routes         []net.IPNet
	MTU            uint32
}

type Endpoint struct {
	IP net.IP
}

type ARPCacheItem struct {
	IP  string
	MAC string
}

type PingReply struct {
	Sequence uint16
	Success  bool
	RTT      time.Duration
}

type OutboundHandler func(engine *Engine, frame []byte) error

type Engine struct {
	config EngineConfig

	stack  *stack.Stack
	linkEP *DirectLinkEndpoint

	mu       sync.RWMutex
	endpoint *Endpoint
	stateV   atomic.Value
	peerMu   sync.Mutex
	peers    map[compactIPv4]compactMAC
	peersV   atomic.Value
}

func NewEngine(config EngineConfig, outbound OutboundHandler) (*Engine, error) {
	if len(config.MAC) == 0 {
		return nil, fmt.Errorf("adopted engine requires a hardware address")
	}
	if outbound == nil {
		return nil, fmt.Errorf("adopted engine requires an outbound handler")
	}

	engine := &Engine{
		config: CloneEngineConfig(config),
		peers:  make(map[compactIPv4]compactMAC),
	}
	engine.stateV.Store((*Endpoint)(nil))
	engine.peersV.Store(make(map[compactIPv4]compactMAC))
	engine.linkEP = NewDirectLinkEndpoint(adoptedNetstackMTU(config.InterfaceName, config.MTU), tcpip.LinkAddress(config.MAC), func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return engine.emitOutbound(pkts, outbound)
	})

	stackEP := ethernet.New(engine.linkEP)
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

	if err := netstack.CreateNICWithOptions(adoptedNetstackNICID, stackEP, stack.NICOptions{
		Name:               config.InterfaceName,
		DeliverLinkPackets: false,
	}); err != nil {
		return nil, fmt.Errorf("create adopted netstack NIC: %s", err)
	}

	routes, err := buildNetstackRoutes(config.Routes, config.DefaultGateway)
	if err != nil {
		netstack.Close()
		netstack.Wait()
		return nil, err
	}
	netstack.SetRouteTable(routes)

	engine.stack = netstack
	return engine, nil
}

func CloneEngineConfig(config EngineConfig) EngineConfig {
	clonedRoutes := make([]net.IPNet, 0, len(config.Routes))
	for _, route := range config.Routes {
		clonedRoutes = append(clonedRoutes, net.IPNet{
			IP:   common.CloneIPv4(route.IP),
			Mask: append(net.IPMask(nil), route.Mask...),
		})
	}

	return EngineConfig{
		InterfaceName:  config.InterfaceName,
		MAC:            common.CloneHardwareAddr(config.MAC),
		DefaultGateway: common.CloneIPv4(config.DefaultGateway),
		Routes:         clonedRoutes,
		MTU:            config.MTU,
	}
}

func (engine *Engine) AddEndpoint(endpoint Endpoint) error {
	if engine == nil {
		return fmt.Errorf("engine identity is required")
	}

	key := compactIPv4FromIP(endpoint.IP)
	if !key.valid {
		return fmt.Errorf("adopted engine requires a valid IPv4 identity")
	}
	address := tcpip.AddrFrom4Slice(key.addr[:])
	engine.mu.Lock()
	defer engine.mu.Unlock()

	if engine.endpoint != nil {
		existingKey := compactIPv4FromIP(engine.endpoint.IP)
		if existingKey != key {
			return fmt.Errorf("adopted engine already manages %s", engine.endpoint.IP)
		}
		engine.endpoint = cloneEndpointValue(endpoint)
		engine.publishStateLocked()
		return nil
	}

	if err := engine.stack.AddProtocolAddress(adoptedNetstackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: address.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("assign adopted IPv4 address: %s", err)
	}

	engine.endpoint = cloneEndpointValue(endpoint)
	engine.publishStateLocked()
	return nil
}

func (engine *Engine) RemoveEndpoint(ip net.IP) {
	if engine == nil {
		return
	}

	key := compactIPv4FromIP(ip)
	if !key.valid {
		return
	}

	engine.mu.Lock()
	defer engine.mu.Unlock()

	if engine.endpoint == nil || compactIPv4FromIP(engine.endpoint.IP) != key {
		return
	}

	engine.endpoint = nil
	engine.publishStateLocked()
	if normalized := common.NormalizeIPv4(ip); normalized != nil {
		_ = engine.stack.RemoveAddress(adoptedNetstackNICID, tcpip.AddrFrom4Slice(normalized.To4()))
	}
}

func (engine *Engine) EndpointSnapshot() *Endpoint {
	if engine == nil {
		return nil
	}

	state, _ := engine.stateV.Load().(*Endpoint)
	if state != nil {
		return cloneEndpointValue(*state)
	}

	engine.mu.RLock()
	endpoint := engine.endpoint
	engine.mu.RUnlock()
	if endpoint == nil {
		return nil
	}
	return cloneEndpointValue(*endpoint)
}

func (engine *Engine) InjectFrame(frame []byte) {
	if engine == nil || len(frame) == 0 {
		return
	}

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer packet.DecRef()
	engine.linkEP.InjectInbound(0, packet)
}

func (engine *Engine) RememberPeer(ip net.IP, mac net.HardwareAddr) {
	if engine == nil {
		return
	}
	compactIP := compactIPv4FromIP(ip)
	compactHardwareAddr := compactMACFromSlice(mac)
	if !compactIP.valid || !compactHardwareAddr.valid {
		return
	}

	peers, _ := engine.peersV.Load().(map[compactIPv4]compactMAC)
	if peers[compactIP] == compactHardwareAddr {
		return
	}

	engine.peerMu.Lock()
	if engine.peers[compactIP] == compactHardwareAddr {
		engine.peerMu.Unlock()
		return
	}
	engine.peers[compactIP] = compactHardwareAddr
	engine.peersV.Store(maps.Clone(engine.peers))
	engine.peerMu.Unlock()

	_ = engine.stack.AddStaticNeighbor(
		adoptedNetstackNICID,
		ipv4.ProtocolNumber,
		tcpip.AddrFrom4(compactIP.addr),
		tcpip.LinkAddress(compactHardwareAddr.addr[:]),
	)
}

func (engine *Engine) PeerMAC(ip net.IP) (net.HardwareAddr, bool) {
	if engine == nil {
		return nil, false
	}

	key := compactIPv4FromIP(ip)
	if !key.valid {
		return nil, false
	}

	peers, _ := engine.peersV.Load().(map[compactIPv4]compactMAC)
	mac, exists := peers[key]
	if !exists || !mac.valid {
		return nil, false
	}

	return mac.HardwareAddr(), true
}

func (engine *Engine) Close() {
	if engine == nil {
		return
	}

	engine.linkEP.Close()
	engine.stack.Close()
	engine.stack.Wait()
}

func (engine *Engine) MatchesConfig(config EngineConfig) bool {
	if engine == nil {
		return false
	}

	if engine.config.InterfaceName != "" && config.InterfaceName != "" && engine.config.InterfaceName != config.InterfaceName {
		return false
	}
	if engine.config.MTU != 0 && config.MTU != 0 && engine.config.MTU != config.MTU {
		return false
	}
	if !bytes.Equal(engine.config.MAC, config.MAC) {
		return false
	}
	if engine.config.DefaultGateway == nil {
		return true
	}
	gateway := common.NormalizeIPv4(config.DefaultGateway)
	return gateway != nil && bytes.Equal(engine.config.DefaultGateway, gateway)
}

func (engine *Engine) publishStateLocked() {
	engine.stateV.Store(cloneEndpointValue(engine.endpointValue()))
}

func (engine *Engine) endpointValue() Endpoint {
	if engine.endpoint == nil {
		return Endpoint{}
	}
	return *engine.endpoint
}

func (engine *Engine) ARPCacheSnapshot() []ARPCacheItem {
	if engine == nil {
		return nil
	}

	entries, err := engine.stack.Neighbors(adoptedNetstackNICID, ipv4.ProtocolNumber)
	if err != nil {
		return nil
	}

	items := make([]ARPCacheItem, 0, len(entries))
	for _, entry := range entries {
		if entry.Addr.BitLen() != net.IPv4len*8 || entry.LinkAddr == "" {
			continue
		}

		addr := entry.Addr.As4()
		items = append(items, ARPCacheItem{
			IP:  net.IP(addr[:]).String(),
			MAC: net.HardwareAddr(entry.LinkAddr).String(),
		})
	}

	return items
}

func (engine *Engine) Ping(sourceIP, targetIP net.IP, count int, payload []byte, timeout time.Duration) ([]PingReply, error) {
	targetIP = common.NormalizeIPv4(targetIP)
	sourceIP = common.NormalizeIPv4(sourceIP)
	if engine == nil || targetIP == nil || sourceIP == nil {
		return nil, fmt.Errorf("valid IPv4 source and target are required")
	}
	if count <= 0 {
		return nil, fmt.Errorf("ping count must be positive")
	}

	endpoint, wq, _, err := engine.newPingEndpoint(sourceIP, targetIP)
	if err != nil {
		return nil, err
	}
	defer endpoint.Close()

	replies := make([]PingReply, 0, count)
	for sequence := 1; sequence <= count; sequence++ {
		reply := PingReply{
			Sequence: uint16(sequence),
		}

		if err := writeICMPEchoRequest(endpoint, reply.Sequence, payload); err != nil {
			return replies, err
		}

		sentAt := time.Now()
		rtt, ok, err := waitForICMPEchoReply(endpoint, wq, reply.Sequence, sentAt, timeout)
		if err != nil {
			replies = append(replies, reply)
			return replies, err
		}
		reply.Success = ok
		reply.RTT = rtt
		replies = append(replies, reply)
	}

	return replies, nil
}

func (engine *Engine) newPingEndpoint(sourceIP, targetIP net.IP) (tcpip.Endpoint, *waiter.Queue, uint16, error) {
	var wq waiter.Queue

	endpoint, err := engine.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("create ICMP endpoint: %s", err)
	}

	localAddress := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(sourceIP.To4()),
	}
	if err := endpoint.Bind(localAddress); err != nil {
		endpoint.Close()
		return nil, nil, 0, fmt.Errorf("bind ICMP endpoint: %s", err)
	}

	remoteAddress := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(targetIP.To4()),
	}
	if err := endpoint.Connect(remoteAddress); err != nil {
		endpoint.Close()
		return nil, nil, 0, fmt.Errorf("connect ICMP endpoint: %s", err)
	}

	boundAddress, err := endpoint.GetLocalAddress()
	if err != nil {
		endpoint.Close()
		return nil, nil, 0, fmt.Errorf("get ICMP endpoint address: %s", err)
	}

	return endpoint, &wq, boundAddress.Port, nil
}

func (engine *Engine) ListenTCP(ip net.IP, port int) (*gonet.TCPListener, error) {
	ip = common.NormalizeIPv4(ip)
	if engine == nil || ip == nil {
		return nil, fmt.Errorf("service requires a valid IPv4 identity")
	}

	return gonet.ListenTCP(engine.stack, tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
}

func (engine *Engine) DialTCP(ctx context.Context, localIP, remoteIP net.IP, remotePort int) (net.Conn, error) {
	localIP = common.NormalizeIPv4(localIP)
	remoteIP = common.NormalizeIPv4(remoteIP)
	if engine == nil || localIP == nil || remoteIP == nil {
		return nil, fmt.Errorf("dial TCP requires valid IPv4 local and remote addresses")
	}

	local := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(localIP.To4()),
	}
	remote := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(remoteIP.To4()),
		Port: uint16(remotePort),
	}
	return gonet.DialTCPWithBind(ctx, engine.stack, local, remote, ipv4.ProtocolNumber)
}

func (engine *Engine) DialUDP(localIP, remoteIP net.IP, remotePort int) (net.Conn, error) {
	localIP = common.NormalizeIPv4(localIP)
	remoteIP = common.NormalizeIPv4(remoteIP)
	if engine == nil || localIP == nil || remoteIP == nil {
		return nil, fmt.Errorf("dial UDP requires valid IPv4 local and remote addresses")
	}

	local := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(localIP.To4()),
	}
	remote := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(remoteIP.To4()),
		Port: uint16(remotePort),
	}
	return gonet.DialUDP(engine.stack, &local, &remote, ipv4.ProtocolNumber)
}

func (engine *Engine) emitOutbound(pkts stack.PacketBufferList, outbound OutboundHandler) (int, tcpip.Error) {
	sent := 0
	for _, pkt := range pkts.AsSlice() {
		frame := AppendPacketBufferTo(nil, pkt)
		if err := outbound(engine, frame); err != nil {
			if sent == 0 {
				return 0, &tcpip.ErrAborted{}
			}
			return sent, nil
		}
		sent++
	}
	return sent, nil
}

func cloneEndpoint(endpoint *Endpoint) *Endpoint {
	if endpoint == nil || common.NormalizeIPv4(endpoint.IP) == nil {
		return nil
	}
	return cloneEndpointValue(*endpoint)
}

func cloneEndpointValue(endpoint Endpoint) *Endpoint {
	if common.NormalizeIPv4(endpoint.IP) == nil {
		return nil
	}
	return &Endpoint{IP: common.CloneIPv4(endpoint.IP)}
}
