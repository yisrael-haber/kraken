package capture

import (
	"bytes"
	"fmt"
	"maps"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type adoptedEngineConfig struct {
	ifaceName      string
	mac            net.HardwareAddr
	defaultGateway net.IP
	routes         []net.IPNet
	mtu            uint32
}

type adoptedEngineState struct {
	identity           adoption.Identity
	hasTransportScript bool
}

type adoptedEngine struct {
	config adoptedEngineConfig

	stack  *stack.Stack
	linkEP *directLinkEndpoint

	mu                   sync.RWMutex
	identity             adoption.Identity
	stateV               atomic.Value
	peerMu               sync.Mutex
	peers                map[compactIPv4]compactMAC
	peersV               atomic.Value
}

func newAdoptedEngine(config adoptedEngineConfig, outbound func(*adoptedEngine, stack.PacketBufferList) (int, tcpip.Error)) (*adoptedEngine, error) {
	if len(config.mac) == 0 {
		return nil, fmt.Errorf("adopted engine requires a hardware address")
	}
	if outbound == nil {
		return nil, fmt.Errorf("adopted engine requires an outbound handler")
	}

	engine := &adoptedEngine{
		config: cloneAdoptedEngineConfig(config),
		peers:  make(map[compactIPv4]compactMAC),
	}
	engine.stateV.Store(adoptedEngineState{})
	engine.peersV.Store(make(map[compactIPv4]compactMAC))
	engine.linkEP = newDirectLinkEndpoint(adoptedNetstackMTU(config.ifaceName, config.mtu), tcpip.LinkAddress(config.mac), func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return outbound(engine, pkts)
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
		Name:               config.ifaceName,
		DeliverLinkPackets: false,
	}); err != nil {
		return nil, fmt.Errorf("create adopted netstack NIC: %s", err)
	}

	routes, err := buildNetstackRoutes(config.routes, config.defaultGateway)
	if err != nil {
		netstack.Close()
		netstack.Wait()
		return nil, err
	}
	netstack.SetRouteTable(routes)

	engine.stack = netstack
	return engine, nil
}

func adoptedEngineConfigForIdentity(identity adoption.Identity, routes []net.IPNet) adoptedEngineConfig {
	return adoptedEngineConfig{
		ifaceName:      identity.Interface().Name,
		mac:            identity.MAC(),
		defaultGateway: identity.DefaultGateway(),
		routes:         routes,
		mtu:            identity.MTU(),
	}
}

func cloneAdoptedEngineConfig(config adoptedEngineConfig) adoptedEngineConfig {
	clonedRoutes := make([]net.IPNet, 0, len(config.routes))
	for _, route := range config.routes {
		clonedRoutes = append(clonedRoutes, net.IPNet{
			IP:   common.CloneIPv4(route.IP),
			Mask: append(net.IPMask(nil), route.Mask...),
		})
	}

	return adoptedEngineConfig{
		ifaceName:      config.ifaceName,
		mac:            common.CloneHardwareAddr(config.mac),
		defaultGateway: common.CloneIPv4(config.defaultGateway),
		routes:         clonedRoutes,
		mtu:            config.mtu,
	}
}

func (group *adoptedEngine) addIdentity(identity adoption.Identity) error {
	if group == nil || identity == nil {
		return fmt.Errorf("engine identity is required")
	}

	key := compactIPv4FromIP(identity.IP())
	if !key.valid {
		return fmt.Errorf("adopted engine requires a valid IPv4 identity")
	}
	address := tcpip.AddrFrom4Slice(key.addr[:])
	if !group.matchesIdentity(identity) {
		return fmt.Errorf("adopted engine configuration does not match identity %s", identity.IP())
	}

	group.mu.Lock()
	defer group.mu.Unlock()

	if group.identity != nil {
		existingKey := compactIPv4FromIP(group.identity.IP())
		if existingKey != key {
			return fmt.Errorf("adopted engine already manages %s", group.identity.IP())
		}
		group.identity = identity
		group.publishStateLocked()
		return nil
	}

	if err := group.stack.AddProtocolAddress(adoptedNetstackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: address.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("assign adopted IPv4 address: %s", err)
	}

	group.identity = identity
	group.publishStateLocked()
	return nil
}

func (group *adoptedEngine) removeIdentity(ip net.IP) {
	if group == nil {
		return
	}

	key := compactIPv4FromIP(ip)
	if !key.valid {
		return
	}

	group.mu.Lock()
	defer group.mu.Unlock()

	if group.identity == nil || compactIPv4FromIP(group.identity.IP()) != key {
		return
	}

	group.identity = nil
	group.publishStateLocked()
	if normalized := common.NormalizeIPv4(ip); normalized != nil {
		_ = group.stack.RemoveAddress(adoptedNetstackNICID, tcpip.AddrFrom4Slice(normalized.To4()))
	}
}

func (group *adoptedEngine) identitySnapshot() adoption.Identity {
	if group == nil {
		return nil
	}

	state, _ := group.stateV.Load().(adoptedEngineState)
	if state.identity != nil {
		return state.identity
	}

	group.mu.RLock()
	identity := group.identity
	group.mu.RUnlock()
	return identity
}

func (group *adoptedEngine) hasBoundTransportScripts() bool {
	if group == nil {
		return false
	}

	state, _ := group.stateV.Load().(adoptedEngineState)
	return state.hasTransportScript
}

func (group *adoptedEngine) injectFrame(frame []byte) {
	if group == nil || len(frame) == 0 {
		return
	}

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer packet.DecRef()
	group.linkEP.InjectInbound(0, packet)
}

func (group *adoptedEngine) rememberPeer(ip compactIPv4, mac compactMAC) {
	if group == nil || !ip.valid || !mac.valid {
		return
	}

	peers, _ := group.peersV.Load().(map[compactIPv4]compactMAC)
	if peers[ip] == mac {
		return
	}

	group.peerMu.Lock()
	if group.peers[ip] == mac {
		group.peerMu.Unlock()
		return
	}
	group.peers[ip] = mac
	group.peersV.Store(maps.Clone(group.peers))
	group.peerMu.Unlock()

	_ = group.stack.AddStaticNeighbor(
		adoptedNetstackNICID,
		ipv4.ProtocolNumber,
		tcpip.AddrFrom4(ip.addr),
		tcpip.LinkAddress(mac.addr[:]),
	)
}

func (group *adoptedEngine) peerMAC(ip net.IP) (net.HardwareAddr, bool) {
	if group == nil {
		return nil, false
	}

	key := compactIPv4FromIP(ip)
	if !key.valid {
		return nil, false
	}

	peers, _ := group.peersV.Load().(map[compactIPv4]compactMAC)
	mac, exists := peers[key]
	if !exists || !mac.valid {
		return nil, false
	}

	return mac.HardwareAddr(), true
}

func (group *adoptedEngine) close() {
	if group == nil {
		return
	}

	group.linkEP.Close()
	group.stack.Close()
	group.stack.Wait()
}

func (group *adoptedEngine) matchesIdentity(identity adoption.Identity) bool {
	if group == nil || identity == nil {
		return false
	}

	if group.config.ifaceName != "" && group.config.ifaceName != identity.Interface().Name {
		return false
	}
	if group.config.mtu != 0 && group.config.mtu != identity.MTU() {
		return false
	}
	if !bytes.Equal(group.config.mac, identity.MAC()) {
		return false
	}
	if group.config.defaultGateway == nil {
		return true
	}
	return bytes.Equal(common.NormalizeIPv4(group.config.defaultGateway), common.NormalizeIPv4(identity.DefaultGateway()))
}

func (group *adoptedEngine) publishStateLocked() {
	state := adoptedEngineState{identity: group.identity}
	if group.identity != nil {
		state.hasTransportScript = strings.TrimSpace(group.identity.TransportScriptName()) != ""
	}
	group.stateV.Store(state)
}

func (group *adoptedEngine) arpCacheSnapshot() []adoption.ARPCacheItem {
	if group == nil {
		return nil
	}

	entries, err := group.stack.Neighbors(adoptedNetstackNICID, ipv4.ProtocolNumber)
	if err != nil {
		return nil
	}

	items := make([]adoption.ARPCacheItem, 0, len(entries))
	for _, entry := range entries {
		if entry.Addr.BitLen() != net.IPv4len*8 || entry.LinkAddr == "" {
			continue
		}

		addr := entry.Addr.As4()
		items = append(items, adoption.ARPCacheItem{
			IP:        net.IP(addr[:]).String(),
			MAC:       net.HardwareAddr(entry.LinkAddr).String(),
			UpdatedAt: "",
		})
	}

	return items
}

func (group *adoptedEngine) ping(sourceIP, targetIP net.IP, count int, payload []byte, timeout time.Duration) ([]netstackPingReply, error) {
	targetIP = common.NormalizeIPv4(targetIP)
	sourceIP = common.NormalizeIPv4(sourceIP)
	if group == nil || targetIP == nil || sourceIP == nil {
		return nil, fmt.Errorf("valid IPv4 source and target are required")
	}
	if count <= 0 {
		return nil, fmt.Errorf("ping count must be positive")
	}

	endpoint, wq, pingID, err := group.newPingEndpoint(sourceIP, targetIP)
	if err != nil {
		return nil, err
	}
	defer endpoint.Close()

	replies := make([]netstackPingReply, 0, count)
	for sequence := 1; sequence <= count; sequence++ {
		reply := netstackPingReply{
			id:       pingID,
			sequence: uint16(sequence),
		}

		if err := writeICMPEchoRequest(endpoint, reply.sequence, payload); err != nil {
			return replies, err
		}

		sentAt := time.Now()
		rtt, ok, err := waitForICMPEchoReply(endpoint, wq, reply.sequence, sentAt, timeout)
		if err != nil {
			replies = append(replies, reply)
			return replies, err
		}
		reply.success = ok
		reply.rtt = rtt
		replies = append(replies, reply)
	}

	return replies, nil
}

func (group *adoptedEngine) newPingEndpoint(sourceIP, targetIP net.IP) (tcpip.Endpoint, *waiter.Queue, uint16, error) {
	var wq waiter.Queue

	endpoint, err := group.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
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
