package capture

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type adoptedEngineGroupConfig struct {
	ifaceName      string
	mac            net.HardwareAddr
	defaultGateway net.IP
	routes         []net.IPNet
	mtu            uint32
}

type adoptedEngineKey struct {
	value string
}

type adoptedEngineGroup struct {
	key    adoptedEngineKey
	config adoptedEngineGroupConfig

	stack  *stack.Stack
	linkEP *directLinkEndpoint

	mu                   sync.RWMutex
	identities           map[compactIPv4]adoption.Identity
	identitiesV          atomic.Value
	scriptedIdentity     atomic.Int32
	managedHTTPPorts     map[uint16]int
	managedHTTPPortsV    atomic.Value
	managedHTTPPortCount atomic.Int32
	peerMu               sync.Mutex
	peers                map[compactIPv4]compactMAC
	peersV               atomic.Value
}

func newAdoptedEngineKey(identity adoption.Identity, routes []net.IPNet) adoptedEngineKey {
	parts := make([]string, 0, 2+len(routes))
	parts = append(parts, strings.ToLower(common.CloneHardwareAddr(identity.MAC()).String()))
	parts = append(parts, common.IPString(identity.DefaultGateway()))
	parts = append(parts, fmt.Sprintf("mtu=%d", identity.MTU()))

	routeParts := make([]string, 0, len(routes))
	for _, route := range routes {
		ip := common.NormalizeIPv4(route.IP)
		if ip == nil {
			continue
		}
		ones, _ := route.Mask.Size()
		routeParts = append(routeParts, fmt.Sprintf("%s/%d", ip.Mask(route.Mask).String(), ones))
	}
	sort.Strings(routeParts)
	parts = append(parts, routeParts...)

	return adoptedEngineKey{
		value: strings.Join(parts, "|"),
	}
}

func newAdoptedEngineGroup(config adoptedEngineGroupConfig, outbound func(*adoptedEngineGroup, stack.PacketBufferList) (int, tcpip.Error)) (*adoptedEngineGroup, error) {
	if len(config.mac) == 0 {
		return nil, fmt.Errorf("engine group requires a hardware address")
	}
	if outbound == nil {
		return nil, fmt.Errorf("engine group requires an outbound handler")
	}

	group := &adoptedEngineGroup{
		config:           cloneAdoptedEngineGroupConfig(config),
		identities:       make(map[compactIPv4]adoption.Identity),
		managedHTTPPorts: make(map[uint16]int),
		peers:            make(map[compactIPv4]compactMAC),
	}
	group.identitiesV.Store(make(map[compactIPv4]adoption.Identity))
	group.managedHTTPPortsV.Store(make(map[uint16]int))
	group.peersV.Store(make(map[compactIPv4]compactMAC))
	group.linkEP = newDirectLinkEndpoint(adoptedNetstackMTU(config.ifaceName, config.mtu), tcpip.LinkAddress(config.mac), func(pkts stack.PacketBufferList) (int, tcpip.Error) {
		return outbound(group, pkts)
	})

	stackEP := ethernet.New(group.linkEP)
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
		RawFactory:               raw.EndpointFactory{},
		AllowPacketEndpointWrite: true,
	})

	if err := netstack.CreateNICWithOptions(adoptedNetstackNICID, stackEP, stack.NICOptions{
		Name:               config.ifaceName,
		DeliverLinkPackets: true,
	}); err != nil {
		return nil, fmt.Errorf("create grouped netstack NIC: %s", err)
	}

	routes, err := buildNetstackRoutes(config.routes, config.defaultGateway)
	if err != nil {
		netstack.Close()
		netstack.Wait()
		return nil, err
	}
	netstack.SetRouteTable(routes)

	group.stack = netstack
	return group, nil
}

func cloneAdoptedEngineGroupConfig(config adoptedEngineGroupConfig) adoptedEngineGroupConfig {
	clonedRoutes := make([]net.IPNet, 0, len(config.routes))
	for _, route := range config.routes {
		clonedRoutes = append(clonedRoutes, net.IPNet{
			IP:   common.CloneIPv4(route.IP),
			Mask: append(net.IPMask(nil), route.Mask...),
		})
	}

	return adoptedEngineGroupConfig{
		ifaceName:      config.ifaceName,
		mac:            common.CloneHardwareAddr(config.mac),
		defaultGateway: common.CloneIPv4(config.defaultGateway),
		routes:         clonedRoutes,
		mtu:            config.mtu,
	}
}

func (group *adoptedEngineGroup) addIdentity(identity adoption.Identity) error {
	if group == nil || identity == nil {
		return fmt.Errorf("group identity is required")
	}

	key := compactIPv4FromIP(identity.IP())
	if !key.valid {
		return fmt.Errorf("engine group requires a valid IPv4 identity")
	}
	address := tcpip.AddrFrom4Slice(key.addr[:])

	group.mu.Lock()
	defer group.mu.Unlock()

	if existing, exists := group.identities[key]; exists {
		previouslyScripted := strings.TrimSpace(existing.ScriptName()) != ""
		nextScripted := strings.TrimSpace(identity.ScriptName()) != ""
		group.identities[key] = identity
		if previouslyScripted != nextScripted {
			if nextScripted {
				group.scriptedIdentity.Add(1)
			} else {
				group.scriptedIdentity.Add(-1)
			}
		}
		group.publishIdentitySnapshotLocked()
		return nil
	}

	if err := group.stack.AddProtocolAddress(adoptedNetstackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: address.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("assign grouped adopted IPv4 address: %s", err)
	}

	group.identities[key] = identity
	if strings.TrimSpace(identity.ScriptName()) != "" {
		group.scriptedIdentity.Add(1)
	}
	group.publishIdentitySnapshotLocked()
	return nil
}

func (group *adoptedEngineGroup) removeIdentity(ip net.IP) {
	if group == nil {
		return
	}

	key := compactIPv4FromIP(ip)
	if !key.valid {
		return
	}

	group.mu.Lock()
	defer group.mu.Unlock()

	identity, exists := group.identities[key]
	if !exists {
		return
	}

	delete(group.identities, key)
	if strings.TrimSpace(identity.ScriptName()) != "" {
		group.scriptedIdentity.Add(-1)
	}
	group.publishIdentitySnapshotLocked()
	if normalized := common.NormalizeIPv4(ip); normalized != nil {
		_ = group.stack.RemoveAddress(adoptedNetstackNICID, tcpip.AddrFrom4Slice(normalized.To4()))
	}
}

func (group *adoptedEngineGroup) empty() bool {
	if group == nil {
		return true
	}

	identities, _ := group.identitiesV.Load().(map[compactIPv4]adoption.Identity)
	return len(identities) == 0
}

func (group *adoptedEngineGroup) identityForKey(key compactIPv4) (adoption.Identity, bool) {
	if group == nil || !key.valid {
		return nil, false
	}

	identities, _ := group.identitiesV.Load().(map[compactIPv4]adoption.Identity)
	if identities == nil {
		group.mu.RLock()
		identity, exists := group.identities[key]
		group.mu.RUnlock()
		return identity, exists
	}
	identity, exists := identities[key]
	return identity, exists
}

func (group *adoptedEngineGroup) identityForSourceAddress(address tcpip.Address, packet *stack.PacketBuffer) (adoption.Identity, bool) {
	if group == nil {
		return nil, false
	}

	if address.BitLen() == net.IPv4len*8 {
		if identity, exists := group.identityForKey(compactIPv4FromSlice(address.AsSlice())); exists {
			return identity, true
		}
	}

	if packet == nil {
		return nil, false
	}

	switch packet.NetworkProtocolNumber {
	case arp.ProtocolNumber:
		network := packet.NetworkHeader().Slice()
		if len(network) < header.ARPSize {
			return nil, false
		}

		arpPacket := header.ARP(network)
		if !arpPacket.IsValid() {
			return nil, false
		}

		if identity, exists := group.identityForKey(compactIPv4FromSlice(arpPacket.ProtocolAddressSender())); exists {
			return identity, true
		}
		return nil, false

	case ipv4.ProtocolNumber:
		network := packet.NetworkHeader().Slice()
		if len(network) == 0 {
			return nil, false
		}

		ipv4Header := header.IPv4(network)
		if !ipv4Header.IsValid(len(network)) {
			return nil, false
		}

		sourceAddress := ipv4Header.SourceAddress()
		if identity, exists := group.identityForKey(compactIPv4FromSlice(sourceAddress.AsSlice())); exists {
			return identity, true
		}
		return nil, false
	}

	return nil, false
}

func (group *adoptedEngineGroup) hasBoundScripts() bool {
	if group == nil {
		return false
	}

	return group.scriptedIdentity.Load() > 0
}

func (group *adoptedEngineGroup) injectFrame(frame []byte) {
	if group == nil || len(frame) == 0 {
		return
	}

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer packet.DecRef()

	group.linkEP.InjectInbound(0, packet)
}

func (group *adoptedEngineGroup) registerManagedHTTPPort(port uint16) {
	if group == nil || port == 0 {
		return
	}

	group.mu.Lock()
	count := group.managedHTTPPorts[port]
	group.managedHTTPPorts[port] = count + 1
	if count == 0 {
		group.managedHTTPPortCount.Add(1)
	}
	group.publishManagedHTTPPortsSnapshotLocked()
	group.mu.Unlock()
}

func (group *adoptedEngineGroup) unregisterManagedHTTPPort(port uint16) {
	if group == nil || port == 0 {
		return
	}

	group.mu.Lock()
	defer group.mu.Unlock()

	count := group.managedHTTPPorts[port]
	if count <= 1 {
		delete(group.managedHTTPPorts, port)
		if count == 1 {
			group.managedHTTPPortCount.Add(-1)
		}
		group.publishManagedHTTPPortsSnapshotLocked()
		return
	}
	group.managedHTTPPorts[port] = count - 1
	group.publishManagedHTTPPortsSnapshotLocked()
}

func (group *adoptedEngineGroup) isManagedHTTPPacket(packet *stack.PacketBuffer) bool {
	if group == nil || group.managedHTTPPortCount.Load() == 0 || packet == nil || packet.TransportProtocolNumber != tcp.ProtocolNumber {
		return false
	}

	transport := packet.TransportHeader().Slice()
	if len(transport) < header.TCPMinimumSize {
		return false
	}

	sourcePort := header.TCP(transport).SourcePort()
	ports, _ := group.managedHTTPPortsV.Load().(map[uint16]int)
	return ports[sourcePort] > 0
}

func (group *adoptedEngineGroup) rememberPeer(ip compactIPv4, mac compactMAC) {
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
	group.peersV.Store(clonePeerSnapshot(group.peers))
	group.peerMu.Unlock()

	_ = group.stack.AddStaticNeighbor(
		adoptedNetstackNICID,
		ipv4.ProtocolNumber,
		tcpip.AddrFrom4(ip.addr),
		tcpip.LinkAddress(mac.addr[:]),
	)
}

func (group *adoptedEngineGroup) peerMAC(ip net.IP) (net.HardwareAddr, bool) {
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

func (group *adoptedEngineGroup) close() {
	if group == nil {
		return
	}

	group.linkEP.Close()
	group.stack.Close()
	group.stack.Wait()
}

func (group *adoptedEngineGroup) publishIdentitySnapshotLocked() {
	group.identitiesV.Store(cloneIdentitySnapshot(group.identities))
}

func (group *adoptedEngineGroup) publishManagedHTTPPortsSnapshotLocked() {
	group.managedHTTPPortsV.Store(cloneManagedHTTPPortSnapshot(group.managedHTTPPorts))
}

func cloneIdentitySnapshot(items map[compactIPv4]adoption.Identity) map[compactIPv4]adoption.Identity {
	cloned := make(map[compactIPv4]adoption.Identity, len(items))
	for key, value := range items {
		cloned[key] = value
	}
	return cloned
}

func groupIdentitySnapshot(group *adoptedEngineGroup) []adoption.Identity {
	if group == nil {
		return nil
	}

	identities, _ := group.identitiesV.Load().(map[compactIPv4]adoption.Identity)
	if identities == nil {
		group.mu.RLock()
		defer group.mu.RUnlock()
		identities = group.identities
	}

	items := make([]adoption.Identity, 0, len(identities))
	for _, identity := range identities {
		if identity != nil {
			items = append(items, identity)
		}
	}
	return items
}

func cloneManagedHTTPPortSnapshot(items map[uint16]int) map[uint16]int {
	cloned := make(map[uint16]int, len(items))
	for key, value := range items {
		cloned[key] = value
	}
	return cloned
}

func clonePeerSnapshot(items map[compactIPv4]compactMAC) map[compactIPv4]compactMAC {
	cloned := make(map[compactIPv4]compactMAC, len(items))
	for key, value := range items {
		cloned[key] = value
	}
	return cloned
}

func (group *adoptedEngineGroup) arpCacheSnapshot() []adoption.ARPCacheItem {
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

func (group *adoptedEngineGroup) ping(sourceIP, targetIP net.IP, count int, payload []byte, timeout time.Duration) ([]netstackPingReply, error) {
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

func (group *adoptedEngineGroup) newPingEndpoint(sourceIP, targetIP net.IP) (tcpip.Endpoint, *waiter.Queue, uint16, error) {
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
