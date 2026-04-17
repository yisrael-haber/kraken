package capture

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
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
}

type adoptedEngineKey struct {
	value string
}

type adoptedEngineGroup struct {
	key    adoptedEngineKey
	config adoptedEngineGroupConfig

	stack  *stack.Stack
	linkEP *directLinkEndpoint

	mu               sync.RWMutex
	identities       map[compactIPv4]adoption.Identity
	scriptedIdentity int
}

func newAdoptedEngineKey(identity adoption.Identity, routes []net.IPNet) adoptedEngineKey {
	parts := make([]string, 0, 2+len(routes))
	parts = append(parts, strings.ToLower(common.CloneHardwareAddr(identity.MAC()).String()))
	parts = append(parts, common.IPString(identity.DefaultGateway()))

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
		config:     cloneAdoptedEngineGroupConfig(config),
		identities: make(map[compactIPv4]adoption.Identity),
	}
	group.linkEP = newDirectLinkEndpoint(adoptedNetstackMTU(config.ifaceName), tcpip.LinkAddress(config.mac), func(pkts stack.PacketBufferList) (int, tcpip.Error) {
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
		if strings.TrimSpace(existing.ScriptName()) != "" {
			group.scriptedIdentity--
		}
		group.identities[key] = identity
		if strings.TrimSpace(identity.ScriptName()) != "" {
			group.scriptedIdentity++
		}
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
		group.scriptedIdentity++
	}
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
		group.scriptedIdentity--
	}
	if normalized := common.NormalizeIPv4(ip); normalized != nil {
		_ = group.stack.RemoveAddress(adoptedNetstackNICID, tcpip.AddrFrom4Slice(normalized.To4()))
	}
}

func (group *adoptedEngineGroup) empty() bool {
	if group == nil {
		return true
	}

	group.mu.RLock()
	defer group.mu.RUnlock()
	return len(group.identities) == 0
}

func (group *adoptedEngineGroup) identityForKey(key compactIPv4) (adoption.Identity, bool) {
	if group == nil || !key.valid {
		return nil, false
	}

	group.mu.RLock()
	defer group.mu.RUnlock()
	identity, exists := group.identities[key]
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

	group.mu.RLock()
	defer group.mu.RUnlock()
	return group.scriptedIdentity > 0
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

func (group *adoptedEngineGroup) rememberPeer(ip compactIPv4, mac compactMAC) {
	if group == nil || !ip.valid || !mac.valid {
		return
	}

	_ = group.stack.AddStaticNeighbor(
		adoptedNetstackNICID,
		ipv4.ProtocolNumber,
		tcpip.AddrFrom4(ip.addr),
		tcpip.LinkAddress(mac.addr[:]),
	)
}

func (group *adoptedEngineGroup) close() {
	if group == nil {
		return
	}

	group.linkEP.Close()
	group.stack.Close()
	group.stack.Wait()
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
