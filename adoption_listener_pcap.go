package main

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	adoptionListenerReadTimeout = 50 * time.Millisecond
	arpCacheTTL                 = 5 * time.Minute
	arpResolveTimeout           = 3 * time.Second
	pingReplyTimeout            = 3 * time.Second
)

type arpCacheEntry struct {
	mac     net.HardwareAddr
	updated time.Time
}

type arpCache struct {
	mu      sync.RWMutex
	entries map[string]arpCacheEntry
}

type pingReply struct {
	receivedAt time.Time
}

type pingWaiterKey struct {
	id       uint16
	sequence uint16
}

type pcapAdoptionListener struct {
	handle          *pcap.Handle
	lookup          adoptionLookup
	resolveOverride packetOverrideLookup
	cache           *arpCache

	mu          sync.Mutex
	arpWaiters  map[string][]chan net.HardwareAddr
	pingWaiters map[pingWaiterKey]chan pingReply
	nextPingID  uint16

	writeMu   sync.Mutex
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newAdoptionListener(iface net.Interface, lookup adoptionLookup, resolveOverride packetOverrideLookup) (adoptionListener, error) {
	deviceName, err := pcapDeviceNameForInterface(iface)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(deviceName, 65535, true, adoptionListenerReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("open adoption listener on %s: %w", iface.Name, err)
	}

	if err := handle.SetBPFFilter("arp or icmp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set adoption capture filter on %s: %w", iface.Name, err)
	}

	listener := &pcapAdoptionListener{
		handle:          handle,
		lookup:          lookup,
		resolveOverride: resolveOverride,
		cache:           newARPCache(),
		arpWaiters:      make(map[string][]chan net.HardwareAddr),
		pingWaiters:     make(map[pingWaiterKey]chan pingReply),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}

	go listener.run()

	return listener, nil
}

func newARPCache() *arpCache {
	return &arpCache{
		entries: make(map[string]arpCacheEntry),
	}
}

func (cache *arpCache) lookup(ip net.IP) (net.HardwareAddr, bool) {
	normalized := normalizeIPv4(ip)
	if normalized == nil {
		return nil, false
	}

	cache.mu.RLock()
	entry, exists := cache.entries[normalized.String()]
	cache.mu.RUnlock()
	if !exists || time.Since(entry.updated) > arpCacheTTL {
		return nil, false
	}

	return cloneHardwareAddr(entry.mac), true
}

func (cache *arpCache) store(ip net.IP, mac net.HardwareAddr) {
	normalized := normalizeIPv4(ip)
	clonedMAC := cloneHardwareAddr(mac)
	if normalized == nil || len(clonedMAC) == 0 {
		return
	}

	cache.mu.Lock()
	cache.entries[normalized.String()] = arpCacheEntry{
		mac:     clonedMAC,
		updated: time.Now(),
	}
	cache.mu.Unlock()
}

func (cache *arpCache) snapshot() []ARPCacheItem {
	now := time.Now()

	cache.mu.RLock()
	items := make([]ARPCacheItem, 0, len(cache.entries))
	for ipText, entry := range cache.entries {
		if now.Sub(entry.updated) > arpCacheTTL {
			continue
		}

		items = append(items, ARPCacheItem{
			IP:        ipText,
			MAC:       cloneHardwareAddr(entry.mac).String(),
			UpdatedAt: entry.updated.UTC().Format(time.RFC3339Nano),
		})
	}
	cache.mu.RUnlock()

	sort.Slice(items, func(i, j int) bool {
		return items[i].IP < items[j].IP
	})

	return items
}

func (listener *pcapAdoptionListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		<-listener.done
	})

	return nil
}

func (listener *pcapAdoptionListener) ARPCacheSnapshot() []ARPCacheItem {
	if listener.cache == nil {
		return nil
	}

	return listener.cache.snapshot()
}

func (listener *pcapAdoptionListener) Ping(source adoptionEntry, targetIP net.IP, count int) (PingAdoptedIPAddressResult, error) {
	targetIP = normalizeIPv4(targetIP)
	if targetIP == nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("a valid IPv4 target is required")
	}
	if count <= 0 {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("ping count must be positive")
	}

	result := PingAdoptedIPAddressResult{
		SourceIP: source.ip.String(),
		TargetIP: targetIP.String(),
		Replies:  make([]PingAdoptedIPAddressReply, 0, count),
	}

	targetMAC, err := listener.resolveHardwareAddr(source, targetIP)
	if err != nil {
		return result, err
	}

	defaultPingID := listener.nextPingIdentifier()

	for sequence := 1; sequence <= count; sequence++ {
		packet := buildICMPEchoPacket(
			source.ip,
			source.mac,
			targetIP,
			targetMAC,
			layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			defaultPingID,
			uint16(sequence),
			nil,
		)

		if err := listener.prepareReadyPacket(packet, source.overrideBindings.ICMPEchoRequestOverride); err != nil {
			return result, err
		}

		finalTargetIP := normalizeIPv4(packet.IPv4.DstIP)
		if finalTargetIP == nil {
			return result, fmt.Errorf("IPv4.DstIP is required for outbound ICMP echo requests")
		}

		replyCh, err := listener.registerPingWaiter(packet.ICMPv4.Id, packet.ICMPv4.Seq)
		if err != nil {
			return result, err
		}

		frame, err := packet.serialize()
		if err != nil {
			listener.unregisterPingWaiter(packet.ICMPv4.Id, packet.ICMPv4.Seq)
			return result, err
		}

		sentAt := time.Now()
		if err := listener.writePacket(frame); err != nil {
			listener.unregisterPingWaiter(packet.ICMPv4.Id, packet.ICMPv4.Seq)
			return result, err
		}

		if result.Sent == 0 {
			result.SourceIP = ipString(packet.IPv4.SrcIP)
			result.TargetIP = ipString(packet.IPv4.DstIP)
		}

		source.recordICMP("outbound", "send-echo-request", finalTargetIP, packet.ICMPv4.Id, packet.ICMPv4.Seq, 0, "sent", "")

		reply := PingAdoptedIPAddressReply{Sequence: int(packet.ICMPv4.Seq)}
		result.Sent++

		if rtt, ok := listener.waitForPingReply(replyCh, sentAt); ok {
			reply.Success = true
			reply.RTTMillis = float64(rtt) / float64(time.Millisecond)
			result.Received++
			source.recordICMP("inbound", "recv-echo-reply", finalTargetIP, packet.ICMPv4.Id, packet.ICMPv4.Seq, rtt, "received", "")
		} else {
			source.recordICMP("inbound", "echo-timeout", finalTargetIP, packet.ICMPv4.Id, packet.ICMPv4.Seq, 0, "timeout", "")
		}

		listener.unregisterPingWaiter(packet.ICMPv4.Id, packet.ICMPv4.Seq)
		result.Replies = append(result.Replies, reply)
	}

	return result, nil
}

func (listener *pcapAdoptionListener) resolveHardwareAddr(source adoptionEntry, targetIP net.IP) (net.HardwareAddr, error) {
	if targetIP == nil {
		return nil, fmt.Errorf("a valid IPv4 target is required")
	}

	if entry, exists := listener.lookup(targetIP); exists {
		return cloneHardwareAddr(entry.mac), nil
	}

	nextHopIP := outboundNextHopIP(source, targetIP)
	if nextHopIP == nil {
		return nil, fmt.Errorf("a valid IPv4 next hop is required")
	}

	if mac, exists := listener.cache.lookup(nextHopIP); exists {
		return mac, nil
	}

	waiter := make(chan net.HardwareAddr, 1)
	key := nextHopIP.String()

	listener.mu.Lock()
	waiters := listener.arpWaiters[key]
	shouldQuery := len(waiters) == 0
	listener.arpWaiters[key] = append(waiters, waiter)
	listener.mu.Unlock()

	if shouldQuery {
		if err := listener.sendARPRequest(source, nextHopIP); err != nil {
			listener.removeARPWaiter(key, waiter)
			return nil, err
		}
	}

	timer := time.NewTimer(arpResolveTimeout)
	defer timer.Stop()

	select {
	case mac := <-waiter:
		return mac, nil
	case <-timer.C:
		listener.removeARPWaiter(key, waiter)
		source.recordARP("outbound", "resolve-timeout", nextHopIP, nil, resolveTimeoutDetails(targetIP, nextHopIP))
		if nextHopIP.Equal(targetIP) {
			return nil, fmt.Errorf("ARP timeout resolving %s", targetIP)
		}
		return nil, fmt.Errorf("ARP timeout resolving next hop %s for target %s", nextHopIP, targetIP)
	case <-listener.stop:
		listener.removeARPWaiter(key, waiter)
		return nil, fmt.Errorf("adoption listener stopped")
	}
}

func outboundNextHopIP(source adoptionEntry, targetIP net.IP) net.IP {
	targetIP = normalizeIPv4(targetIP)
	if targetIP == nil {
		return nil
	}
	if normalizeIPv4(source.defaultGateway) == nil {
		return cloneIPv4(targetIP)
	}

	routes := interfaceIPv4Networks(source.iface)
	if shouldRouteDirect(targetIP, routes) {
		return cloneIPv4(targetIP)
	}

	return cloneIPv4(source.defaultGateway)
}

func shouldRouteDirect(targetIP net.IP, routes []net.IPNet) bool {
	targetIP = normalizeIPv4(targetIP)
	if targetIP == nil {
		return false
	}
	if len(routes) == 0 {
		return true
	}

	for _, route := range routes {
		if route.Contains(targetIP) {
			return true
		}
	}

	return false
}

func interfaceIPv4Networks(iface net.Interface) []net.IPNet {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	networks := make([]net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := normalizeIPv4(ipNet.IP)
		if ip == nil || len(ipNet.Mask) != net.IPv4len {
			continue
		}

		networks = append(networks, net.IPNet{
			IP:   cloneIPv4(ip.Mask(ipNet.Mask)),
			Mask: append(net.IPMask(nil), ipNet.Mask...),
		})
	}

	return networks
}

func resolveTimeoutDetails(targetIP, nextHopIP net.IP) string {
	if normalizeIPv4(targetIP) == nil || normalizeIPv4(nextHopIP) == nil {
		return "no ARP reply received"
	}
	if targetIP.Equal(nextHopIP) {
		return "no ARP reply received"
	}

	return fmt.Sprintf("no ARP reply received from next hop %s for target %s", nextHopIP, targetIP)
}

func (listener *pcapAdoptionListener) nextPingIdentifier() uint16 {
	listener.mu.Lock()
	defer listener.mu.Unlock()

	for {
		listener.nextPingID++
		if listener.nextPingID == 0 {
			continue
		}
		return listener.nextPingID
	}
}

func (listener *pcapAdoptionListener) registerPingWaiter(id, sequence uint16) (chan pingReply, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()

	key := pingWaiterKey{id: id, sequence: sequence}
	if _, exists := listener.pingWaiters[key]; exists {
		return nil, fmt.Errorf("a ping waiter is already active for ICMP id=%d seq=%d", id, sequence)
	}

	replyCh := make(chan pingReply, 1)
	listener.pingWaiters[key] = replyCh
	return replyCh, nil
}

func (listener *pcapAdoptionListener) unregisterPingWaiter(id, sequence uint16) {
	listener.mu.Lock()
	delete(listener.pingWaiters, pingWaiterKey{id: id, sequence: sequence})
	listener.mu.Unlock()
}

func (listener *pcapAdoptionListener) waitForPingReply(replyCh <-chan pingReply, sentAt time.Time) (time.Duration, bool) {
	timer := time.NewTimer(pingReplyTimeout)
	defer timer.Stop()

	for {
		select {
		case reply := <-replyCh:
			return reply.receivedAt.Sub(sentAt), true
		case <-timer.C:
			return 0, false
		case <-listener.stop:
			return 0, false
		}
	}
}

func (listener *pcapAdoptionListener) run() {
	defer close(listener.done)
	defer listener.handle.Close()

	source := gopacket.NewPacketSource(listener.handle, listener.handle.LinkType())

	for {
		select {
		case <-listener.stop:
			return
		default:
		}

		packet, err := source.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			return
		}

		if arpLayer, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
			listener.handleARPPacket(arpLayer)
			continue
		}

		ethernet, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			continue
		}

		ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}

		icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok {
			continue
		}

		listener.handleICMPPacket(ethernet, ipv4, icmp)
	}
}

func (listener *pcapAdoptionListener) handleARPPacket(arpLayer *layers.ARP) {
	sourceIP := normalizeIPv4(net.IP(arpLayer.SourceProtAddress))
	sourceMAC := cloneHardwareAddr(net.HardwareAddr(arpLayer.SourceHwAddress))
	if sourceIP != nil && len(sourceMAC) != 0 {
		listener.cache.store(sourceIP, sourceMAC)
		if arpLayer.Operation == uint16(layers.ARPReply) {
			listener.notifyARPWaiters(sourceIP, sourceMAC)
			if entry, exists := listener.lookup(net.IP(arpLayer.DstProtAddress)); exists {
				entry.recordARP("inbound", "recv-reply", sourceIP, sourceMAC, "")
			}
		}
	}

	if arpLayer.Operation != uint16(layers.ARPRequest) {
		return
	}

	requestedIP := normalizeIPv4(net.IP(arpLayer.DstProtAddress))
	if requestedIP == nil {
		return
	}

	entry, exists := listener.lookup(requestedIP)
	if !exists {
		return
	}

	if sourceIP == nil || len(sourceMAC) == 0 {
		return
	}

	entry.recordARP("inbound", "recv-request", sourceIP, sourceMAC, "")
	_ = listener.sendARPReply(entry, sourceIP, sourceMAC)
}

func (listener *pcapAdoptionListener) handleICMPPacket(ethernet *layers.Ethernet, ipv4 *layers.IPv4, icmp *layers.ICMPv4) {
	entry, exists := listener.lookup(ipv4.DstIP)
	if !exists {
		return
	}

	sourceIP := normalizeIPv4(ipv4.SrcIP)
	sourceMAC := cloneHardwareAddr(net.HardwareAddr(ethernet.SrcMAC))
	if sourceIP != nil && len(sourceMAC) != 0 {
		listener.cache.store(sourceIP, sourceMAC)
	}

	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		if sourceIP == nil || len(sourceMAC) == 0 {
			return
		}
		entry.recordICMP("inbound", "recv-echo-request", sourceIP, icmp.Id, icmp.Seq, 0, "received", "")
		_ = listener.sendICMPEchoReply(entry, sourceIP, sourceMAC, icmp.Id, icmp.Seq, icmp.Payload)
	case layers.ICMPv4TypeEchoReply:
		listener.deliverPingReply(icmp.Id, icmp.Seq)
	}
}

func (listener *pcapAdoptionListener) deliverPingReply(id, sequence uint16) {
	listener.mu.Lock()
	replyCh, exists := listener.pingWaiters[pingWaiterKey{id: id, sequence: sequence}]
	listener.mu.Unlock()
	if !exists {
		return
	}

	select {
	case replyCh <- pingReply{receivedAt: time.Now()}:
	default:
	}
}

func (listener *pcapAdoptionListener) notifyARPWaiters(ip net.IP, mac net.HardwareAddr) {
	key := ip.String()

	listener.mu.Lock()
	waiters := listener.arpWaiters[key]
	delete(listener.arpWaiters, key)
	listener.mu.Unlock()

	for _, waiter := range waiters {
		select {
		case waiter <- cloneHardwareAddr(mac):
		default:
		}
	}
}

func (listener *pcapAdoptionListener) removeARPWaiter(key string, target chan net.HardwareAddr) {
	listener.mu.Lock()
	defer listener.mu.Unlock()

	waiters := listener.arpWaiters[key]
	for index, waiter := range waiters {
		if waiter != target {
			continue
		}

		waiters = append(waiters[:index], waiters[index+1:]...)
		if len(waiters) == 0 {
			delete(listener.arpWaiters, key)
		} else {
			listener.arpWaiters[key] = waiters
		}
		return
	}
}

func (listener *pcapAdoptionListener) sendARPRequest(source adoptionEntry, targetIP net.IP) error {
	packet := buildARPRequestPacket(source.ip, source.mac, targetIP)
	frame, err := listener.serializeReadyPacket(packet, source.overrideBindings.ARPRequestOverride)
	if err != nil {
		return err
	}
	if err := listener.writePacket(frame); err != nil {
		return err
	}

	source.recordARP(
		"outbound",
		"send-request",
		net.IP(packet.ARP.DstProtAddress),
		net.HardwareAddr(packet.Ethernet.DstMAC),
		"",
	)
	return nil
}

func (listener *pcapAdoptionListener) sendARPReply(entry adoptionEntry, requesterIP net.IP, requesterMAC net.HardwareAddr) error {
	packet := buildARPReplyPacket(entry.ip, entry.mac, requesterIP, requesterMAC)
	frame, err := listener.serializeReadyPacket(packet, entry.overrideBindings.ARPReplyOverride)
	if err != nil {
		return err
	}
	if err := listener.writePacket(frame); err != nil {
		return err
	}

	entry.recordARP(
		"outbound",
		"send-reply",
		net.IP(packet.ARP.DstProtAddress),
		net.HardwareAddr(packet.Ethernet.DstMAC),
		"",
	)
	return nil
}

func (listener *pcapAdoptionListener) sendICMPEchoReply(entry adoptionEntry, targetIP net.IP, targetMAC net.HardwareAddr, id, sequence uint16, payload []byte) error {
	packet := buildICMPEchoPacket(
		entry.ip,
		entry.mac,
		targetIP,
		targetMAC,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		id,
		sequence,
		payload,
	)
	frame, err := listener.serializeReadyPacket(packet, entry.overrideBindings.ICMPEchoReplyOverride)
	if err != nil {
		return err
	}
	if err := listener.writePacket(frame); err != nil {
		return err
	}

	entry.recordICMP(
		"outbound",
		"send-echo-reply",
		packet.IPv4.DstIP,
		packet.ICMPv4.Id,
		packet.ICMPv4.Seq,
		0,
		"sent",
		"",
	)
	return nil
}

func (listener *pcapAdoptionListener) serializeReadyPacket(packet *outboundPacket, overrideName string) ([]byte, error) {
	if err := listener.prepareReadyPacket(packet, overrideName); err != nil {
		return nil, err
	}

	return packet.serialize()
}

func (listener *pcapAdoptionListener) prepareReadyPacket(packet *outboundPacket, overrideName string) error {
	if err := packet.validate(); err != nil {
		return err
	}

	return listener.applyBoundOverride(packet, overrideName)
}

func (listener *pcapAdoptionListener) applyBoundOverride(packet *outboundPacket, name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	if listener.resolveOverride == nil {
		return fmt.Errorf("stored packet overrides are unavailable")
	}

	override, exists := listener.resolveOverride(name)
	if !exists {
		return fmt.Errorf("stored packet override %q was not found", name)
	}

	return packet.applyOverride(override)
}

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	listener.writeMu.Lock()
	defer listener.writeMu.Unlock()

	return listener.handle.WritePacketData(frame)
}
