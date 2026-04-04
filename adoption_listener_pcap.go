package main

import (
	"fmt"
	"io"
	"net"
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
	seq        uint16
	receivedAt time.Time
}

type pcapAdoptionListener struct {
	handle *pcap.Handle
	lookup adoptionLookup
	cache  *arpCache

	mu          sync.Mutex
	arpWaiters  map[string][]chan net.HardwareAddr
	pingWaiters map[uint16]chan pingReply
	nextPingID  uint16

	writeMu   sync.Mutex
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newAdoptionListener(iface net.Interface, lookup adoptionLookup) (adoptionListener, error) {
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
		handle:      handle,
		lookup:      lookup,
		cache:       newARPCache(),
		arpWaiters:  make(map[string][]chan net.HardwareAddr),
		pingWaiters: make(map[uint16]chan pingReply),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
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

func (listener *pcapAdoptionListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		<-listener.done
	})

	return nil
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

	pingID, replyCh := listener.registerPingWaiter(count)
	defer listener.unregisterPingWaiter(pingID)

	for sequence := 1; sequence <= count; sequence++ {
		frame, err := buildICMPEchoFrame(
			source.ip,
			source.mac,
			targetIP,
			targetMAC,
			layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			pingID,
			uint16(sequence),
			nil,
		)
		if err != nil {
			return result, err
		}

		sentAt := time.Now()
		if err := listener.writePacket(frame); err != nil {
			return result, err
		}
		source.recordICMP("outbound", "send-echo-request", targetIP, pingID, uint16(sequence), 0, "sent", "")

		reply := PingAdoptedIPAddressReply{Sequence: sequence}
		result.Sent++

		if rtt, ok := listener.waitForPingReply(replyCh, uint16(sequence), sentAt); ok {
			reply.Success = true
			reply.RTTMillis = float64(rtt) / float64(time.Millisecond)
			result.Received++
			source.recordICMP("inbound", "recv-echo-reply", targetIP, pingID, uint16(sequence), rtt, "received", "")
		} else {
			source.recordICMP("inbound", "echo-timeout", targetIP, pingID, uint16(sequence), 0, "timeout", "")
		}

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

	if mac, exists := listener.cache.lookup(targetIP); exists {
		return mac, nil
	}

	waiter := make(chan net.HardwareAddr, 1)
	key := targetIP.String()

	listener.mu.Lock()
	waiters := listener.arpWaiters[key]
	shouldQuery := len(waiters) == 0
	listener.arpWaiters[key] = append(waiters, waiter)
	listener.mu.Unlock()

	if shouldQuery {
		if err := listener.sendARPRequest(source, targetIP); err != nil {
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
		source.recordARP("outbound", "resolve-timeout", targetIP, nil, "no ARP reply received")
		return nil, fmt.Errorf("ARP timeout resolving %s", targetIP)
	case <-listener.stop:
		listener.removeARPWaiter(key, waiter)
		return nil, fmt.Errorf("adoption listener stopped")
	}
}

func (listener *pcapAdoptionListener) registerPingWaiter(buffer int) (uint16, chan pingReply) {
	if buffer <= 0 {
		buffer = 1
	}

	listener.mu.Lock()
	defer listener.mu.Unlock()

	for {
		listener.nextPingID++
		if listener.nextPingID == 0 {
			continue
		}
		if _, exists := listener.pingWaiters[listener.nextPingID]; exists {
			continue
		}

		replyCh := make(chan pingReply, buffer)
		listener.pingWaiters[listener.nextPingID] = replyCh
		return listener.nextPingID, replyCh
	}
}

func (listener *pcapAdoptionListener) unregisterPingWaiter(id uint16) {
	listener.mu.Lock()
	delete(listener.pingWaiters, id)
	listener.mu.Unlock()
}

func (listener *pcapAdoptionListener) waitForPingReply(replyCh <-chan pingReply, sequence uint16, sentAt time.Time) (time.Duration, bool) {
	timer := time.NewTimer(pingReplyTimeout)
	defer timer.Stop()

	for {
		select {
		case reply := <-replyCh:
			if reply.seq != sequence {
				continue
			}
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
	replyCh, exists := listener.pingWaiters[id]
	listener.mu.Unlock()
	if !exists {
		return
	}

	select {
	case replyCh <- pingReply{seq: sequence, receivedAt: time.Now()}:
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
	frame, err := buildARPRequestFrame(source.ip, source.mac, targetIP)
	if err != nil {
		return err
	}

	if err := listener.writePacket(frame); err != nil {
		return err
	}

	source.recordARP("outbound", "send-request", targetIP, nil, "")
	return nil
}

func (listener *pcapAdoptionListener) sendARPReply(entry adoptionEntry, requesterIP net.IP, requesterMAC net.HardwareAddr) error {
	frame, err := buildARPReplyFrame(entry.ip, entry.mac, requesterIP, requesterMAC)
	if err != nil {
		return err
	}

	if err := listener.writePacket(frame); err != nil {
		return err
	}

	entry.recordARP("outbound", "send-reply", requesterIP, requesterMAC, "")
	return nil
}

func (listener *pcapAdoptionListener) sendICMPEchoReply(entry adoptionEntry, targetIP net.IP, targetMAC net.HardwareAddr, id, sequence uint16, payload []byte) error {
	frame, err := buildICMPEchoFrame(
		entry.ip,
		entry.mac,
		targetIP,
		targetMAC,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		id,
		sequence,
		payload,
	)
	if err != nil {
		return err
	}

	if err := listener.writePacket(frame); err != nil {
		return err
	}

	entry.recordICMP("outbound", "send-echo-reply", targetIP, id, sequence, 0, "sent", "")
	return nil
}

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	listener.writeMu.Lock()
	defer listener.writeMu.Unlock()

	return listener.handle.WritePacketData(frame)
}

func buildARPReplyFrame(adoptedIP net.IP, adoptedMAC net.HardwareAddr, requesterIP net.IP, requesterMAC net.HardwareAddr) ([]byte, error) {
	ethernet := &layers.Ethernet{
		SrcMAC:       adoptedMAC,
		DstMAC:       requesterMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         uint16(layers.ARPReply),
		SourceHwAddress:   cloneHardwareAddr(adoptedMAC),
		SourceProtAddress: cloneIPv4(adoptedIP),
		DstHwAddress:      cloneHardwareAddr(requesterMAC),
		DstProtAddress:    cloneIPv4(requesterIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, ethernet, arp); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func buildARPRequestFrame(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) ([]byte, error) {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	ethernet := &layers.Ethernet{
		SrcMAC:       sourceMAC,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         uint16(layers.ARPRequest),
		SourceHwAddress:   cloneHardwareAddr(sourceMAC),
		SourceProtAddress: cloneIPv4(sourceIP),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    cloneIPv4(targetIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, ethernet, arp); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func buildICMPEchoFrame(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) ([]byte, error) {
	ethernet := &layers.Ethernet{
		SrcMAC:       sourceMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    cloneIPv4(sourceIP),
		DstIP:    cloneIPv4(targetIP),
	}

	icmp := &layers.ICMPv4{
		TypeCode: typeCode,
		Id:       id,
		Seq:      sequence,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var body gopacket.Payload
	if len(payload) != 0 {
		body = gopacket.Payload(append([]byte(nil), payload...))
	}

	if body == nil {
		if err := gopacket.SerializeLayers(buffer, options, ethernet, ipv4, icmp); err != nil {
			return nil, err
		}
		return buffer.Bytes(), nil
	}

	if err := gopacket.SerializeLayers(buffer, options, ethernet, ipv4, icmp, body); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
