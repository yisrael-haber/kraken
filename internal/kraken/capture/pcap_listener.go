package capture

import (
	"errors"
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
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/inventory"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

const (
	adoptionListenerSnapLen     = 65535
	adoptionListenerReadTimeout = 50 * time.Millisecond
	arpCacheTTL                 = 5 * time.Minute
	arpCacheSweepInterval       = time.Minute
	arpCacheMaxEntries          = 1024
	arpResolveTimeout           = 3 * time.Second
	pingReplyTimeout            = 3 * time.Second
	outboundWorkerCount         = 4
	outboundJobQueueSize        = 64
)

type arpCacheEntry struct {
	mac     net.HardwareAddr
	updated time.Time
}

type arpCache struct {
	mu            sync.RWMutex
	entries       map[string]arpCacheEntry
	ttl           time.Duration
	sweepInterval time.Duration
	maxEntries    int
	lastSweep     time.Time
}

type pingReply struct {
	receivedAt time.Time
}

type pingWaiterKey struct {
	id       uint16
	sequence uint16
}

type outboundJob struct {
	run  func() error
	done chan error
}

type packetModifiers struct {
	overrideName string
	scriptName   string
	scriptCtx    scriptpkg.ExecutionContext
}

type pcapAdoptionListener struct {
	handle          *pcap.Handle
	lookup          adoption.LookupFunc
	resolveOverride adoption.OverrideLookupFunc
	resolveScript   adoption.ScriptLookupFunc
	cache           *arpCache

	mu          sync.Mutex
	arpWaiters  map[string][]chan net.HardwareAddr
	pingWaiters map[pingWaiterKey]chan pingReply
	nextPingID  uint16

	writeMu             sync.Mutex
	serializeBufferPool sync.Pool
	outboundJobs        chan outboundJob
	workerGroup         sync.WaitGroup
	stop                chan struct{}
	done                chan struct{}
	closeOnce           sync.Once

	stateMu sync.RWMutex
	runErr  error
}

func NewListener(iface net.Interface, lookup adoption.LookupFunc, resolveOverride adoption.OverrideLookupFunc, resolveScript adoption.ScriptLookupFunc) (adoption.Listener, error) {
	deviceName, err := inventory.CaptureDeviceNameForInterface(iface)
	if err != nil {
		return nil, err
	}

	handle, err := openAdoptionHandle(deviceName, iface.Name)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter("arp or icmp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set adoption capture filter on %s: %w", iface.Name, err)
	}

	listener := &pcapAdoptionListener{
		handle:          handle,
		lookup:          lookup,
		resolveOverride: resolveOverride,
		resolveScript:   resolveScript,
		cache:           newARPCache(),
		arpWaiters:      make(map[string][]chan net.HardwareAddr),
		pingWaiters:     make(map[pingWaiterKey]chan pingReply),
		serializeBufferPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBufferExpectedSize(64, 64)
			},
		},
		outboundJobs: make(chan outboundJob, outboundJobQueueSize),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}

	listener.startOutboundWorkers(outboundWorkerCount)
	go listener.run()

	return listener, nil
}

func openAdoptionHandle(deviceName, ifaceName string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(deviceName)
	if err == nil {
		defer inactive.CleanUp()

		if err := inactive.SetSnapLen(adoptionListenerSnapLen); err == nil {
			if err := inactive.SetPromisc(true); err == nil {
				if err := inactive.SetTimeout(adoptionListenerReadTimeout); err == nil {
					if err := inactive.SetImmediateMode(true); err == nil {
						handle, err := inactive.Activate()
						if err == nil {
							return handle, nil
						}
					}
				}
			}
		}
	}

	handle, err := pcap.OpenLive(deviceName, adoptionListenerSnapLen, true, adoptionListenerReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("open adoption listener on %s: %w", ifaceName, err)
	}

	return handle, nil
}

func newARPCache() *arpCache {
	return &arpCache{
		entries:       make(map[string]arpCacheEntry),
		ttl:           arpCacheTTL,
		sweepInterval: arpCacheSweepInterval,
		maxEntries:    arpCacheMaxEntries,
	}
}

func (cache *arpCache) lookup(ip net.IP) (net.HardwareAddr, bool) {
	normalized := common.NormalizeIPv4(ip)
	if normalized == nil {
		return nil, false
	}

	now := time.Now()
	key := normalized.String()

	cache.mu.RLock()
	entry, exists := cache.entries[key]
	cache.mu.RUnlock()
	if !exists {
		return nil, false
	}
	if cache.isExpired(now, entry) {
		cache.mu.Lock()
		if current, stillExists := cache.entries[key]; stillExists && cache.isExpired(now, current) {
			delete(cache.entries, key)
		}
		cache.mu.Unlock()
		return nil, false
	}

	return common.CloneHardwareAddr(entry.mac), true
}

func (cache *arpCache) store(ip net.IP, mac net.HardwareAddr) {
	normalized := common.NormalizeIPv4(ip)
	clonedMAC := common.CloneHardwareAddr(mac)
	if normalized == nil || len(clonedMAC) == 0 {
		return
	}

	now := time.Now()
	key := normalized.String()

	cache.mu.Lock()
	cache.entries[key] = arpCacheEntry{
		mac:     clonedMAC,
		updated: now,
	}
	if cache.shouldSweepLocked(now) {
		cache.sweepLocked(now)
	}
	cache.mu.Unlock()
}

func (cache *arpCache) snapshot() []adoption.ARPCacheItem {
	now := time.Now()

	cache.mu.Lock()
	cache.sweepLocked(now)
	items := make([]adoption.ARPCacheItem, 0, len(cache.entries))
	for ipText, entry := range cache.entries {
		items = append(items, adoption.ARPCacheItem{
			IP:        ipText,
			MAC:       common.CloneHardwareAddr(entry.mac).String(),
			UpdatedAt: entry.updated.UTC().Format(time.RFC3339Nano),
		})
	}
	cache.mu.Unlock()

	sort.Slice(items, func(i, j int) bool {
		return items[i].IP < items[j].IP
	})

	return items
}

func (cache *arpCache) isExpired(now time.Time, entry arpCacheEntry) bool {
	if cache.ttl <= 0 {
		return false
	}

	return now.Sub(entry.updated) > cache.ttl
}

func (cache *arpCache) shouldSweepLocked(now time.Time) bool {
	if cache.sweepInterval <= 0 {
		return cache.maxEntries > 0 && len(cache.entries) > cache.maxEntries
	}

	return cache.lastSweep.IsZero() ||
		now.Sub(cache.lastSweep) >= cache.sweepInterval ||
		(cache.maxEntries > 0 && len(cache.entries) > cache.maxEntries)
}

func (cache *arpCache) sweepLocked(now time.Time) {
	cache.lastSweep = now

	for key, entry := range cache.entries {
		if cache.isExpired(now, entry) {
			delete(cache.entries, key)
		}
	}

	if cache.maxEntries <= 0 || len(cache.entries) <= cache.maxEntries {
		return
	}

	type agedEntry struct {
		key     string
		updated time.Time
	}

	items := make([]agedEntry, 0, len(cache.entries))
	for key, entry := range cache.entries {
		items = append(items, agedEntry{key: key, updated: entry.updated})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].updated.Before(items[j].updated)
	})

	for index := 0; index < len(items)-cache.maxEntries; index++ {
		delete(cache.entries, items[index].key)
	}
}

func (listener *pcapAdoptionListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		listener.workerGroup.Wait()
		<-listener.done
	})

	return nil
}

func (listener *pcapAdoptionListener) startOutboundWorkers(count int) {
	if count <= 0 {
		count = 1
	}

	for index := 0; index < count; index++ {
		listener.workerGroup.Add(1)
		go func() {
			defer listener.workerGroup.Done()

			for {
				select {
				case <-listener.stop:
					return
				case job := <-listener.outboundJobs:
					if job.run == nil {
						continue
					}
					err := job.run()
					if job.done != nil {
						job.done <- err
					}
				}
			}
		}()
	}
}

func (listener *pcapAdoptionListener) submitOutboundJob(job outboundJob) error {
	select {
	case <-listener.stop:
		return adoption.ErrListenerStopped
	case listener.outboundJobs <- job:
		return nil
	}
}

func (listener *pcapAdoptionListener) runOutboundJobSync(run func() error) error {
	done := make(chan error, 1)
	if err := listener.submitOutboundJob(outboundJob{
		run:  run,
		done: done,
	}); err != nil {
		return err
	}

	select {
	case err := <-done:
		return err
	case <-listener.stop:
		return adoption.ErrListenerStopped
	}
}

func (listener *pcapAdoptionListener) runOutboundJobAsync(run func() error) error {
	select {
	case <-listener.stop:
		return adoption.ErrListenerStopped
	case listener.outboundJobs <- outboundJob{run: run}:
		return nil
	default:
		return fmt.Errorf("outbound worker queue is full")
	}
}

func (listener *pcapAdoptionListener) Healthy() error {
	listener.stateMu.RLock()
	runErr := listener.runErr
	listener.stateMu.RUnlock()
	if runErr != nil {
		return runErr
	}

	select {
	case <-listener.done:
		return adoption.ErrListenerStopped
	default:
		return nil
	}
}

func (listener *pcapAdoptionListener) ARPCacheSnapshot() []adoption.ARPCacheItem {
	if listener.cache == nil {
		return nil
	}

	return listener.cache.snapshot()
}

func (listener *pcapAdoptionListener) Ping(source adoption.Identity, targetIP net.IP, count int) (adoption.PingAdoptedIPAddressResult, error) {
	targetIP = common.NormalizeIPv4(targetIP)
	if targetIP == nil {
		return adoption.PingAdoptedIPAddressResult{}, fmt.Errorf("a valid IPv4 target is required")
	}
	if count <= 0 {
		return adoption.PingAdoptedIPAddressResult{}, fmt.Errorf("ping count must be positive")
	}

	result := adoption.PingAdoptedIPAddressResult{
		SourceIP: source.IP().String(),
		TargetIP: targetIP.String(),
		Replies:  make([]adoption.PingAdoptedIPAddressReply, 0, count),
	}

	targetMAC, err := listener.resolveHardwareAddr(source, targetIP)
	if err != nil {
		return result, err
	}

	defaultPingID := listener.nextPingIdentifier()

	for sequence := 1; sequence <= count; sequence++ {
		packet := packetpkg.BuildICMPEchoPacket(
			source.IP(),
			source.MAC(),
			targetIP,
			targetMAC,
			layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			defaultPingID,
			uint16(sequence),
			nil,
		)

		if err := listener.prepareReadyPacket(packet, buildPacketModifiers(source, adoption.SendPathICMPEchoRequest, "icmpv4")); err != nil {
			return result, err
		}

		finalSourceIP := common.IPString(packet.IPv4.SrcIP)
		finalTargetIP := common.NormalizeIPv4(packet.IPv4.DstIP)
		if finalTargetIP == nil {
			return result, fmt.Errorf("IPv4.DstIP is required for outbound ICMP echo requests")
		}
		packetID := packet.ICMPv4.Id
		packetSeq := packet.ICMPv4.Seq

		replyCh, err := listener.registerPingWaiter(packetID, packetSeq)
		if err != nil {
			return result, err
		}

		sentAt := time.Now()
		if err := listener.writePreparedPacket(packet); err != nil {
			listener.unregisterPingWaiter(packetID, packetSeq)
			return result, err
		}

		if result.Sent == 0 {
			result.SourceIP = finalSourceIP
			result.TargetIP = finalTargetIP.String()
		}

		source.RecordICMP("outbound", "send-echo-request", finalTargetIP, packetID, packetSeq, 0, "sent", "")

		reply := adoption.PingAdoptedIPAddressReply{Sequence: int(packetSeq)}
		result.Sent++

		if rtt, ok := listener.waitForPingReply(replyCh, sentAt); ok {
			reply.Success = true
			reply.RTTMillis = float64(rtt) / float64(time.Millisecond)
			result.Received++
			source.RecordICMP("inbound", "recv-echo-reply", finalTargetIP, packetID, packetSeq, rtt, "received", "")
		} else {
			source.RecordICMP("inbound", "echo-timeout", finalTargetIP, packetID, packetSeq, 0, "timeout", "")
		}

		listener.unregisterPingWaiter(packetID, packetSeq)
		result.Replies = append(result.Replies, reply)
	}

	return result, nil
}

func (listener *pcapAdoptionListener) resolveHardwareAddr(source adoption.Identity, targetIP net.IP) (net.HardwareAddr, error) {
	if targetIP == nil {
		return nil, fmt.Errorf("a valid IPv4 target is required")
	}

	if entry, exists := listener.lookup(targetIP); exists {
		return common.CloneHardwareAddr(entry.MAC()), nil
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
		source.RecordARP("outbound", "resolve-timeout", nextHopIP, nil, resolveTimeoutDetails(targetIP, nextHopIP))
		if nextHopIP.Equal(targetIP) {
			return nil, fmt.Errorf("ARP timeout resolving %s", targetIP)
		}
		return nil, fmt.Errorf("ARP timeout resolving next hop %s for target %s", nextHopIP, targetIP)
	case <-listener.stop:
		listener.removeARPWaiter(key, waiter)
		return nil, fmt.Errorf("adoption listener stopped")
	}
}

func outboundNextHopIP(source adoption.Identity, targetIP net.IP) net.IP {
	targetIP = common.NormalizeIPv4(targetIP)
	if targetIP == nil {
		return nil
	}
	if common.NormalizeIPv4(source.DefaultGateway()) == nil {
		return common.CloneIPv4(targetIP)
	}

	routes := interfaceIPv4Networks(source.Interface())
	if shouldRouteDirect(targetIP, routes) {
		return common.CloneIPv4(targetIP)
	}

	return common.CloneIPv4(source.DefaultGateway())
}

func shouldRouteDirect(targetIP net.IP, routes []net.IPNet) bool {
	targetIP = common.NormalizeIPv4(targetIP)
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

		ip := common.NormalizeIPv4(ipNet.IP)
		if ip == nil || len(ipNet.Mask) != net.IPv4len {
			continue
		}

		networks = append(networks, net.IPNet{
			IP:   common.CloneIPv4(ip.Mask(ipNet.Mask)),
			Mask: append(net.IPMask(nil), ipNet.Mask...),
		})
	}

	return networks
}

func resolveTimeoutDetails(targetIP, nextHopIP net.IP) string {
	if common.NormalizeIPv4(targetIP) == nil || common.NormalizeIPv4(nextHopIP) == nil {
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
	var runErr error

	defer listener.setRunErr(runErr)
	defer close(listener.done)
	defer listener.handle.Close()

	source := gopacket.NewPacketSource(listener.handle, listener.handle.LinkType())
	source.DecodeOptions = gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	}

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
			select {
			case <-listener.stop:
			default:
				runErr = adoption.ErrListenerStopped
			}
			return
		}
		if err != nil {
			select {
			case <-listener.stop:
			default:
				runErr = err
			}
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

func (listener *pcapAdoptionListener) setRunErr(err error) {
	if err == nil {
		return
	}

	listener.stateMu.Lock()
	if listener.runErr == nil {
		listener.runErr = err
	}
	listener.stateMu.Unlock()
}

func (listener *pcapAdoptionListener) handleARPPacket(arpLayer *layers.ARP) {
	sourceIP := common.NormalizeIPv4(net.IP(arpLayer.SourceProtAddress))
	sourceMAC := net.HardwareAddr(arpLayer.SourceHwAddress)
	if sourceIP != nil && len(sourceMAC) != 0 {
		listener.cache.store(sourceIP, sourceMAC)
		if arpLayer.Operation == uint16(layers.ARPReply) {
			listener.notifyARPWaiters(sourceIP, sourceMAC)
			if item, exists := listener.lookup(net.IP(arpLayer.DstProtAddress)); exists {
				item.RecordARP("inbound", "recv-reply", sourceIP, sourceMAC, "")
			}
		}
	}

	if arpLayer.Operation != uint16(layers.ARPRequest) {
		return
	}

	requestedIP := common.NormalizeIPv4(net.IP(arpLayer.DstProtAddress))
	if requestedIP == nil {
		return
	}

	item, exists := listener.lookup(requestedIP)
	if !exists {
		return
	}

	if sourceIP == nil || len(sourceMAC) == 0 {
		return
	}

	item.RecordARP("inbound", "recv-request", sourceIP, sourceMAC, "")
	_ = listener.sendARPReply(item, sourceIP, sourceMAC)
}

func (listener *pcapAdoptionListener) handleICMPPacket(ethernet *layers.Ethernet, ipv4 *layers.IPv4, icmp *layers.ICMPv4) {
	item, exists := listener.lookup(ipv4.DstIP)
	if !exists {
		return
	}

	sourceIP := common.NormalizeIPv4(ipv4.SrcIP)
	sourceMAC := net.HardwareAddr(ethernet.SrcMAC)
	if sourceIP != nil && len(sourceMAC) != 0 {
		listener.cache.store(sourceIP, sourceMAC)
	}

	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		if sourceIP == nil || len(sourceMAC) == 0 {
			return
		}
		item.RecordICMP("inbound", "recv-echo-request", sourceIP, icmp.Id, icmp.Seq, 0, "received", "")
		_ = listener.sendICMPEchoReply(item, sourceIP, sourceMAC, icmp.Id, icmp.Seq, icmp.Payload)
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
		case waiter <- common.CloneHardwareAddr(mac):
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

func (listener *pcapAdoptionListener) sendARPRequest(source adoption.Identity, targetIP net.IP) error {
	packet := packetpkg.BuildARPRequestPacket(source.IP(), source.MAC(), targetIP)
	modifiers := buildPacketModifiers(source, adoption.SendPathARPRequest, "arp")

	return listener.runOutboundJobSync(func() error {
		if err := listener.prepareReadyPacket(packet, modifiers); err != nil {
			return err
		}
		if err := listener.writePreparedPacket(packet); err != nil {
			return err
		}

		source.RecordARP(
			"outbound",
			"send-request",
			net.IP(packet.ARP.DstProtAddress),
			net.HardwareAddr(packet.Ethernet.DstMAC),
			"",
		)
		return nil
	})
}

func (listener *pcapAdoptionListener) sendARPReply(item adoption.Identity, requesterIP net.IP, requesterMAC net.HardwareAddr) error {
	packet := packetpkg.BuildARPReplyPacket(item.IP(), item.MAC(), requesterIP, requesterMAC)
	modifiers := buildPacketModifiers(item, adoption.SendPathARPReply, "arp")

	if err := listener.runOutboundJobAsync(func() error {
		if err := listener.prepareReadyPacket(packet, modifiers); err != nil {
			item.RecordARP("outbound", "send-reply-error", requesterIP, requesterMAC, err.Error())
			return err
		}
		if err := listener.writePreparedPacket(packet); err != nil {
			item.RecordARP("outbound", "send-reply-error", requesterIP, requesterMAC, err.Error())
			return err
		}

		item.RecordARP(
			"outbound",
			"send-reply",
			net.IP(packet.ARP.DstProtAddress),
			net.HardwareAddr(packet.Ethernet.DstMAC),
			"",
		)
		return nil
	}); err != nil {
		item.RecordARP("outbound", "send-reply-error", requesterIP, requesterMAC, err.Error())
		return err
	}

	return nil
}

func (listener *pcapAdoptionListener) sendICMPEchoReply(item adoption.Identity, targetIP net.IP, targetMAC net.HardwareAddr, id, sequence uint16, payload []byte) error {
	packet := packetpkg.BuildICMPEchoPacket(
		item.IP(),
		item.MAC(),
		targetIP,
		targetMAC,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		id,
		sequence,
		payload,
	)
	modifiers := buildPacketModifiers(item, adoption.SendPathICMPEchoReply, "icmpv4")

	if err := listener.runOutboundJobAsync(func() error {
		if err := listener.prepareReadyPacket(packet, modifiers); err != nil {
			item.RecordICMP("outbound", "send-echo-reply", targetIP, id, sequence, 0, "error", err.Error())
			return err
		}
		if err := listener.writePreparedPacket(packet); err != nil {
			item.RecordICMP("outbound", "send-echo-reply", targetIP, id, sequence, 0, "error", err.Error())
			return err
		}

		item.RecordICMP(
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
	}); err != nil {
		item.RecordICMP("outbound", "send-echo-reply", targetIP, id, sequence, 0, "error", err.Error())
		return err
	}

	return nil
}

func (listener *pcapAdoptionListener) serializeReadyPacket(packet *packetpkg.OutboundPacket, overrideName string) ([]byte, error) {
	if err := listener.prepareReadyPacket(packet, packetModifiers{overrideName: overrideName}); err != nil {
		return nil, err
	}

	return packet.Serialize()
}

func (listener *pcapAdoptionListener) prepareReadyPacket(packet *packetpkg.OutboundPacket, modifiers packetModifiers) error {
	if packet == nil {
		return nil
	}
	if !packet.Trusted {
		if err := packet.Validate(); err != nil {
			return err
		}
		packet.Trusted = true
	}

	if err := listener.applyBoundOverride(packet, modifiers.overrideName); err != nil {
		return err
	}
	if err := listener.applyBoundScript(packet, modifiers.scriptName, modifiers.scriptCtx); err != nil {
		return err
	}

	return packet.Validate()
}

func (listener *pcapAdoptionListener) writePreparedPacket(packet *packetpkg.OutboundPacket) error {
	buffer := listener.serializeBufferPool.Get().(gopacket.SerializeBuffer)
	defer listener.serializeBufferPool.Put(buffer)

	if err := packet.SerializeValidatedInto(buffer); err != nil {
		return err
	}

	return listener.writePacket(buffer.Bytes())
}

func (listener *pcapAdoptionListener) applyBoundOverride(packet *packetpkg.OutboundPacket, name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	if listener.resolveOverride == nil {
		return fmt.Errorf("stored packet overrides are unavailable")
	}

	override, err := listener.resolveOverride(name)
	if err != nil {
		if errors.Is(err, packetpkg.ErrStoredPacketOverrideNotFound) {
			return fmt.Errorf("stored packet override %q was not found", name)
		}

		return err
	}
	if override.Name == "" {
		return fmt.Errorf("stored packet override %q was not found", name)
	}

	return packet.ApplyOverride(override)
}

func (listener *pcapAdoptionListener) applyBoundScript(packet *packetpkg.OutboundPacket, name string, ctx scriptpkg.ExecutionContext) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	if listener.resolveScript == nil {
		return fmt.Errorf("stored scripts are unavailable")
	}

	script, err := listener.resolveScript(name)
	if err != nil {
		if errors.Is(err, scriptpkg.ErrStoredScriptNotFound) {
			return fmt.Errorf("stored script %q was not found", name)
		}

		return err
	}
	if script.Name == "" {
		return fmt.Errorf("stored script %q was not found", name)
	}

	return scriptpkg.Execute(script, packet, ctx, nil)
}

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	listener.writeMu.Lock()
	defer listener.writeMu.Unlock()

	return listener.handle.WritePacketData(frame)
}

func buildPacketModifiers(identity adoption.Identity, sendPath, protocol string) packetModifiers {
	bindings := identity.OverrideBindings()
	return packetModifiers{
		overrideName: bindings.OverrideForSendPath(sendPath),
		scriptName:   bindings.ScriptForSendPath(sendPath),
		scriptCtx: scriptpkg.ExecutionContext{
			ScriptName: bindings.ScriptForSendPath(sendPath),
			SendPath:   sendPath,
			Protocol:   protocol,
			Adopted: scriptpkg.ExecutionIdentity{
				IP:             identity.IP().String(),
				MAC:            identity.MAC().String(),
				InterfaceName:  identity.Interface().Name,
				DefaultGateway: common.IPString(identity.DefaultGateway()),
			},
		},
	}
}
