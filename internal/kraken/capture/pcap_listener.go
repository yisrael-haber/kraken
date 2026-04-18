package capture

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	adoptionListenerSnapLen     = 65535
	adoptionListenerReadTimeout = 50 * time.Millisecond
	pingReplyTimeout            = 3 * time.Second
	routeARPResolveTimeout      = 750 * time.Millisecond
	routeARPRequestInterval     = 150 * time.Millisecond
	routeARPResolvePollInterval = 25 * time.Millisecond
)

const emptyAdoptionCaptureBPFFilter = "(ether proto 0x0800 and ether proto 0x0806)"

type inboundFrameInfo struct {
	sourceIP  compactIPv4
	targetIP  compactIPv4
	sourceMAC compactMAC
}

type pcapAdoptionListener struct {
	handle        *pcap.Handle
	deviceName    string
	iface         net.Interface
	forward       adoption.ForwardLookupFunc
	resolveScript adoption.ScriptLookupFunc
	routes        []net.IPNet

	handleMu        sync.RWMutex
	captureFilter   string
	writeMu         sync.Mutex
	frameBufferPool sync.Pool

	stackMu   sync.RWMutex
	groups    map[string]*adoptedEngineGroup
	ipGroups  map[compactIPv4]*adoptedEngineGroup
	ipGroupsV atomic.Value
	groupsV   atomic.Value

	recordersMu sync.RWMutex
	recorders   map[string]*packetRecorder

	servicesMu sync.RWMutex
	services   map[string]map[string]*managedTCPService

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	stateMu sync.RWMutex
	runErr  error
}

func NewListener(iface net.Interface, forward adoption.ForwardLookupFunc, resolveScript adoption.ScriptLookupFunc) (adoption.Listener, error) {
	deviceName, err := interfacespkg.CaptureDeviceNameForInterface(iface)
	if err != nil {
		return nil, err
	}

	handle, err := openAdoptionHandle(deviceName, iface.Name)
	if err != nil {
		return nil, err
	}

	listener := &pcapAdoptionListener{
		handle:        handle,
		deviceName:    deviceName,
		iface:         iface,
		forward:       forward,
		resolveScript: resolveScript,
		routes:        interfaceIPv4Networks(iface),
		groups:        make(map[string]*adoptedEngineGroup),
		ipGroups:      make(map[compactIPv4]*adoptedEngineGroup),
		recorders:     make(map[string]*packetRecorder),
		services:      make(map[string]map[string]*managedTCPService),
		frameBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, 0, 2048)
			},
		},
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	listener.groupsV.Store([]*adoptedEngineGroup(nil))
	listener.ipGroupsV.Store(make(map[compactIPv4]*adoptedEngineGroup))
	listener.applyCaptureFilter(buildAdoptionCaptureBPFFilter(nil, listener.ipGroups))

	go listener.run()

	return listener, nil
}

func openAdoptionHandle(deviceName, ifaceName string) (*pcap.Handle, error) {
	handle, err := openCaptureHandle(deviceName, ifaceName, "adoption listener", 0, adoptionListenerReadTimeout)
	if err != nil {
		return nil, err
	}
	_ = handle.SetDirection(pcap.DirectionIn)
	return handle, nil
}

func openCaptureHandle(deviceName, ifaceName, purpose string, bufferSize int, readTimeout time.Duration) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(deviceName)
	if err == nil {
		defer inactive.CleanUp()

		if err := inactive.SetSnapLen(adoptionListenerSnapLen); err == nil {
			if err := inactive.SetPromisc(true); err == nil {
				if err := inactive.SetTimeout(readTimeout); err == nil {
					if bufferSize > 0 {
						_ = inactive.SetBufferSize(bufferSize)
					}
					_ = inactive.SetImmediateMode(true)
					handle, err := inactive.Activate()
					if err == nil {
						return handle, nil
					}
				}
			}
		}
	}

	handle, err := pcap.OpenLive(deviceName, adoptionListenerSnapLen, true, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("open %s on %s: %w", purpose, ifaceName, err)
	}

	return handle, nil
}

func (listener *pcapAdoptionListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		listener.stopAllRecorders()
		listener.stopAllTCPServices()
		listener.closeAllNetstacks()
		<-listener.done
	})

	return nil
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
	groups, _ := listener.groupsV.Load().([]*adoptedEngineGroup)

	merged := make(map[string]adoption.ARPCacheItem)
	for _, group := range groups {
		for _, item := range group.arpCacheSnapshot() {
			if item.IP == "" || item.MAC == "" {
				continue
			}
			if existing, exists := merged[item.IP]; !exists || existing.UpdatedAt == "" {
				merged[item.IP] = item
			}
		}
	}

	items := make([]adoption.ARPCacheItem, 0, len(merged))
	for _, item := range merged {
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].IP < items[j].IP
	})

	return items
}

func (listener *pcapAdoptionListener) EnsureIdentity(identity adoption.Identity) error {
	if identity == nil {
		return nil
	}

	_, err := listener.engineGroupForIdentity(identity)
	return err
}

func (listener *pcapAdoptionListener) InjectFrame(frame []byte) error {
	info, ok := classifyInboundFrame(frame)
	listener.injectLocalFrame(frame, info, ok)
	return nil
}

func (listener *pcapAdoptionListener) RouteFrame(via adoption.Identity, route routingpkg.StoredRoute, frame []byte) error {
	if listener == nil || via == nil {
		return nil
	}
	if len(frame) < header.EthernetMinimumSize {
		return nil
	}

	group, err := listener.engineGroupForIdentity(via)
	if err != nil {
		return err
	}

	outbound := listener.takeFrameBuffer(len(frame))
	outbound = append(outbound[:0], frame...)
	defer listener.releaseFrameBuffer(outbound[:0])

	if route.ScriptName != "" {
		mutablePacket, err := scriptpkg.NewMutablePacket(outbound)
		if err != nil {
			return err
		}
		defer mutablePacket.Release()

		if err := listener.applyMutableScriptByName(mutablePacket, route.ScriptName, buildRoutedPacketScript(via, route)); err != nil {
			return err
		}
		outbound = mutablePacket.Bytes()
	}

	ipv4Header, destinationIP, err := parseRoutedIPv4Frame(outbound)
	if err != nil {
		return err
	}
	nextHopIP, err := routeNextHop(listener.routes, via.DefaultGateway(), destinationIP)
	if err != nil {
		return err
	}
	nextHopMAC, err := listener.resolveRoutePeerMAC(group, via, nextHopIP)
	if err != nil {
		return err
	}
	if err := rewriteForwardedIPv4Frame(outbound, ipv4Header, via.MAC(), nextHopMAC); err != nil {
		return err
	}

	return listener.writePacket(outbound)
}

func (listener *pcapAdoptionListener) StartRecording(source adoption.Identity, outputPath string) (adoption.PacketRecordingStatus, error) {
	key := recordingKey(source.IP())
	if key == "" {
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording requires a valid IPv4 identity")
	}

	listener.recordersMu.Lock()
	if listener.recorders == nil {
		listener.recorders = make(map[string]*packetRecorder)
	}
	existing := listener.recorders[key]
	if snapshot := existing.snapshot(); snapshot != nil && snapshot.Active {
		listener.recordersMu.Unlock()
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording is already active for %s", key)
	}
	listener.recordersMu.Unlock()

	recorder, err := startPacketRecorder(listener.deviceName, listener.iface.Name, source, outputPath)
	if err != nil {
		return adoption.PacketRecordingStatus{}, err
	}

	listener.recordersMu.Lock()
	if previous := listener.recorders[key]; previous != nil {
		go previous.close()
	}
	listener.recorders[key] = recorder
	listener.recordersMu.Unlock()

	snapshot := recorder.snapshot()
	if snapshot == nil {
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording for %s did not start", key)
	}

	return *snapshot, nil
}

func (listener *pcapAdoptionListener) StopRecording(ip net.IP) error {
	key := recordingKey(ip)
	if key == "" {
		return nil
	}

	listener.recordersMu.Lock()
	recorder := listener.recorders[key]
	delete(listener.recorders, key)
	listener.recordersMu.Unlock()

	if recorder != nil {
		recorder.close()
	}

	return nil
}

func (listener *pcapAdoptionListener) RecordingSnapshot(ip net.IP) *adoption.PacketRecordingStatus {
	key := recordingKey(ip)
	if key == "" {
		return nil
	}

	listener.recordersMu.RLock()
	recorder := listener.recorders[key]
	listener.recordersMu.RUnlock()

	return recorder.snapshot()
}

func (listener *pcapAdoptionListener) ForgetIdentity(ip net.IP) {
	listener.forgetIdentity(ip)
}

func (listener *pcapAdoptionListener) stopAllRecorders() {
	listener.recordersMu.Lock()
	recorders := make([]*packetRecorder, 0, len(listener.recorders))
	for key, recorder := range listener.recorders {
		delete(listener.recorders, key)
		if recorder != nil {
			recorders = append(recorders, recorder)
		}
	}
	listener.recordersMu.Unlock()

	for _, recorder := range recorders {
		recorder.close()
	}
}

func (listener *pcapAdoptionListener) stopAllTCPServices() {
	for _, service := range listener.takeTCPServices(nil) {
		service.stop()
	}
}

func (listener *pcapAdoptionListener) closeAllNetstacks() {
	listener.stackMu.Lock()
	groups := make([]*adoptedEngineGroup, 0, len(listener.groups))
	for key, group := range listener.groups {
		delete(listener.groups, key)
		if group != nil {
			groups = append(groups, group)
		}
	}
	listener.ipGroups = make(map[compactIPv4]*adoptedEngineGroup)
	listener.publishGroupSnapshotLocked()
	listener.stackMu.Unlock()

	for _, group := range groups {
		group.close()
	}
}

func (listener *pcapAdoptionListener) forgetIdentity(ip net.IP) {
	key := compactIPv4FromIP(ip)
	if !key.valid {
		return
	}

	for _, service := range listener.takeTCPServices(ip) {
		service.stop()
	}

	var toClose *adoptedEngineGroup

	listener.stackMu.Lock()
	group := listener.ipGroups[key]
	delete(listener.ipGroups, key)
	if group != nil {
		group.removeIdentity(ip)
		if group.empty() {
			delete(listener.groups, group.key.value)
			toClose = group
		}
	}
	listener.publishGroupSnapshotLocked()
	listener.stackMu.Unlock()

	if toClose != nil {
		toClose.close()
	}
}

func (listener *pcapAdoptionListener) engineGroupForIdentity(identity adoption.Identity) (*adoptedEngineGroup, error) {
	if identity == nil {
		return nil, fmt.Errorf("netstack requires an identity")
	}

	ipKey := compactIPv4FromIP(identity.IP())
	if !ipKey.valid {
		return nil, fmt.Errorf("netstack requires a valid IPv4 identity")
	}

	groupKey := newAdoptedEngineKey(identity, listener.routes)

	ipGroups := listener.currentIPGroups()
	existing := ipGroups[ipKey]

	var suspendedServices []*managedTCPService
	if existing != nil && existing.key.value != groupKey.value {
		suspendedServices = listener.takeTCPServices(identity.IP())
		for _, service := range suspendedServices {
			service.stop()
		}
	}

	listener.stackMu.Lock()
	existing = listener.ipGroups[ipKey]
	if existing != nil && existing.key.value == groupKey.value {
		if err := existing.addIdentity(identity); err != nil {
			listener.publishGroupSnapshotLocked()
			listener.stackMu.Unlock()
			listener.restoreTCPServices(identity, existing, suspendedServices)
			return nil, err
		}
		listener.ipGroups[ipKey] = existing
		listener.publishGroupSnapshotLocked()
		listener.stackMu.Unlock()
		listener.restoreTCPServices(identity, existing, suspendedServices)
		return existing, nil
	}

	group := listener.groups[groupKey.value]
	created := false
	if group == nil {
		newGroup, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
			ifaceName:      listener.iface.Name,
			mac:            identity.MAC(),
			defaultGateway: identity.DefaultGateway(),
			routes:         listener.routes,
		}, listener.handleEngineGroupOutbound)
		if err != nil {
			listener.publishGroupSnapshotLocked()
			listener.stackMu.Unlock()
			listener.restoreTCPServices(identity, existing, suspendedServices)
			return nil, err
		}
		newGroup.key = groupKey
		group = newGroup
		created = true
	}

	if err := group.addIdentity(identity); err != nil {
		listener.publishGroupSnapshotLocked()
		listener.stackMu.Unlock()
		if created {
			group.close()
		}
		listener.restoreTCPServices(identity, existing, suspendedServices)
		return nil, err
	}

	if created {
		listener.groups[groupKey.value] = group
	}
	listener.ipGroups[ipKey] = group

	var toClose *adoptedEngineGroup
	if existing != nil {
		existing.removeIdentity(identity.IP())
		if existing.empty() {
			delete(listener.groups, existing.key.value)
			toClose = existing
		}
	}

	listener.publishGroupSnapshotLocked()
	listener.stackMu.Unlock()
	if toClose != nil {
		toClose.close()
	}
	listener.restoreTCPServices(identity, group, suspendedServices)
	return group, nil
}

func (listener *pcapAdoptionListener) publishGroupSnapshotLocked() {
	groups := make([]*adoptedEngineGroup, 0, len(listener.groups))
	for _, group := range listener.groups {
		if group != nil {
			groups = append(groups, group)
		}
	}
	listener.groupsV.Store(groups)
	ipGroups := cloneEngineGroupMap(listener.ipGroups)
	listener.ipGroupsV.Store(ipGroups)
	listener.applyCaptureFilter(buildAdoptionCaptureBPFFilter(groups, ipGroups))
}

func recordingKey(ip net.IP) string {
	normalized := common.NormalizeIPv4(ip)
	if normalized == nil {
		return ""
	}

	return normalized.String()
}

func (listener *pcapAdoptionListener) takeFrameBuffer(minSize int) []byte {
	if frame, _ := listener.frameBufferPool.Get().([]byte); cap(frame) >= minSize {
		return frame[:0]
	}

	if minSize <= 0 {
		minSize = 2048
	}
	return make([]byte, 0, minSize)
}

func (listener *pcapAdoptionListener) releaseFrameBuffer(frame []byte) {
	if frame == nil {
		return
	}

	listener.frameBufferPool.Put(frame[:0])
}

func (listener *pcapAdoptionListener) Ping(source adoption.Identity, targetIP net.IP, count int, payload []byte) (adoption.PingAdoptedIPAddressResult, error) {
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

	group, err := listener.engineGroupForIdentity(source)
	if err != nil {
		return result, err
	}

	replies, err := group.ping(source.IP(), targetIP, count, payload, pingReplyTimeout)
	for _, reply := range replies {
		result.Sent++
		item := adoption.PingAdoptedIPAddressReply{
			Sequence: int(reply.sequence),
			Success:  reply.success,
		}
		if reply.success {
			item.RTTMillis = float64(reply.rtt) / float64(time.Millisecond)
			result.Received++
		}
		result.Replies = append(result.Replies, item)
	}

	if err != nil {
		return result, err
	}

	return result, nil
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

func (listener *pcapAdoptionListener) run() {
	var runErr error

	defer listener.setRunErr(runErr)
	defer close(listener.done)
	if listener.handle != nil {
		defer listener.handle.Close()
	}

	for {
		select {
		case <-listener.stop:
			return
		default:
		}

		listener.handleMu.RLock()
		handle := listener.handle
		if handle == nil {
			listener.handleMu.RUnlock()
			runErr = adoption.ErrListenerStopped
			return
		}
		frame, _, err := handle.ZeroCopyReadPacketData()
		listener.handleMu.RUnlock()
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

		listener.dispatchInboundFrame(frame)
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

func (listener *pcapAdoptionListener) dispatchInboundFrame(frame []byte) {
	if len(frame) < header.EthernetMinimumSize {
		return
	}

	info, ok := classifyInboundFrame(frame)
	if listener.injectLocalFrame(frame, info, ok) {
		return
	}

	eth := header.Ethernet(frame)
	if eth.Type() != header.IPv4ProtocolNumber || !ok || listener.forward == nil {
		return
	}

	decision, exists := listener.forward(info.targetIP.IP())
	if !exists || decision.Listener == nil {
		return
	}

	if decision.Routed {
		_ = decision.Listener.RouteFrame(decision.Identity, decision.Route, frame)
		return
	}

	_ = decision.Listener.InjectFrame(frame)
}

func (listener *pcapAdoptionListener) injectLocalFrame(frame []byte, info inboundFrameInfo, classified bool) bool {
	if len(frame) < header.EthernetMinimumSize {
		return false
	}

	if classified {
		ipGroups := listener.currentIPGroups()
		group := ipGroups[info.targetIP]
		if group != nil {
			group.rememberPeer(info.sourceIP, info.sourceMAC)
			group.injectFrame(frame)
			return true
		}
	}

	eth := header.Ethernet(frame)
	if eth.DestinationAddress() != header.EthernetBroadcastAddress {
		return false
	}

	groups, _ := listener.groupsV.Load().([]*adoptedEngineGroup)
	for _, group := range groups {
		if group == nil {
			continue
		}
		group.injectFrame(frame)
	}
	return true
}

func cloneEngineGroupMap(items map[compactIPv4]*adoptedEngineGroup) map[compactIPv4]*adoptedEngineGroup {
	cloned := make(map[compactIPv4]*adoptedEngineGroup, len(items))
	for key, value := range items {
		cloned[key] = value
	}
	return cloned
}

func (listener *pcapAdoptionListener) currentIPGroups() map[compactIPv4]*adoptedEngineGroup {
	ipGroups, _ := listener.ipGroupsV.Load().(map[compactIPv4]*adoptedEngineGroup)
	if ipGroups != nil {
		return ipGroups
	}

	listener.stackMu.RLock()
	defer listener.stackMu.RUnlock()
	return listener.ipGroups
}

func buildAdoptionCaptureBPFFilter(groups []*adoptedEngineGroup, ipGroups map[compactIPv4]*adoptedEngineGroup) string {
	if len(ipGroups) == 0 && len(groups) == 0 {
		return emptyAdoptionCaptureBPFFilter
	}

	ips := make([]compactIPv4, 0, len(ipGroups))
	for key := range ipGroups {
		if key.valid {
			ips = append(ips, key)
		}
	}
	macs := make([]compactMAC, 0, len(groups))
	seenMACs := make(map[compactMAC]struct{}, len(groups))
	for _, group := range groups {
		if group == nil {
			continue
		}
		mac := compactMACFromSlice(group.config.mac)
		if !mac.valid {
			continue
		}
		if _, exists := seenMACs[mac]; exists {
			continue
		}
		seenMACs[mac] = struct{}{}
		macs = append(macs, mac)
	}

	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i].addr[:], ips[j].addr[:]) < 0
	})
	sort.Slice(macs, func(i, j int) bool {
		return bytes.Compare(macs[i].addr[:], macs[j].addr[:]) < 0
	})

	clauses := make([]string, 0, 3)
	if len(ips) > 0 {
		var arpTargets strings.Builder
		var ipTargets strings.Builder
		for index, ip := range ips {
			ipText := ip.IP().String()
			if index > 0 {
				arpTargets.WriteString(" or ")
				ipTargets.WriteString(" or ")
			}
			arpTargets.WriteString("arp dst host ")
			arpTargets.WriteString(ipText)
			ipTargets.WriteString("dst host ")
			ipTargets.WriteString(ipText)
		}
		clauses = append(clauses,
			fmt.Sprintf("(arp and (%s))", arpTargets.String()),
			fmt.Sprintf("(ip and (%s))", ipTargets.String()),
		)
	}
	if len(macs) > 0 {
		var macTargets strings.Builder
		for index, mac := range macs {
			if index > 0 {
				macTargets.WriteString(" or ")
			}
			macTargets.WriteString("ether dst host ")
			macTargets.WriteString(mac.HardwareAddr().String())
		}
		clauses = append(clauses, fmt.Sprintf("(%s)", macTargets.String()))
	}
	if len(clauses) == 0 {
		return emptyAdoptionCaptureBPFFilter
	}

	return strings.Join(clauses, " or ")
}

func (listener *pcapAdoptionListener) applyCaptureFilter(filter string) {
	if listener == nil {
		return
	}
	if filter == "" {
		filter = emptyAdoptionCaptureBPFFilter
	}

	listener.handleMu.Lock()
	defer listener.handleMu.Unlock()

	if filter == listener.captureFilter {
		return
	}
	if listener.handle == nil {
		listener.captureFilter = filter
		return
	}
	if err := listener.handle.SetBPFFilter(filter); err != nil {
		return
	}

	listener.captureFilter = filter
}

func classifyInboundFrame(frame []byte) (inboundFrameInfo, bool) {
	if len(frame) < header.EthernetMinimumSize {
		return inboundFrameInfo{}, false
	}

	ethernet := header.Ethernet(frame)
	payload := frame[header.EthernetMinimumSize:]

	switch ethernet.Type() {
	case header.ARPProtocolNumber:
		if len(payload) < header.ARPSize {
			return inboundFrameInfo{}, false
		}
		arp := header.ARP(payload)
		if !arp.IsValid() {
			return inboundFrameInfo{}, false
		}

		info := inboundFrameInfo{
			sourceIP:  compactIPv4FromSlice(arp.ProtocolAddressSender()),
			targetIP:  compactIPv4FromSlice(arp.ProtocolAddressTarget()),
			sourceMAC: compactMACFromSlice(arp.HardwareAddressSender()),
		}
		return info, info.sourceIP.valid && info.targetIP.valid && info.sourceMAC.valid

	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(payload)
		if !ipv4.IsValid(len(payload)) {
			return inboundFrameInfo{}, false
		}

		sourceAddr := ipv4.SourceAddress().As4()
		targetAddr := ipv4.DestinationAddress().As4()
		info := inboundFrameInfo{
			sourceIP:  compactIPv4FromSlice(sourceAddr[:]),
			targetIP:  compactIPv4FromSlice(targetAddr[:]),
			sourceMAC: compactMACFromSlice([]byte(ethernet.SourceAddress())),
		}
		return info, info.sourceIP.valid && info.targetIP.valid && info.sourceMAC.valid
	}

	return inboundFrameInfo{}, false
}

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	if listener == nil {
		return nil
	}

	listener.handleMu.RLock()
	handle := listener.handle
	if handle == nil {
		listener.handleMu.RUnlock()
		return adoption.ErrListenerStopped
	}
	defer listener.handleMu.RUnlock()

	listener.writeMu.Lock()
	defer listener.writeMu.Unlock()

	return handle.WritePacketData(frame)
}

func buildBoundPacketScript(identity adoption.Identity) scriptpkg.ExecutionContext {
	return buildPacketScriptContext(identity, identity.ScriptName(), nil)
}

func buildRoutedPacketScript(identity adoption.Identity, route routingpkg.StoredRoute) scriptpkg.ExecutionContext {
	return buildPacketScriptContext(identity, route.ScriptName, map[string]any{
		"stage": "routing",
		"route": map[string]any{
			"label":           route.Label,
			"destinationCIDR": route.DestinationCIDR,
			"viaAdoptedIP":    route.ViaAdoptedIP,
		},
	})
}

func buildPacketScriptContext(identity adoption.Identity, scriptName string, metadata map[string]any) scriptpkg.ExecutionContext {
	scriptName = strings.TrimSpace(scriptName)
	if scriptName == "" {
		return scriptpkg.ExecutionContext{}
	}

	return scriptpkg.ExecutionContext{
		ScriptName: scriptName,
		Adopted:    buildExecutionIdentity(identity),
		Metadata:   metadata,
	}
}

func buildExecutionIdentity(identity adoption.Identity) scriptpkg.ExecutionIdentity {
	if identity == nil {
		return scriptpkg.ExecutionIdentity{}
	}

	return scriptpkg.ExecutionIdentity{
		Label:          identity.Label(),
		IP:             identity.IP().String(),
		MAC:            identity.MAC().String(),
		InterfaceName:  identity.Interface().Name,
		DefaultGateway: common.IPString(identity.DefaultGateway()),
	}
}

func parseRoutedIPv4Frame(frame []byte) (header.IPv4, net.IP, error) {
	if len(frame) < header.EthernetMinimumSize {
		return nil, nil, fmt.Errorf("routed frame is too short")
	}

	eth := header.Ethernet(frame)
	if eth.Type() != header.IPv4ProtocolNumber {
		return nil, nil, fmt.Errorf("routing requires an IPv4 frame")
	}

	payload := frame[header.EthernetMinimumSize:]
	ipv4Header := header.IPv4(payload)
	if !ipv4Header.IsValid(len(payload)) {
		return nil, nil, fmt.Errorf("routed frame contains an invalid IPv4 packet")
	}

	destinationAddr := ipv4Header.DestinationAddress().As4()
	destinationIP := net.IPv4(destinationAddr[0], destinationAddr[1], destinationAddr[2], destinationAddr[3]).To4()
	return ipv4Header, destinationIP, nil
}

func routeNextHop(routes []net.IPNet, defaultGateway, destinationIP net.IP) (net.IP, error) {
	destinationIP = common.NormalizeIPv4(destinationIP)
	if destinationIP == nil {
		return nil, fmt.Errorf("a routed IPv4 destination is required")
	}

	for _, route := range routes {
		if route.Contains(destinationIP) {
			return common.CloneIPv4(destinationIP), nil
		}
	}

	defaultGateway = common.NormalizeIPv4(defaultGateway)
	if defaultGateway == nil {
		return nil, fmt.Errorf("no next hop is available for %s", destinationIP.String())
	}

	return defaultGateway, nil
}

func rewriteForwardedIPv4Frame(frame []byte, ipv4Header header.IPv4, sourceMAC, destinationMAC net.HardwareAddr) error {
	if len(frame) < header.EthernetMinimumSize {
		return fmt.Errorf("forwarded frame is too short")
	}
	if len(ipv4Header) == 0 {
		return fmt.Errorf("forwarded frame requires an IPv4 header")
	}
	if len(sourceMAC) == 0 || len(destinationMAC) == 0 {
		return fmt.Errorf("forwarded frame requires source and destination MAC addresses")
	}

	if ipv4Header.TTL() <= 1 {
		return fmt.Errorf("forwarded frame TTL expired")
	}

	copy(frame[:6], destinationMAC)
	copy(frame[6:12], sourceMAC)
	ipv4Header.SetTTL(ipv4Header.TTL() - 1)
	ipv4Header.SetChecksum(0)
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())
	return nil
}

func (listener *pcapAdoptionListener) resolveRoutePeerMAC(group *adoptedEngineGroup, via adoption.Identity, nextHopIP net.IP) (net.HardwareAddr, error) {
	nextHopIP = common.NormalizeIPv4(nextHopIP)
	if group == nil || via == nil || nextHopIP == nil {
		return nil, fmt.Errorf("next hop resolution requires a valid routed identity and IPv4 target")
	}

	deadline := time.Now().Add(routeARPResolveTimeout)
	lastRequest := time.Time{}
	for {
		if mac, exists := group.peerMAC(nextHopIP); exists {
			return mac, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("route next hop %s did not resolve", nextHopIP.String())
		}
		if lastRequest.IsZero() || time.Since(lastRequest) >= routeARPRequestInterval {
			if err := listener.requestRoutePeerMAC(via, nextHopIP); err != nil {
				return nil, err
			}
			lastRequest = time.Now()
		}
		time.Sleep(routeARPResolvePollInterval)
	}
}

func (listener *pcapAdoptionListener) requestRoutePeerMAC(via adoption.Identity, nextHopIP net.IP) error {
	packet := packetpkg.BuildARPRequestPacket(via.IP(), via.MAC(), nextHopIP)
	buffer := gopacket.NewSerializeBuffer()
	if err := packet.SerializeValidatedInto(buffer); err != nil {
		return err
	}
	return listener.writePacket(buffer.Bytes())
}
