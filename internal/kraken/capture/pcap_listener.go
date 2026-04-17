package capture

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	adoptionListenerSnapLen     = 65535
	adoptionListenerReadTimeout = 50 * time.Millisecond
	activityLogQueueDepth       = 1024
	pingReplyTimeout            = 3 * time.Second
)

type frameActivity struct {
	protocol  string
	sourceIP  compactIPv4
	targetIP  compactIPv4
	sourceMAC compactMAC
	targetMAC compactMAC
	arpOp     header.ARPOp
	icmpType  header.ICMPv4Type
	icmpID    uint16
	icmpSeq   uint16
}

type pcapAdoptionListener struct {
	handle        *pcap.Handle
	deviceName    string
	iface         net.Interface
	lookup        adoption.LookupFunc
	resolveScript adoption.ScriptLookupFunc
	routes        []net.IPNet

	writeMu         sync.Mutex
	frameBufferPool sync.Pool

	stackMu  sync.RWMutex
	groups   map[string]*adoptedEngineGroup
	ipGroups map[compactIPv4]*adoptedEngineGroup
	groupsV  atomic.Value

	recordersMu sync.RWMutex
	recorders   map[string]*packetRecorder

	servicesMu sync.RWMutex
	services   map[string]map[string]*managedTCPService

	activityQueue chan activityLogRecord
	activityStop  chan struct{}
	activityDone  chan struct{}

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	stateMu sync.RWMutex
	runErr  error
}

func NewListener(iface net.Interface, lookup adoption.LookupFunc, resolveScript adoption.ScriptLookupFunc) (adoption.Listener, error) {
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
		lookup:        lookup,
		resolveScript: resolveScript,
		routes:        interfaceIPv4Networks(iface),
		groups:        make(map[string]*adoptedEngineGroup),
		ipGroups:      make(map[compactIPv4]*adoptedEngineGroup),
		recorders:     make(map[string]*packetRecorder),
		services:      make(map[string]map[string]*managedTCPService),
		activityQueue: make(chan activityLogRecord, activityLogQueueDepth),
		activityStop:  make(chan struct{}),
		activityDone:  make(chan struct{}),
		frameBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, 0, 2048)
			},
		},
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	listener.groupsV.Store([]*adoptedEngineGroup(nil))

	go listener.runActivityWriter()
	go listener.run()

	return listener, nil
}

func openAdoptionHandle(deviceName, ifaceName string) (*pcap.Handle, error) {
	return openCaptureHandle(deviceName, ifaceName, "adoption listener", 0, adoptionListenerReadTimeout)
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
		close(listener.activityStop)
		<-listener.activityDone
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

	listener.stackMu.RLock()
	existing := listener.ipGroups[ipKey]
	listener.stackMu.RUnlock()

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
			listener.enqueueActivity(activityLogRecord{
				identity:  source,
				direction: "inbound",
				protocol:  "icmpv4",
				event:     "recv-echo-reply",
				status:    "received",
				peerIP:    compactIPv4FromIP(targetIP),
				icmpID:    reply.id,
				icmpSeq:   reply.sequence,
				rtt:       reply.rtt,
			})
		} else {
			listener.enqueueActivity(activityLogRecord{
				identity:  source,
				direction: "inbound",
				protocol:  "icmpv4",
				event:     "echo-timeout",
				status:    "timeout",
				peerIP:    compactIPv4FromIP(targetIP),
				icmpID:    reply.id,
				icmpSeq:   reply.sequence,
			})
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
	defer listener.handle.Close()

	for {
		select {
		case <-listener.stop:
			return
		default:
		}

		frame, _, err := listener.handle.ZeroCopyReadPacketData()
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

	if activity, ok := classifyFrameActivity(frame); ok && activity.targetIP.valid {
		listener.stackMu.RLock()
		group := listener.ipGroups[activity.targetIP]
		listener.stackMu.RUnlock()
		if group != nil {
			group.rememberPeer(activity.sourceIP, activity.sourceMAC)
			listener.enqueueInboundFrameActivity(group, activity)
			group.injectFrame(frame)
			return
		}
	}

	eth := header.Ethernet(frame)
	if eth.DestinationAddress() != header.EthernetBroadcastAddress {
		return
	}

	groups, _ := listener.groupsV.Load().([]*adoptedEngineGroup)
	for _, group := range groups {
		if group == nil {
			continue
		}
		group.injectFrame(frame)
	}
}

func (listener *pcapAdoptionListener) enqueueActivity(record activityLogRecord) {
	if listener == nil || record.identity == nil {
		return
	}

	select {
	case <-listener.activityStop:
		return
	default:
	}

	select {
	case listener.activityQueue <- record:
	default:
	}
}

func (listener *pcapAdoptionListener) runActivityWriter() {
	defer close(listener.activityDone)

	for {
		select {
		case record := <-listener.activityQueue:
			writeActivityRecord(record)
		case <-listener.activityStop:
			for {
				select {
				case record := <-listener.activityQueue:
					writeActivityRecord(record)
				default:
					return
				}
			}
		}
	}
}

func (listener *pcapAdoptionListener) enqueueInboundFrameActivity(group *adoptedEngineGroup, activity frameActivity) {
	if listener == nil || group == nil {
		return
	}

	identity, exists := group.identityForKey(activity.targetIP)
	if !exists {
		return
	}

	record, ok := activity.inboundRecord(identity)
	if !ok {
		return
	}

	listener.enqueueActivity(record)
}

func (listener *pcapAdoptionListener) enqueueOutboundFrameActivity(group *adoptedEngineGroup, frame []byte) {
	if listener == nil || group == nil {
		return
	}

	activity, ok := classifyFrameActivity(frame)
	if !ok {
		return
	}

	identity, exists := group.identityForKey(activity.sourceIP)
	if !exists {
		return
	}

	record, ok := activity.outboundRecord(identity)
	if !ok {
		return
	}

	listener.enqueueActivity(record)
}

func classifyFrameActivity(frame []byte) (frameActivity, bool) {
	if len(frame) < header.EthernetMinimumSize {
		return frameActivity{}, false
	}

	ethernet := header.Ethernet(frame)
	payload := frame[header.EthernetMinimumSize:]

	switch ethernet.Type() {
	case header.ARPProtocolNumber:
		if len(payload) < header.ARPSize {
			return frameActivity{}, false
		}
		arp := header.ARP(payload)
		if !arp.IsValid() {
			return frameActivity{}, false
		}

		activity := frameActivity{
			protocol:  "arp",
			sourceIP:  compactIPv4FromSlice(arp.ProtocolAddressSender()),
			targetIP:  compactIPv4FromSlice(arp.ProtocolAddressTarget()),
			sourceMAC: compactMACFromSlice(arp.HardwareAddressSender()),
			targetMAC: compactMACFromSlice(arp.HardwareAddressTarget()),
			arpOp:     arp.Op(),
		}
		return activity, activity.sourceIP.valid && activity.targetIP.valid

	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(payload)
		if !ipv4.IsValid(len(payload)) {
			return frameActivity{}, false
		}

		sourceAddr := ipv4.SourceAddress().As4()
		targetAddr := ipv4.DestinationAddress().As4()
		activity := frameActivity{
			protocol:  "ipv4",
			sourceIP:  compactIPv4FromSlice(sourceAddr[:]),
			targetIP:  compactIPv4FromSlice(targetAddr[:]),
			sourceMAC: compactMACFromSlice([]byte(ethernet.SourceAddress())),
			targetMAC: compactMACFromSlice([]byte(ethernet.DestinationAddress())),
		}
		if !activity.sourceIP.valid || !activity.targetIP.valid {
			return frameActivity{}, false
		}

		if ipv4.TransportProtocol() != header.ICMPv4ProtocolNumber {
			return activity, true
		}

		icmpPayload := ipv4.Payload()
		if len(icmpPayload) < header.ICMPv4MinimumSize {
			return activity, true
		}

		icmp := header.ICMPv4(icmpPayload)
		activity.protocol = "icmpv4"
		activity.icmpType = icmp.Type()
		activity.icmpID = icmp.Ident()
		activity.icmpSeq = icmp.Sequence()
		return activity, true
	}

	return frameActivity{}, false
}

func targetIPv4ForFrame(frame []byte) (compactIPv4, bool) {
	activity, ok := classifyFrameActivity(frame)
	if !ok || !activity.targetIP.valid {
		return compactIPv4{}, false
	}

	return activity.targetIP, true
}

func (activity frameActivity) inboundRecord(identity adoption.Identity) (activityLogRecord, bool) {
	if identity == nil {
		return activityLogRecord{}, false
	}

	switch activity.protocol {
	case "arp":
		event := ""
		switch activity.arpOp {
		case header.ARPRequest:
			event = "recv-request"
		case header.ARPReply:
			event = "recv-reply"
		default:
			return activityLogRecord{}, false
		}

		return activityLogRecord{
			identity:  identity,
			direction: "inbound",
			protocol:  "arp",
			event:     event,
			peerIP:    activity.sourceIP,
			peerMAC:   activity.sourceMAC,
		}, true

	case "icmpv4":
		event := ""
		switch activity.icmpType {
		case header.ICMPv4Echo:
			event = "recv-echo-request"
		case header.ICMPv4EchoReply:
			event = "recv-echo-reply"
		default:
			return activityLogRecord{}, false
		}

		return activityLogRecord{
			identity:  identity,
			direction: "inbound",
			protocol:  "icmpv4",
			event:     event,
			status:    "received",
			peerIP:    activity.sourceIP,
			icmpID:    activity.icmpID,
			icmpSeq:   activity.icmpSeq,
		}, true
	}

	return activityLogRecord{}, false
}

func (activity frameActivity) outboundRecord(identity adoption.Identity) (activityLogRecord, bool) {
	if identity == nil {
		return activityLogRecord{}, false
	}

	switch activity.protocol {
	case "arp":
		event := ""
		switch activity.arpOp {
		case header.ARPRequest:
			event = "send-request"
		case header.ARPReply:
			event = "send-reply"
		default:
			return activityLogRecord{}, false
		}

		return activityLogRecord{
			identity:  identity,
			direction: "outbound",
			protocol:  "arp",
			event:     event,
			peerIP:    activity.targetIP,
			peerMAC:   activity.targetMAC,
		}, true

	case "icmpv4":
		event := ""
		switch activity.icmpType {
		case header.ICMPv4Echo:
			event = "send-echo-request"
		case header.ICMPv4EchoReply:
			event = "send-echo-reply"
		default:
			return activityLogRecord{}, false
		}

		return activityLogRecord{
			identity:  identity,
			direction: "outbound",
			protocol:  "icmpv4",
			event:     event,
			status:    "sent",
			peerIP:    activity.targetIP,
			icmpID:    activity.icmpID,
			icmpSeq:   activity.icmpSeq,
		}, true
	}

	return activityLogRecord{}, false
}

func writeActivityRecord(record activityLogRecord) {
	if record.identity == nil || record.event == "" {
		return
	}

	switch record.protocol {
	case "arp":
		record.identity.RecordARP(record.direction, record.event, record.peerIP.IP(), record.peerMAC.HardwareAddr(), record.details)
	case "icmpv4":
		record.identity.RecordICMP(record.direction, record.event, record.peerIP.IP(), record.icmpID, record.icmpSeq, record.rtt, record.status, record.details)
	}
}

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	listener.writeMu.Lock()
	defer listener.writeMu.Unlock()

	return listener.handle.WritePacketData(frame)
}

func buildBoundPacketScript(identity adoption.Identity) scriptpkg.ExecutionContext {
	scriptName := identity.ScriptName()
	if strings.TrimSpace(scriptName) == "" {
		return scriptpkg.ExecutionContext{}
	}

	return scriptpkg.ExecutionContext{
		ScriptName: scriptName,
		Adopted: scriptpkg.ExecutionIdentity{
			Label:          identity.Label(),
			IP:             identity.IP().String(),
			MAC:            identity.MAC().String(),
			InterfaceName:  identity.Interface().Name,
			DefaultGateway: common.IPString(identity.DefaultGateway()),
		},
	}
}
