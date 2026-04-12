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

type boundPacketScript struct {
	ctx scriptpkg.ExecutionContext
}

type inboundFrameInfo struct {
	protocol  string
	sourceIP  net.IP
	targetIP  net.IP
	sourceMAC net.HardwareAddr
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
	ipGroups map[string]*adoptedEngineGroup
	groupsV  atomic.Value

	recordersMu sync.RWMutex
	recorders   map[string]*packetRecorder

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
		ipGroups:      make(map[string]*adoptedEngineGroup),
		recorders:     make(map[string]*packetRecorder),
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

func (listener *pcapAdoptionListener) closeAllNetstacks() {
	listener.stackMu.Lock()
	groups := make([]*adoptedEngineGroup, 0, len(listener.groups))
	for key, group := range listener.groups {
		delete(listener.groups, key)
		if group != nil {
			groups = append(groups, group)
		}
	}
	listener.ipGroups = make(map[string]*adoptedEngineGroup)
	listener.publishGroupSnapshotLocked()
	listener.stackMu.Unlock()

	for _, group := range groups {
		group.close()
	}
}

func (listener *pcapAdoptionListener) forgetIdentity(ip net.IP) {
	key := recordingKey(ip)
	if key == "" {
		return
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

	ipKey := recordingKey(identity.IP())
	if ipKey == "" {
		return nil, fmt.Errorf("netstack requires a valid IPv4 identity")
	}

	groupKey := newAdoptedEngineKey(identity, listener.routes)

	var toClose *adoptedEngineGroup

	listener.stackMu.Lock()
	defer func() {
		listener.publishGroupSnapshotLocked()
		listener.stackMu.Unlock()
		if toClose != nil {
			toClose.close()
		}
	}()

	existing := listener.ipGroups[ipKey]
	if existing != nil && existing.key.value == groupKey.value {
		if err := existing.addIdentity(identity); err != nil {
			return nil, err
		}
		listener.ipGroups[ipKey] = existing
		return existing, nil
	}

	if existing != nil {
		existing.removeIdentity(identity.IP())
		delete(listener.ipGroups, ipKey)
		if existing.empty() {
			delete(listener.groups, existing.key.value)
			toClose = existing
		}
	}

	group := listener.groups[groupKey.value]
	if group == nil {
		created, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
			ifaceName:      listener.iface.Name,
			mac:            identity.MAC(),
			defaultGateway: identity.DefaultGateway(),
			routes:         listener.routes,
		}, listener.handleEngineGroupOutbound)
		if err != nil {
			return nil, err
		}
		created.key = groupKey
		listener.groups[groupKey.value] = created
		group = created
	}

	if err := group.addIdentity(identity); err != nil {
		if group.empty() {
			delete(listener.groups, groupKey.value)
			toClose = group
		}
		return nil, err
	}

	listener.ipGroups[ipKey] = group
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
	if len(frame) == 0 {
		return
	}

	groups := listener.recipientGroupsForFrame(frame)
	if len(groups) == 0 {
		return
	}

	for _, group := range groups {
		if group == nil {
			continue
		}

		owned := listener.takeFrameBuffer(len(frame))
		owned = append(owned[:0], frame...)
		group.injectOwnedFrame(owned, func() {
			listener.releaseFrameBuffer(owned)
		})
	}
}

func (listener *pcapAdoptionListener) recipientGroupsForFrame(frame []byte) []*adoptedEngineGroup {
	if len(frame) < header.EthernetMinimumSize {
		return nil
	}

	if info, ok := classifyInboundFrame(frame); ok && common.NormalizeIPv4(info.targetIP) != nil {
		key := recordingKey(info.targetIP)
		listener.stackMu.RLock()
		group := listener.ipGroups[key]
		listener.stackMu.RUnlock()
		if group != nil {
			return []*adoptedEngineGroup{group}
		}
		return nil
	}

	eth := header.Ethernet(frame)
	if eth.DestinationAddress() != header.EthernetBroadcastAddress {
		return nil
	}

	groups, _ := listener.groupsV.Load().([]*adoptedEngineGroup)
	return groups
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

		targetIP := common.CloneIPv4(net.IP(arp.ProtocolAddressTarget()))
		if targetIP == nil {
			return inboundFrameInfo{}, false
		}

		return inboundFrameInfo{
			protocol:  "arp",
			sourceIP:  common.CloneIPv4(net.IP(arp.ProtocolAddressSender())),
			targetIP:  targetIP,
			sourceMAC: common.CloneHardwareAddr(net.HardwareAddr(arp.HardwareAddressSender())),
			arpOp:     arp.Op(),
		}, true

	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(payload)
		if !ipv4.IsValid(len(payload)) {
			return inboundFrameInfo{}, false
		}

		sourceAddr := ipv4.SourceAddress().As4()
		targetAddr := ipv4.DestinationAddress().As4()
		targetIP := common.CloneIPv4(net.IP(targetAddr[:]))
		if targetIP == nil {
			return inboundFrameInfo{}, false
		}

		info := inboundFrameInfo{
			protocol:  "ipv4",
			sourceIP:  common.CloneIPv4(net.IP(sourceAddr[:])),
			targetIP:  targetIP,
			sourceMAC: common.CloneHardwareAddr(net.HardwareAddr(ethernet.SourceAddress())),
		}

		if ipv4.TransportProtocol() != header.ICMPv4ProtocolNumber {
			return info, true
		}

		icmpPayload := ipv4.Payload()
		if len(icmpPayload) < header.ICMPv4MinimumSize {
			return info, true
		}

		icmp := header.ICMPv4(icmpPayload)
		info.protocol = "icmpv4"
		info.icmpType = icmp.Type()
		info.icmpID = icmp.Ident()
		info.icmpSeq = icmp.Sequence()
		return info, true
	}

	return inboundFrameInfo{}, false
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

func buildBoundPacketScript(identity adoption.Identity) boundPacketScript {
	scriptName := identity.ScriptName()
	if strings.TrimSpace(scriptName) == "" {
		return boundPacketScript{}
	}

	return boundPacketScript{
		ctx: scriptpkg.ExecutionContext{
			ScriptName: scriptName,
			Adopted: scriptpkg.ExecutionIdentity{
				Label:          identity.Label(),
				IP:             identity.IP().String(),
				MAC:            identity.MAC().String(),
				InterfaceName:  identity.Interface().Name,
				DefaultGateway: common.IPString(identity.DefaultGateway()),
			},
		},
	}
}
