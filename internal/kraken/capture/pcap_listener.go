package capture

import (
	"bytes"
	"fmt"
	"io"
	"maps"
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

const inactiveAdoptionCaptureBPFFilter = "less 1"

type inboundFrameInfo struct {
	sourceIP  compactIPv4
	targetIP  compactIPv4
	sourceMAC compactMAC
}

type listenerMetrics struct {
	framesRead      atomic.Uint64
	localFrames     atomic.Uint64
	forwardedFrames atomic.Uint64
	routedFrames    atomic.Uint64
}

type pcapAdoptionListener struct {
	handle        *pcap.Handle
	deviceName    string
	iface         net.Interface
	forward       adoption.ForwardLookupFunc
	resolveScript adoption.ScriptLookupFunc
	routes        []net.IPNet

	captureFilter        string
	pendingCaptureFilter string
	filterLastError      string
	filterUpdatedAt      string
	filterMu             sync.Mutex
	captureFilterDirty   atomic.Bool
	writeMu              sync.Mutex
	frameBufferPool      sync.Pool
	metrics              listenerMetrics

	stackMu  sync.RWMutex
	engines  map[compactIPv4]*adoptedEngine
	enginesV atomic.Value

	recordersMu sync.RWMutex
	recorders   map[string]*packetRecorder

	scriptErrorsMu sync.RWMutex
	scriptErrors   map[string]adoption.ScriptRuntimeError

	servicesMu sync.RWMutex
	services   map[string]map[string]*managedService

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
		engines:       make(map[compactIPv4]*adoptedEngine),
		recorders:     make(map[string]*packetRecorder),
		scriptErrors:  make(map[string]adoption.ScriptRuntimeError),
		services:      make(map[string]map[string]*managedService),
		frameBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, 0, 2048)
			},
		},
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	listener.enginesV.Store(make(map[compactIPv4]*adoptedEngine))
	if err := listener.setCaptureFilter(buildAdoptionCaptureBPFFilter(listener.engines)); err != nil {
		handle.Close()
		return nil, err
	}
	listener.setCaptureDirection()

	go listener.run()

	return listener, nil
}

func openAdoptionHandle(deviceName, ifaceName string) (*pcap.Handle, error) {
	handle, err := openCaptureHandle(deviceName, ifaceName, "adoption listener", 0, adoptionListenerReadTimeout)
	if err != nil {
		return nil, err
	}
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
		listener.stopAllServices()
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
	engines := listener.currentEngines()

	merged := make(map[string]adoption.ARPCacheItem)
	for _, engine := range engines {
		for _, item := range engine.arpCacheSnapshot() {
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

func (listener *pcapAdoptionListener) StatusSnapshot(ip net.IP) adoption.ListenerStatus {
	return adoption.ListenerStatus{
		Capture:     listener.captureStatusSnapshot(),
		Metrics:     listener.metricsSnapshot(ip),
		ScriptError: listener.scriptRuntimeSnapshot(ip),
	}
}

func (listener *pcapAdoptionListener) captureStatusSnapshot() *adoption.CaptureStatus {
	if listener == nil {
		return nil
	}

	listener.filterMu.Lock()
	status := adoption.CaptureStatus{
		ActiveFilter:  listener.captureFilter,
		PendingFilter: listener.pendingCaptureFilter,
		LastError:     listener.filterLastError,
		UpdatedAt:     listener.filterUpdatedAt,
	}
	listener.filterMu.Unlock()

	if status.LastError == "" && status.PendingFilter == "" {
		return nil
	}
	return &status
}

func (listener *pcapAdoptionListener) metricsSnapshot(ip net.IP) *adoption.AdoptedIPMetrics {
	key := compactIPv4FromIP(ip)
	if listener == nil || !key.valid {
		return nil
	}

	metrics := adoption.AdoptedIPMetrics{
		FramesRead:      listener.metrics.framesRead.Load(),
		LocalFrames:     listener.metrics.localFrames.Load(),
		ForwardedFrames: listener.metrics.forwardedFrames.Load(),
		RouteHits:       listener.metrics.routedFrames.Load(),
	}

	engine := listener.currentEngines()[key]
	if engine != nil {
		engine.addMetricsSnapshot(&metrics)
	}
	metrics.ApplicationScriptErrors = listener.serviceApplicationScriptErrors(key.IP())
	if metrics == (adoption.AdoptedIPMetrics{}) {
		return nil
	}
	return &metrics
}

func (listener *pcapAdoptionListener) scriptRuntimeSnapshot(ip net.IP) *adoption.ScriptRuntimeError {
	key := recordingKey(ip)
	if listener == nil || key == "" {
		return nil
	}

	listener.scriptErrorsMu.RLock()
	item, exists := listener.scriptErrors[key]
	listener.scriptErrorsMu.RUnlock()
	if !exists || item.LastError == "" {
		return nil
	}
	return &item
}

func (listener *pcapAdoptionListener) EnsureIdentity(identity adoption.Identity) error {
	if identity == nil {
		return nil
	}

	listener.clearScriptRuntimeError(identity.IP())
	_, err := listener.engineForIdentity(identity)
	return err
}

func (listener *pcapAdoptionListener) InjectFrame(frame []byte) error {
	info, ok := classifyInboundFrame(frame)
	listener.injectLocalFrame(frame, info, ok, listener.currentEngines())
	return nil
}

func (listener *pcapAdoptionListener) RouteFrame(via adoption.Identity, route routingpkg.StoredRoute, frame []byte) error {
	if listener == nil || via == nil {
		return nil
	}
	if len(frame) < header.EthernetMinimumSize {
		return nil
	}

	engine, err := listener.engineForIdentity(via)
	if err != nil {
		return err
	}

	outbound := listener.takeFrameBuffer(len(frame))
	outbound = append(outbound[:0], frame...)
	defer listener.releaseFrameBuffer(outbound[:0])

	if err := listener.prepareRoutedFrame(engine, via, outbound); err != nil {
		return err
	}
	engine.metrics.routedFrames.Add(1)
	engine.metrics.outboundFrames.Add(1)

	if err := listener.emitPreparedFrame(outbound, buildRoutedTransportScript(via, route)); err != nil {
		engine.metrics.outboundWriteErrors.Add(1)
		return err
	}
	return nil
}

func (listener *pcapAdoptionListener) prepareRoutedFrame(engine *adoptedEngine, via adoption.Identity, outbound []byte) error {
	ipv4Header, destinationIP, err := parseRoutedIPv4Frame(outbound)
	if err != nil {
		return err
	}
	nextHopIP, err := routeNextHop(listener.routes, via.DefaultGateway(), destinationIP)
	if err != nil {
		return err
	}
	nextHopMAC, err := listener.resolveRoutePeerMAC(engine, via, nextHopIP)
	if err != nil {
		return err
	}
	if err := rewriteForwardedIPv4Frame(outbound, ipv4Header, via.MAC(), nextHopMAC); err != nil {
		return err
	}

	return nil
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

func (listener *pcapAdoptionListener) stopAllServices() {
	for _, service := range listener.takeServices(nil) {
		service.stop()
	}
}

func (listener *pcapAdoptionListener) closeAllNetstacks() {
	listener.stackMu.Lock()
	engines := make([]*adoptedEngine, 0, len(listener.engines))
	for key, engine := range listener.engines {
		delete(listener.engines, key)
		if engine != nil {
			engines = append(engines, engine)
		}
	}
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()

	for _, engine := range engines {
		engine.close()
	}
}

func (listener *pcapAdoptionListener) forgetIdentity(ip net.IP) {
	key := compactIPv4FromIP(ip)
	if !key.valid {
		return
	}

	for _, service := range listener.takeServices(ip) {
		service.stop()
	}

	var toClose *adoptedEngine

	listener.stackMu.Lock()
	engine := listener.engines[key]
	delete(listener.engines, key)
	if engine != nil {
		engine.removeIdentity(ip)
		if engine.identitySnapshot() == nil {
			toClose = engine
		}
	}
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()

	if toClose != nil {
		toClose.close()
	}
}

func (listener *pcapAdoptionListener) engineForIdentity(identity adoption.Identity) (*adoptedEngine, error) {
	if identity == nil {
		return nil, fmt.Errorf("netstack requires an identity")
	}

	ipKey := compactIPv4FromIP(identity.IP())
	if !ipKey.valid {
		return nil, fmt.Errorf("netstack requires a valid IPv4 identity")
	}

	var suspendedServices []*managedService
	existing := listener.currentEngines()[ipKey]
	if existing != nil && !existing.matchesIdentity(identity) {
		suspendedServices = listener.takeServices(identity.IP())
		for _, service := range suspendedServices {
			service.stop()
		}
	}

	listener.stackMu.Lock()
	existing = listener.engines[ipKey]
	if existing != nil && existing.matchesIdentity(identity) {
		if err := existing.addIdentity(identity); err != nil {
			listener.publishEngineSnapshotLocked()
			listener.stackMu.Unlock()
			listener.restoreServices(identity, existing, suspendedServices)
			return nil, err
		}
		listener.engines[ipKey] = existing
		listener.publishEngineSnapshotLocked()
		listener.stackMu.Unlock()
		listener.restoreServices(identity, existing, suspendedServices)
		return existing, nil
	}

	engine, err := newAdoptedEngine(adoptedEngineConfigForIdentity(identity, listener.routes), listener.handleEngineOutbound)
	if err != nil {
		listener.publishEngineSnapshotLocked()
		listener.stackMu.Unlock()
		listener.restoreServices(identity, existing, suspendedServices)
		return nil, err
	}
	if err := engine.addIdentity(identity); err != nil {
		listener.publishEngineSnapshotLocked()
		listener.stackMu.Unlock()
		engine.close()
		listener.restoreServices(identity, existing, suspendedServices)
		return nil, err
	}
	listener.engines[ipKey] = engine
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()
	if existing != nil {
		existing.close()
	}
	listener.restoreServices(identity, engine, suspendedServices)
	return engine, nil
}

func (listener *pcapAdoptionListener) publishEngineSnapshotLocked() {
	engines := maps.Clone(listener.engines)
	listener.enginesV.Store(engines)
	listener.applyCaptureFilter(buildAdoptionCaptureBPFFilter(engines))
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

	group, err := listener.engineForIdentity(source)
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
	handle := listener.handle
	if handle == nil {
		runErr = adoption.ErrListenerStopped
		return
	}
	defer handle.Close()

	for {
		select {
		case <-listener.stop:
			return
		default:
		}

		listener.flushCaptureFilter(handle)
		frame, _, err := handle.ZeroCopyReadPacketData()
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

		listener.metrics.framesRead.Add(1)
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

	engines := listener.currentEngines()
	info, ok := classifyInboundFrame(frame)
	if listener.injectLocalFrame(frame, info, ok, engines) {
		listener.metrics.localFrames.Add(1)
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
		listener.metrics.routedFrames.Add(1)
		_ = decision.Listener.RouteFrame(decision.Identity, decision.Route, frame)
		return
	}

	listener.metrics.forwardedFrames.Add(1)
	_ = decision.Listener.InjectFrame(frame)
}

func (listener *pcapAdoptionListener) injectLocalFrame(frame []byte, info inboundFrameInfo, classified bool, engines map[compactIPv4]*adoptedEngine) bool {
	if classified {
		engine := engines[info.targetIP]
		if engine != nil {
			engine.rememberPeer(info.sourceIP, info.sourceMAC)
			engine.injectFrame(frame)
			return true
		}
	}

	eth := header.Ethernet(frame)
	if eth.DestinationAddress() != header.EthernetBroadcastAddress {
		return false
	}

	for _, engine := range engines {
		engine.injectFrame(frame)
	}
	return true
}

func (listener *pcapAdoptionListener) currentEngines() map[compactIPv4]*adoptedEngine {
	engines, _ := listener.enginesV.Load().(map[compactIPv4]*adoptedEngine)
	if engines != nil {
		return engines
	}

	listener.stackMu.RLock()
	defer listener.stackMu.RUnlock()
	return listener.engines
}

func buildAdoptionCaptureBPFFilter(engines map[compactIPv4]*adoptedEngine) string {
	if len(engines) == 0 {
		return inactiveAdoptionCaptureBPFFilter
	}

	ips := make([]compactIPv4, 0, len(engines))
	for key := range engines {
		if key.valid {
			ips = append(ips, key)
		}
	}

	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i].addr[:], ips[j].addr[:]) < 0
	})

	clauses := make([]string, 0, 2)
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
	if len(clauses) == 0 {
		return inactiveAdoptionCaptureBPFFilter
	}

	return strings.Join(clauses, " or ")
}

func (listener *pcapAdoptionListener) applyCaptureFilter(filter string) {
	if listener == nil {
		return
	}
	if filter == "" {
		filter = inactiveAdoptionCaptureBPFFilter
	}

	listener.filterMu.Lock()
	if filter == listener.captureFilter || filter == listener.pendingCaptureFilter {
		listener.filterMu.Unlock()
		return
	}
	listener.pendingCaptureFilter = filter
	listener.captureFilterDirty.Store(true)
	listener.filterMu.Unlock()
}

func (listener *pcapAdoptionListener) setCaptureFilter(filter string) error {
	if listener == nil {
		return nil
	}
	if filter == "" {
		filter = inactiveAdoptionCaptureBPFFilter
	}
	if listener.handle != nil {
		if err := listener.handle.SetBPFFilter(filter); err != nil {
			listener.recordCaptureError(filter, err)
			return fmt.Errorf("set adoption capture filter: %w", err)
		}
	}
	listener.filterMu.Lock()
	listener.captureFilter = filter
	listener.pendingCaptureFilter = ""
	listener.filterLastError = ""
	listener.filterUpdatedAt = ""
	listener.captureFilterDirty.Store(false)
	listener.filterMu.Unlock()
	return nil
}

func (listener *pcapAdoptionListener) flushCaptureFilter(handle *pcap.Handle) {
	if listener == nil || handle == nil || !listener.captureFilterDirty.Load() {
		return
	}

	listener.filterMu.Lock()
	defer listener.filterMu.Unlock()

	filter := listener.pendingCaptureFilter
	if filter == "" || filter == listener.captureFilter {
		listener.pendingCaptureFilter = ""
		listener.captureFilterDirty.Store(false)
		return
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		listener.filterLastError = err.Error()
		listener.filterUpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		listener.pendingCaptureFilter = ""
		listener.captureFilterDirty.Store(false)
		return
	}

	listener.captureFilter = filter
	listener.pendingCaptureFilter = ""
	listener.filterLastError = ""
	listener.filterUpdatedAt = ""
	listener.captureFilterDirty.Store(false)
}

func (listener *pcapAdoptionListener) setCaptureDirection() {
	if listener == nil || listener.handle == nil {
		return
	}
	if err := listener.handle.SetDirection(pcap.DirectionIn); err != nil {
		listener.recordCaptureError("", fmt.Errorf("set adoption capture direction on %s: %w", listener.iface.Name, err))
	}
}

func (listener *pcapAdoptionListener) recordCaptureError(filter string, err error) {
	if listener == nil || err == nil {
		return
	}

	listener.filterMu.Lock()
	if filter != "" {
		listener.pendingCaptureFilter = filter
	}
	listener.filterLastError = err.Error()
	listener.filterUpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	listener.captureFilterDirty.Store(false)
	listener.filterMu.Unlock()
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
			sourceMAC: compactMACFromSlice(frame[6:header.EthernetMinimumSize]),
		}
		return info, info.sourceIP.valid && info.targetIP.valid && info.sourceMAC.valid
	}

	return inboundFrameInfo{}, false
}

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	if listener == nil {
		return nil
	}

	handle := listener.handle
	if handle == nil {
		return adoption.ErrListenerStopped
	}

	listener.writeMu.Lock()
	defer listener.writeMu.Unlock()

	return handle.WritePacketData(frame)
}

func buildBoundTransportScript(identity adoption.Identity) scriptpkg.ExecutionContext {
	return buildPacketScriptContext(identity, identity.TransportScriptName(), map[string]any{
		"direction": "outbound",
		"handler":   "transport",
	})
}

func buildRoutedTransportScript(identity adoption.Identity, route routingpkg.StoredRoute) scriptpkg.ExecutionContext {
	return buildPacketScriptContext(identity, route.TransportScriptName, map[string]any{
		"stage":     "routing",
		"direction": "outbound",
		"handler":   "transport",
		"route": map[string]any{
			"label":               route.Label,
			"destinationCIDR":     route.DestinationCIDR,
			"viaAdoptedIP":        route.ViaAdoptedIP,
			"transportScriptName": route.TransportScriptName,
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
		MTU:            int(identity.MTU()),
	}
}

func (listener *pcapAdoptionListener) recordTransportScriptError(ctx scriptpkg.ExecutionContext, err error) {
	if listener == nil || err == nil || ctx.Adopted.IP == "" {
		return
	}

	key := ctx.Adopted.IP
	item := adoption.ScriptRuntimeError{
		ScriptName: strings.TrimSpace(ctx.ScriptName),
		Surface:    string(scriptpkg.SurfaceTransport),
		LastError:  err.Error(),
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if stage, ok := ctx.Metadata["stage"].(string); ok {
		item.Stage = stage
	}
	if direction, ok := ctx.Metadata["direction"].(string); ok {
		item.Direction = direction
	}

	listener.scriptErrorsMu.Lock()
	if listener.scriptErrors == nil {
		listener.scriptErrors = make(map[string]adoption.ScriptRuntimeError)
	}
	listener.scriptErrors[key] = item
	listener.scriptErrorsMu.Unlock()

	if engine := listener.engineForIP(net.ParseIP(key)); engine != nil {
		engine.metrics.transportScriptErrors.Add(1)
	}
}

func (listener *pcapAdoptionListener) clearScriptRuntimeError(ip net.IP) {
	key := recordingKey(ip)
	if listener == nil || key == "" {
		return
	}

	listener.scriptErrorsMu.Lock()
	delete(listener.scriptErrors, key)
	listener.scriptErrorsMu.Unlock()
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

func (listener *pcapAdoptionListener) resolveRoutePeerMAC(group *adoptedEngine, via adoption.Identity, nextHopIP net.IP) (net.HardwareAddr, error) {
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
