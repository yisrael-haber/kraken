package operations

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

	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	adoptionListenerSnapLen     = 65535
	adoptionListenerReadTimeout = 50 * time.Millisecond
)

const inactiveAdoptionCaptureBPFFilter = "less 1"

type inboundFrameInfo struct {
	targetIP net.IP
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
	writePacketData      func([]byte) error

	stackMu  sync.RWMutex
	engines  map[string]*adoptedEngine
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

	handle, err := openCaptureHandle(deviceName, iface.Name, "adoption listener", 0, adoptionListenerReadTimeout)
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
		engines:       make(map[string]*adoptedEngine),
		recorders:     make(map[string]*packetRecorder),
		scriptErrors:  make(map[string]adoption.ScriptRuntimeError),
		services:      make(map[string]map[string]*managedService),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	listener.enginesV.Store(make(map[string]*adoptedEngine))
	if err := listener.setCaptureFilter(buildAdoptionCaptureBPFFilter(listener.engines)); err != nil {
		handle.Close()
		return nil, err
	}
	listener.setCaptureDirection()

	go listener.run()

	return listener, nil
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

func (listener *pcapAdoptionListener) StatusSnapshot(ip net.IP) adoption.ListenerStatus {
	return adoption.ListenerStatus{
		Capture:     listener.captureStatusSnapshot(),
		ScriptError: listener.scriptRuntimeSnapshot(ip),
	}
}

func (listener *pcapAdoptionListener) captureStatusSnapshot() *adoption.CaptureStatus {
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

func (listener *pcapAdoptionListener) scriptRuntimeSnapshot(ip net.IP) *adoption.ScriptRuntimeError {
	key := engineKey(ip)
	if key == "" {
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
	if identity.IP.To4() == nil {
		return nil
	}

	listener.clearScriptRuntimeError(identity.IP)
	_, err := listener.engineForIdentity(identity)
	return err
}

func (listener *pcapAdoptionListener) InjectFrame(frame buffer.Buffer) error {
	raw := bufferBytes(&frame)
	info, ok := classifyInboundFrame(raw)
	if !listener.injectLocalFrame(frame, info, ok, listener.currentEngines()) {
		frame.Release()
	}
	return nil
}

func (listener *pcapAdoptionListener) StartRecording(source adoption.Identity, outputPath string) (adoption.PacketRecordingStatus, error) {
	key := engineKey(source.IP)
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

	recorder, err := startPacketRecorder(listener.deviceName, listener.iface.Name, listener.iface.HardwareAddr, source, outputPath)
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
	key := engineKey(ip)
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
	key := engineKey(ip)
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
	key := engineKey(ip)
	if key == "" {
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
	if identity.IP.To4() == nil {
		return nil, fmt.Errorf("netstack requires an identity")
	}

	ipKey := engineKey(identity.IP)
	if ipKey == "" {
		return nil, fmt.Errorf("netstack requires a valid IPv4 identity")
	}

	var suspendedServices []*managedService
	existing := listener.currentEngines()[ipKey]
	if existing != nil && !existing.matchesIdentity(identity) {
		suspendedServices = listener.takeServices(identity.IP)
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

	engine, err := newAdoptedEngine(engineConfigForIdentity(identity, listener.routes), listener.handleEngineOutbound)
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

func (listener *pcapAdoptionListener) Ping(source adoption.Identity, targetIP net.IP, count int, payload []byte) (adoption.PingAdoptedIPAddressResult, error) {
	targetIP = targetIP.To4()
	if targetIP == nil {
		return adoption.PingAdoptedIPAddressResult{}, fmt.Errorf("a valid IPv4 target is required")
	}
	if count <= 0 {
		return adoption.PingAdoptedIPAddressResult{}, fmt.Errorf("ping count must be positive")
	}

	result := adoption.PingAdoptedIPAddressResult{
		SourceIP: source.IP.String(),
		TargetIP: targetIP.String(),
		Replies:  make([]adoption.PingAdoptedIPAddressReply, 0, count),
	}
	return result, fmt.Errorf("ICMP ping is not implemented")
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

		ip := ipNet.IP.To4()
		if ip == nil || len(ipNet.Mask) != net.IPv4len {
			continue
		}

		networks = append(networks, net.IPNet{
			IP:   ip.Mask(ipNet.Mask),
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

		listener.dispatchInboundFrame(buffer.MakeWithData(frame))
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

func (listener *pcapAdoptionListener) dispatchInboundFrame(frame buffer.Buffer) {
	raw := bufferBytes(&frame)
	if len(raw) < header.EthernetMinimumSize {
		frame.Release()
		return
	}

	engines := listener.currentEngines()
	info, ok := classifyInboundFrame(raw)
	if listener.injectLocalFrame(frame, info, ok, engines) {
		return
	}

	if !ok || header.Ethernet(raw).Type() != header.IPv4ProtocolNumber || listener.forward == nil {
		frame.Release()
		return
	}

	target, exists := listener.forward(info.targetIP)
	if !exists || target == nil {
		frame.Release()
		return
	}

	_ = target.InjectFrame(frame)
}

func (listener *pcapAdoptionListener) injectLocalFrame(frame buffer.Buffer, info inboundFrameInfo, classified bool, engines map[string]*adoptedEngine) bool {
	if classified {
		engine := engines[engineKey(info.targetIP)]
		if engine != nil {
			engine.injectFrame(frame)
			return true
		}
	}

	raw := bufferBytes(&frame)
	if len(raw) < header.EthernetMinimumSize || header.Ethernet(raw).DestinationAddress() != header.EthernetBroadcastAddress {
		return false
	}

	for _, engine := range engines {
		engine.injectFrame(frame.Clone())
	}
	frame.Release()
	return true
}

func classifyInboundFrame(frame []byte) (inboundFrameInfo, bool) {
	if len(frame) < header.EthernetMinimumSize {
		return inboundFrameInfo{}, false
	}

	payload := frame[header.EthernetMinimumSize:]
	switch header.Ethernet(frame).Type() {
	case header.ARPProtocolNumber:
		if len(payload) < header.ARPSize {
			return inboundFrameInfo{}, false
		}
		arp := header.ARP(payload)
		if !arp.IsValid() {
			return inboundFrameInfo{}, false
		}
		return inboundFrameInfo{targetIP: net.IP(arp.ProtocolAddressTarget())}, true
	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(payload)
		if !ipv4.IsValid(len(payload)) {
			return inboundFrameInfo{}, false
		}
		target := ipv4.DestinationAddress().As4()
		return inboundFrameInfo{targetIP: target[:]}, true
	default:
		return inboundFrameInfo{}, false
	}
}

func (listener *pcapAdoptionListener) currentEngines() map[string]*adoptedEngine {
	engines, _ := listener.enginesV.Load().(map[string]*adoptedEngine)
	if engines != nil {
		return engines
	}

	listener.stackMu.RLock()
	defer listener.stackMu.RUnlock()
	return listener.engines
}

func buildAdoptionCaptureBPFFilter(engines map[string]*adoptedEngine) string {
	if len(engines) == 0 {
		return inactiveAdoptionCaptureBPFFilter
	}

	ips := make([]net.IP, 0, len(engines))
	for key := range engines {
		ip := net.ParseIP(key).To4()
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i], ips[j]) < 0
	})

	clauses := make([]string, 0, 2)
	if len(ips) > 0 {
		var arpTargets strings.Builder
		var ipTargets strings.Builder
		for index, ip := range ips {
			ipText := ip.String()
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
	if listener.handle == nil {
		return
	}
	if err := listener.handle.SetDirection(pcap.DirectionIn); err != nil {
		listener.recordCaptureError("", fmt.Errorf("set adoption capture direction on %s: %w", listener.iface.Name, err))
	}
}

func (listener *pcapAdoptionListener) recordCaptureError(filter string, err error) {
	if err == nil {
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

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	listener.writeMu.Lock()
	defer listener.writeMu.Unlock()

	if listener.writePacketData != nil {
		return listener.writePacketData(frame)
	}

	handle := listener.handle
	if handle == nil {
		return adoption.ErrListenerStopped
	}

	return handle.WritePacketData(frame)
}

func (listener *pcapAdoptionListener) writePacketBuffer(frame *buffer.Buffer) error {
	return listener.writePacket(bufferBytes(frame))
}

func bufferBytes(frame *buffer.Buffer) []byte {
	if frame == nil || frame.Size() == 0 {
		return nil
	}

	views := frame.AsViewList()
	view := views.Front()
	if view != nil && view.Next() == nil && view.Size() == int(frame.Size()) {
		return view.AsSlice()
	}
	return frame.Flatten()
}

func mutableBufferBytes(frame *buffer.Buffer) []byte {
	if frame == nil || frame.Size() == 0 {
		return nil
	}
	view, ok := frame.PullUp(0, int(frame.Size()))
	if !ok {
		return nil
	}
	return view.AsSlice()
}

func buildBoundTransportScript(identity adoption.Identity) scriptpkg.ExecutionContext {
	scriptName := strings.TrimSpace(identity.TransportScriptName)
	if scriptName == "" {
		return scriptpkg.ExecutionContext{}
	}
	return buildPacketScriptContext(identity, scriptName, map[string]any{
		"direction": "outbound",
		"handler":   "transport",
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
	if identity.IP.To4() == nil {
		return scriptpkg.ExecutionIdentity{}
	}

	return scriptpkg.ExecutionIdentity{
		Label:          identity.Label,
		IP:             identity.IP.String(),
		MAC:            identity.MAC.String(),
		InterfaceName:  identity.InterfaceName,
		DefaultGateway: ipString(identity.DefaultGateway),
		MTU:            int(identity.MTU),
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (listener *pcapAdoptionListener) recordTransportScriptError(ctx scriptpkg.ExecutionContext, err error) {
	if err == nil || ctx.Adopted.IP == "" {
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

}

func (listener *pcapAdoptionListener) clearScriptRuntimeError(ip net.IP) {
	key := engineKey(ip)
	if key == "" {
		return
	}

	listener.scriptErrorsMu.Lock()
	delete(listener.scriptErrors, key)
	listener.scriptErrorsMu.Unlock()
}
