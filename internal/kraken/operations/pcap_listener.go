package operations

import (
	"bytes"
	"errors"
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
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const adoptionListenerReadTimeout = 50 * time.Millisecond
const inactiveAdoptionCaptureBPFFilter = "less 1"

type inboundFrameInfo struct {
	targetIP net.IP
}

type pcapAdoptionListener struct {
	pcap          *netruntime.PcapHandle
	deviceName    string
	iface         net.Interface
	forward       adoption.ForwardLookupFunc
	resolveScript adoption.ScriptLookupFunc
	routes        []net.IPNet

	writePacketData func([]byte) error

	stackMu  sync.RWMutex
	engines  map[string]*adoption.Identity
	enginesV atomic.Value

	recordersMu sync.RWMutex
	recorders   map[string]*packetRecorder

	scriptErrorsMu sync.RWMutex
	scriptErrors   map[string]adoption.ScriptRuntimeError

	servicesMu sync.RWMutex
	services   map[string]map[string]*managedService

	pcapMu        sync.Mutex
	captureFilter string

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

	pcapHandle, err := netruntime.OpenPcapHandle(netruntime.PcapOptions{
		DeviceName:    deviceName,
		InterfaceName: iface.Name,
		Purpose:       "adoption listener",
		ReadTimeout:   adoptionListenerReadTimeout,
		BPFFilter:     inactiveAdoptionCaptureBPFFilter,
		Direction:     pcap.DirectionIn,
	})
	if err != nil {
		return nil, err
	}

	listener := &pcapAdoptionListener{
		pcap:          pcapHandle,
		deviceName:    deviceName,
		iface:         iface,
		forward:       forward,
		resolveScript: resolveScript,
		routes:        interfaceIPv4Networks(iface),
		engines:       make(map[string]*adoption.Identity),
		recorders:     make(map[string]*packetRecorder),
		scriptErrors:  make(map[string]adoption.ScriptRuntimeError),
		services:      make(map[string]map[string]*managedService),
		captureFilter: inactiveAdoptionCaptureBPFFilter,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	listener.enginesV.Store(make(map[string]*adoption.Identity))
	go listener.run()

	return listener, nil
}

func (listener *pcapAdoptionListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		listener.stopAllRecorders()
		listener.stopAllServices()
		listener.closeAllNetstacks()
		listener.pcapMu.Lock()
		if listener.pcap != nil {
			_ = listener.pcap.Close()
			listener.pcap = nil
		}
		listener.pcapMu.Unlock()
		<-listener.done
	})
	return nil
}

func (listener *pcapAdoptionListener) Healthy() error {
	if listener.done == nil {
		return adoption.ErrListenerStopped
	}

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
	listener.pcapMu.Lock()
	activeFilter := listener.captureFilter
	listener.pcapMu.Unlock()
	if activeFilter == "" || activeFilter == inactiveAdoptionCaptureBPFFilter {
		return nil
	}
	return &adoption.CaptureStatus{ActiveFilter: activeFilter}
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

func (listener *pcapAdoptionListener) EnsureIdentity(identity *adoption.Identity) error {
	if identity == nil || identity.IP.To4() == nil {
		return nil
	}

	listener.clearScriptRuntimeError(identity.IP)
	return listener.ensureEngine(identity)
}

func (listener *pcapAdoptionListener) InjectFrame(frame buffer.Buffer) error {
	listener.dispatchInboundFrame(frame)
	return nil
}

func (listener *pcapAdoptionListener) StartRecording(source *adoption.Identity, outputPath string) (adoption.PacketRecordingStatus, error) {
	if source == nil {
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording requires a valid IPv4 identity")
	}
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

	recorder, err := startPacketRecorder(listener.deviceName, listener.iface.Name, listener.iface.HardwareAddr, *source, outputPath)
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
	engines := make([]*adoption.Identity, 0, len(listener.engines))
	for key, engine := range listener.engines {
		delete(listener.engines, key)
		if engine != nil {
			engines = append(engines, engine)
		}
	}
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()

	for _, engine := range engines {
		engine.CloseEngine()
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

	var toClose *adoption.Identity

	listener.stackMu.Lock()
	identity := listener.engines[key]
	delete(listener.engines, key)
	if identity != nil {
		toClose = identity
	}
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()

	if toClose != nil {
		toClose.CloseEngine()
	}
}

func (listener *pcapAdoptionListener) ensureEngine(identity *adoption.Identity) error {
	if identity == nil || identity.IP.To4() == nil {
		return fmt.Errorf("netstack requires an identity")
	}

	ipKey := engineKey(identity.IP)
	if ipKey == "" {
		return fmt.Errorf("netstack requires a valid IPv4 identity")
	}

	var suspendedServices []*managedService
	existing := listener.currentEngines()[ipKey]
	if existing != nil && existing != identity {
		suspendedServices = listener.takeServices(identity.IP)
		for _, service := range suspendedServices {
			service.stop()
		}
	}

	listener.stackMu.Lock()
	existing = listener.engines[ipKey]
	if existing == identity {
		listener.publishEngineSnapshotLocked()
		listener.stackMu.Unlock()
		listener.restoreServices(identity, suspendedServices)
		return nil
	}

	if err := identity.EnsureEngine(listener.routes, listener.handleEngineOutbound); err != nil {
		listener.publishEngineSnapshotLocked()
		listener.stackMu.Unlock()
		listener.restoreServices(identity, suspendedServices)
		return err
	}
	listener.engines[ipKey] = identity
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()
	if existing != nil && existing != identity {
		existing.CloseEngine()
	}
	listener.restoreServices(identity, suspendedServices)
	return nil
}

func (listener *pcapAdoptionListener) publishEngineSnapshotLocked() {
	engines := maps.Clone(listener.engines)
	listener.enginesV.Store(engines)
	listener.reopenPcap(buildAdoptionCaptureBPFFilter(engines))
}

func (listener *pcapAdoptionListener) currentEngines() map[string]*adoption.Identity {
	engines, _ := listener.enginesV.Load().(map[string]*adoption.Identity)
	if engines != nil {
		return engines
	}

	listener.stackMu.RLock()
	defer listener.stackMu.RUnlock()
	return listener.engines
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

func (listener *pcapAdoptionListener) Ping(source *adoption.Identity, targetIP net.IP, count int, payload []byte) (adoption.PingAdoptedIPAddressResult, error) {
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
	if listener.pcap == nil {
		runErr = adoption.ErrListenerStopped
		return
	}

	for {
		select {
		case <-listener.stop:
			return
		default:
		}

		listener.pcapMu.Lock()
		pcapHandle := listener.pcap
		if pcapHandle == nil {
			listener.pcapMu.Unlock()
			runErr = adoption.ErrListenerStopped
			return
		}
		frame, err := pcapHandle.Read()
		listener.pcapMu.Unlock()
		if errors.Is(err, netruntime.ErrPcapReadTimeout) {
			continue
		}
		if errors.Is(err, netruntime.ErrPcapHandleClosed) {
			select {
			case <-listener.stop:
			default:
				runErr = adoption.ErrListenerStopped
			}
			return
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

func (listener *pcapAdoptionListener) reopenPcap(filter string) {
	if filter == "" {
		filter = inactiveAdoptionCaptureBPFFilter
	}

	listener.pcapMu.Lock()
	if filter == listener.captureFilter {
		listener.pcapMu.Unlock()
		return
	}

	pcapHandle, err := netruntime.OpenPcapHandle(netruntime.PcapOptions{
		DeviceName:    listener.deviceName,
		InterfaceName: listener.iface.Name,
		Purpose:       "adoption listener",
		ReadTimeout:   adoptionListenerReadTimeout,
		BPFFilter:     filter,
		Direction:     pcap.DirectionIn,
	})
	if err != nil {
		listener.recordCaptureError(filter, err)
		listener.pcapMu.Unlock()
		return
	}

	previous := listener.pcap
	listener.pcap = pcapHandle
	listener.captureFilter = filter
	listener.clearCaptureError()
	if previous != nil {
		_ = previous.Close()
	}
	listener.pcapMu.Unlock()
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

func (listener *pcapAdoptionListener) recordCaptureError(filter string, err error) {
	if err == nil {
		return
	}

	listener.stateMu.Lock()
	listener.runErr = fmt.Errorf("reopen pcap with filter %q: %w", filter, err)
	listener.stateMu.Unlock()
}

func (listener *pcapAdoptionListener) clearCaptureError() {
	listener.stateMu.Lock()
	listener.runErr = nil
	listener.stateMu.Unlock()
}

func (listener *pcapAdoptionListener) injectLocalFrame(frame buffer.Buffer, info inboundFrameInfo, classified bool, engines map[string]*adoption.Identity) bool {
	if classified {
		identity := engines[engineKey(info.targetIP)]
		if identity != nil {
			identity.InjectFrame(frame)
			return true
		}
	}

	raw := bufferBytes(&frame)
	if len(raw) < header.EthernetMinimumSize || header.Ethernet(raw).DestinationAddress() != header.EthernetBroadcastAddress {
		return false
	}

	for _, identity := range engines {
		identity.InjectFrame(frame.Clone())
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

func buildAdoptionCaptureBPFFilter(engines map[string]*adoption.Identity) string {
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

func (listener *pcapAdoptionListener) writePacketBuffer(frame *buffer.Buffer) error {
	if listener.writePacketData != nil {
		return listener.writePacketData(bufferBytes(frame))
	}
	listener.pcapMu.Lock()
	pcapHandle := listener.pcap
	if pcapHandle == nil {
		listener.pcapMu.Unlock()
		return adoption.ErrListenerStopped
	}
	err := pcapHandle.Write(frame)
	listener.pcapMu.Unlock()
	if errors.Is(err, netruntime.ErrPcapHandleClosed) {
		return adoption.ErrListenerStopped
	} else {
		return err
	}
}

func (listener *pcapAdoptionListener) writePacket(frame []byte) error {
	if listener.writePacketData != nil {
		return listener.writePacketData(frame)
	}
	buffer := buffer.MakeWithData(frame)
	defer buffer.Release()
	return listener.writePacketBuffer(&buffer)
}

func bufferBytes(frame *buffer.Buffer) []byte {
	return frame.Flatten()
}

func mutableBufferBytes(frame *buffer.Buffer) []byte {
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
