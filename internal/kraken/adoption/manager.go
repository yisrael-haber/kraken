package adoption

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"gvisor.dev/gvisor/pkg/buffer"
)

type Manager struct {
	mu                 sync.RWMutex
	entries            map[[4]byte]*Identity
	interfaceListeners map[string]*netruntime.InterfaceListener
	scripts            *storage.ScriptStore
	genericScripts     *storage.ScriptStore
	genericRunMu       sync.Mutex
	genericRunCancel   context.CancelFunc
	genericRunOutput   func(GenericScriptOutputEvent)
}

func NewManager() (*Manager, error) {
	scripts, err := storage.NewScriptStore("Transport")
	if err != nil {
		return nil, err
	}
	genericScripts, err := storage.NewScriptStore("Generic")
	if err != nil {
		return nil, err
	}
	return &Manager{
		entries:            make(map[[4]byte]*Identity),
		interfaceListeners: make(map[string]*netruntime.InterfaceListener),
		scripts:            scripts,
		genericScripts:     genericScripts,
	}, nil
}

func (s *Manager) AdoptIPAddress(request Identity) (*Identity, error) {
	iface, err := net.InterfaceByName(request.Interface.Name)
	if err != nil {
		return nil, err
	}
	listener, err := s.interfaceListener(*iface)
	if err != nil {
		return nil, err
	}
	request.Interface = *iface
	return s.adoptIdentity(request, listener)
}

func (s *Manager) ListAdoptedIPAddresses() []*Identity {
	s.mu.RLock()
	items := make([]*Identity, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, item)
	}
	s.mu.RUnlock()
	return items
}

func (s *Manager) GetAdoptedIPAddressDetails(ip string) (*Identity, error) {
	return s.lookupAdoptedIP(ip)
}

func (s *Manager) ListScripts(kind string) ([]storage.StoredScript, error) {
	store, err := s.scriptStore(kind)
	if err != nil {
		return nil, err
	}
	items, err := store.List()
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i], _ = compileStoredScript(items[i], script.ScriptKind(kind))
	}
	return items, nil
}

func (s *Manager) GetScript(kind, name string) (storage.StoredScript, error) {
	store, err := s.scriptStore(kind)
	if err != nil {
		return storage.StoredScript{}, err
	}
	item, err := store.Get(name)
	if err != nil {
		return storage.StoredScript{}, err
	}
	item, _ = compileStoredScript(item, script.ScriptKind(kind))
	return item, nil
}

func (s *Manager) SaveScript(kind string, scriptToSave storage.StoredScript) (storage.StoredScript, error) {
	store, err := s.scriptStore(kind)
	if err != nil {
		return storage.StoredScript{}, err
	}
	saved, err := store.Save(scriptToSave)
	if err != nil {
		return storage.StoredScript{}, err
	}
	saved, compiled := compileStoredScript(saved, script.ScriptKind(kind))
	if kind == string(script.ScriptKindTransport) {
		s.updateBoundTransportScript(saved.Name, compiled)
	}
	return saved, nil
}

func (s *Manager) DeleteScript(kind, name string) error {
	store, err := s.scriptStore(kind)
	if err != nil {
		return err
	}
	if err := store.Delete(name); err != nil {
		return err
	}
	if kind == string(script.ScriptKindTransport) {
		s.updateBoundTransportScript(name, nil)
	}
	return nil
}

func (s *Manager) RefreshScripts(kind string) ([]storage.StoredScript, error) {
	items, err := s.ListScripts(kind)
	if err == nil && kind == string(script.ScriptKindTransport) {
		s.refreshBoundTransportScripts()
	}
	return items, err
}

func (s *Manager) scriptStore(kind string) (*storage.ScriptStore, error) {
	switch script.ScriptKind(kind) {
	case script.ScriptKindTransport:
		return s.scripts, nil
	case script.ScriptKindGeneric:
		return s.genericScripts, nil
	default:
		return nil, fmt.Errorf("unsupported script kind %q", kind)
	}
}

func (s *Manager) UpdateAdoptedIPAddressScript(ip, scriptName string) (*Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return nil, err
	}
	transportScript, err := s.lookupScript(scriptName)
	if err != nil {
		return nil, err
	}
	item.engine.UpdateTransportScript(transportScript)
	return item, nil
}

func (s *Manager) UpdateAdoptedIPAddressMTU(ip string, mtu uint32) (*Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeIdentityMTU(item.Interface, int(mtu))
	if err != nil {
		return nil, err
	}
	item.MTU = normalized
	item.engine.SetMTU(normalized)
	return item, nil
}

func (s *Manager) ReleaseIPAddress(ip string) error {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return err
	}
	key := identityKey(adoptedIP)

	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		return errAdoptedIPNotFound(adoptedIP)
	}
	delete(s.entries, key)
	closeListener, captureErr := s.refreshInterfaceCaptureLocked(item.Interface.Name)
	s.mu.Unlock()

	if closeListener != nil {
		closeListener.Close()
	}
	item.close()
	if captureErr != nil {
		return captureErr
	}
	return nil
}

func (s *Manager) ResolveDNSAdoptedIPAddress(request operations.ResolveDNSAdoptedIPAddressRequest) (operations.ResolveDNSAdoptedIPAddressResult, error) {
	source, err := s.lookupAdoptedIP(request.SourceIP)
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	return operations.ResolveDNSWithDialer(request, source.engine.DialTCP, source.engine.DialUDP)
}

func (s *Manager) PingAdoptedIPAddress(request operations.PingAdoptedIPAddressRequest) (operations.PingAdoptedIPAddressResult, error) {
	source, err := s.lookupAdoptedIP(request.SourceIP)
	if err != nil {
		return operations.PingAdoptedIPAddressResult{}, err
	}
	return operations.PingWithDialer(request, source.engine.OpenICMPv4)
}

type GenericScriptOutputEvent struct {
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

func (s *Manager) SetGenericScriptOutputSink(sink func(GenericScriptOutputEvent)) {
	s.genericRunMu.Lock()
	s.genericRunOutput = sink
	s.genericRunMu.Unlock()
}

func (s *Manager) RunStoredGenericScript(scriptName string) (script.RunResult, error) {
	scriptName = strings.TrimSpace(scriptName)
	if scriptName == "" {
		return script.RunResult{}, fmt.Errorf("script name is required")
	}
	compiled, err := lookupStoredScript(s.genericScripts, script.ScriptKindGeneric, scriptName)
	if err != nil {
		return script.RunResult{}, err
	}
	ctx := script.ExecutionContext{
		ScriptName: scriptName,
		Identities: s.scriptIdentities(),
		Metadata: map[string]string{
			"handler": "generic",
		},
	}
	runContext, cancel := context.WithCancel(context.Background())
	s.genericRunMu.Lock()
	if s.genericRunCancel != nil {
		s.genericRunMu.Unlock()
		cancel()
		return script.RunResult{}, fmt.Errorf("a generic script is already running")
	}
	s.genericRunCancel = cancel
	outputSink := s.genericRunOutput
	s.genericRunMu.Unlock()
	defer func() {
		s.genericRunMu.Lock()
		s.genericRunCancel = nil
		s.genericRunMu.Unlock()
		cancel()
	}()

	if outputSink != nil {
		ctx.Stdout = func(text string) {
			outputSink(GenericScriptOutputEvent{Stream: "stdout", Text: text})
		}
		ctx.Stderr = func(text string) {
			outputSink(GenericScriptOutputEvent{Stream: "stderr", Text: text})
		}
	}
	return script.ExecuteGenericWithContext(runContext, compiled, ctx)
}

func (s *Manager) StopStoredGenericScript() {
	s.genericRunMu.Lock()
	cancel := s.genericRunCancel
	s.genericRunMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Manager) StartAdoptedIPAddressRecording(ip, outputPath string) (*Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return nil, err
	}
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		outputPath, err = defaultRecordingOutputPath(item.IP)
		if err != nil {
			return nil, err
		}
	}
	if err := item.startRecording(outputPath); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *Manager) StopAdoptedIPAddressRecording(ip string) (*Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return nil, err
	}
	item.stopRecording()
	return item, nil
}

func (s *Manager) StartAdoptedIPAddressService(ip, serviceName string, config map[string]string) (*Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return nil, err
	}
	service, err := operations.NewService(serviceName, config)
	if err != nil {
		return nil, err
	}
	if err := item.startService(service); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *Manager) StopAdoptedIPAddressService(ip, serviceName string) (*Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return nil, err
	}
	item.stopService(serviceName)
	return item, nil
}

func (s *Manager) lookupScript(scriptName string) (*script.CompiledScript, error) {
	scriptName = strings.TrimSpace(scriptName)
	if scriptName == "" {
		return nil, nil
	}
	compiled, err := lookupStoredScript(s.scripts, script.ScriptKindTransport, scriptName)
	if err != nil {
		return nil, err
	}
	return compiled, nil
}

func (s *Manager) updateBoundTransportScript(name string, compiled *script.CompiledScript) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, item := range s.entries {
		if item.engine.ScriptName() == name {
			item.engine.UpdateTransportScript(compiled)
		}
	}
}

func (s *Manager) refreshBoundTransportScripts() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, item := range s.entries {
		name := item.engine.ScriptName()
		if name == "" {
			continue
		}
		compiled, err := lookupStoredScript(s.scripts, script.ScriptKindTransport, name)
		if err != nil {
			item.engine.UpdateTransportScript(nil)
			continue
		}
		item.engine.UpdateTransportScript(compiled)
	}
}

func lookupStoredScript(store *storage.ScriptStore, kind script.ScriptKind, name string) (*script.CompiledScript, error) {
	item, err := store.Get(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("stored script %q was not found", name)
		}
		return nil, err
	}
	item, compiled := compileStoredScript(item, kind)
	if !item.Available {
		return nil, fmt.Errorf("stored script is invalid: %s", item.CompileError)
	}
	return compiled, nil
}

func compileStoredScript(item storage.StoredScript, kind script.ScriptKind) (storage.StoredScript, *script.CompiledScript) {
	var compiled *script.CompiledScript
	var err error
	if kind == script.ScriptKindGeneric {
		compiled, err = script.CompileGeneric(item.Name, item.Source)
	} else {
		compiled, err = script.CompileTransport(item.Name, item.Source)
	}
	item.Available = err == nil
	item.CompileError = ""
	if err != nil {
		item.CompileError = err.Error()
		compiled = nil
	}
	return item, compiled
}

func (s *Manager) scriptIdentities() []script.ExecutionIdentity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identities := make([]script.ExecutionIdentity, 0, len(s.entries))
	for _, item := range s.entries {
		identities = append(identities, item.engine.ScriptIdentity())
	}
	sort.Slice(identities, func(i, j int) bool {
		return identities[i].IP < identities[j].IP
	})
	return identities
}

func (s *Manager) adoptIdentity(identity Identity, listener *netruntime.InterfaceListener) (adopted *Identity, err error) {
	defer func() {
		if err == nil {
			return
		}
		if identity.engine != nil {
			identity.close()
		}
		s.mu.Lock()
		closeListener, _ := s.refreshInterfaceCaptureLocked(identity.Interface.Name)
		s.mu.Unlock()
		if closeListener != nil {
			closeListener.Close()
		}
	}()

	if err = identity.init(listener); err != nil {
		return nil, err
	}
	key := identityKey(identity.IP)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[key]; exists {
		return nil, fmt.Errorf("IP %s is already adopted", identity.IP)
	}
	s.entries[key] = &identity
	if _, err = s.refreshInterfaceCaptureLocked(identity.Interface.Name); err != nil {
		delete(s.entries, key)
		return nil, err
	}

	return &identity, nil
}

func (s *Manager) lookup(ip net.IP) (*Identity, error) {
	key := identityKey(ip)

	s.mu.RLock()
	item, exists := s.entries[key]
	s.mu.RUnlock()
	if !exists {
		return nil, errAdoptedIPNotFound(ip)
	}
	return item, nil
}

func (s *Manager) lookupAdoptedIP(ip string) (*Identity, error) {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return nil, err
	}
	return s.lookup(adoptedIP)
}

func (s *Manager) forwardFrame(destinationIP net.IP, frame buffer.Buffer) bool {
	destinationIP = destinationIP.To4()
	if destinationIP == nil {
		return false
	}

	s.mu.RLock()
	item := s.entries[identityKey(destinationIP)]
	if item == nil {
		item = s.routeIdentity(destinationIP)
	}
	s.mu.RUnlock()

	if item == nil {
		return false
	}
	item.engine.InjectFrame(frame)
	return true
}

func (s *Manager) routeIdentity(destinationIP net.IP) *Identity {
	destination := binary.BigEndian.Uint32(destinationIP)
	var selected *Identity
	selectedPrefix := -1
	for _, item := range s.entries {
		if destination&item.mask != item.network {
			continue
		}
		if item.SubnetPrefix > selectedPrefix {
			selected = item
			selectedPrefix = item.SubnetPrefix
		}
	}
	return selected
}

func (s *Manager) interfaceListener(iface net.Interface) (*netruntime.InterfaceListener, error) {
	s.mu.RLock()
	listener := s.interfaceListeners[iface.Name]
	s.mu.RUnlock()
	if listener != nil {
		return listener, nil
	}

	created, err := netruntime.NewInterfaceListener(iface, s.forwardFrame)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if listener = s.interfaceListeners[iface.Name]; listener != nil {
		created.Close()
		return listener, nil
	}
	s.interfaceListeners[iface.Name] = created
	return created, nil
}

func (s *Manager) refreshInterfaceCaptureLocked(interfaceName string) (*netruntime.InterfaceListener, error) {
	listener := s.interfaceListeners[interfaceName]
	if listener == nil {
		return nil, nil
	}
	filter := s.interfaceCaptureFilterLocked(interfaceName)
	if filter == "" {
		delete(s.interfaceListeners, interfaceName)
		return listener, nil
	}
	return nil, listener.SetCaptureFilter(filter)
}

func (s *Manager) interfaceCaptureFilterLocked(interfaceName string) string {
	var clauses []string
	for _, identity := range s.entries {
		if identity.Interface.Name != interfaceName {
			continue
		}
		clauses = append(clauses,
			fmt.Sprintf("(arp and arp dst host %s)", identity.IP),
			fmt.Sprintf("(ip and dst host %s)", identity.IP),
		)
		if identity.SubnetPrefix < 32 {
			mask := net.CIDRMask(identity.SubnetPrefix, 32)
			clauses = append(clauses, fmt.Sprintf("(ip and dst net %s/%d and not dst host %s)", identity.IP.Mask(mask), identity.SubnetPrefix, identity.IP))
		}
	}
	return strings.Join(clauses, " or ")
}

func identityKey(ip net.IP) [4]byte {
	return *(*[4]byte)(ip)
}

func errAdoptedIPNotFound(ip net.IP) error {
	return fmt.Errorf("IP %s is not currently adopted", ip)
}

func (s *Manager) Close() {
	s.StopStoredGenericScript()
	s.mu.Lock()
	items := make([]*Identity, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, item)
	}
	clear(s.entries)
	listeners := make([]*netruntime.InterfaceListener, 0, len(s.interfaceListeners))
	for _, listener := range s.interfaceListeners {
		listeners = append(listeners, listener)
	}
	clear(s.interfaceListeners)
	s.mu.Unlock()

	for _, item := range items {
		item.close()
	}
	for _, listener := range listeners {
		listener.Close()
	}
}
