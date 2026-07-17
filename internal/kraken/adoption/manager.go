package adoption

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
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
	interfaceListeners map[string]adoptionListener
	scripts            *storage.ScriptStore
	genericScripts     *storage.ScriptStore
	genericRunMu       sync.Mutex
	genericRunCancel   context.CancelFunc
	genericRunOutput   func(GenericScriptOutputEvent)
}

type adoptionListener interface {
	netruntime.PacketEndpoint
	Close()
	SetCaptureFilter(filter string) error
}

func NewManager() *Manager {
	return &Manager{
		entries:            make(map[[4]byte]*Identity),
		interfaceListeners: make(map[string]adoptionListener),
		scripts:            storage.NewScriptStore(),
		genericScripts:     storage.NewGenericScriptStore(),
	}
}

func (s *Manager) AdoptIPAddress(request Identity) (Identity, error) {
	iface, err := net.InterfaceByName(strings.TrimSpace(request.InterfaceName))
	if err != nil {
		return Identity{}, err
	}
	listener, err := s.interfaceListener(*iface)
	if err != nil {
		return Identity{}, err
	}
	request.InterfaceName = iface.Name
	request.Interface = *iface
	return s.adoptIdentity(request, listener)
}

func (s *Manager) ListAdoptedIPAddresses() []Identity {
	s.mu.RLock()
	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, *item)
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].InterfaceName != items[j].InterfaceName {
			return items[i].InterfaceName < items[j].InterfaceName
		}
		return bytes.Compare(items[i].IP, items[j].IP) < 0
	})
	return items
}

func (s *Manager) GetAdoptedIPAddressDetails(ip string) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	return *item, nil
}

func (s *Manager) ListScripts(kind string) ([]storage.StoredScriptSummary, error) {
	store, err := s.scriptStore(kind)
	if err != nil {
		return nil, err
	}
	return store.List()
}

func (s *Manager) GetScript(kind, name string) (storage.StoredScript, error) {
	store, err := s.scriptStore(kind)
	if err != nil {
		return storage.StoredScript{}, err
	}
	return store.Get(name)
}

func (s *Manager) SaveScript(kind string, request storage.SaveStoredScriptRequest) (storage.StoredScript, error) {
	store, err := s.scriptStore(kind)
	if err != nil {
		return storage.StoredScript{}, err
	}
	saved, err := store.Save(request)
	if err == nil && kind == string(script.ScriptKindTransport) {
		s.updateBoundTransportScript(saved.Name, saved.Compiled)
	}
	return saved, err
}

func (s *Manager) DeleteScript(kind, name string) error {
	store, err := s.scriptStore(kind)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if err := store.Delete(name); err != nil {
		return err
	}
	if kind == string(script.ScriptKindTransport) {
		s.updateBoundTransportScript(name, nil)
	}
	return nil
}

func (s *Manager) RefreshScripts(kind string) ([]storage.StoredScriptSummary, error) {
	store, err := s.scriptStore(kind)
	if err != nil {
		return nil, err
	}
	summaries, err := store.List()
	if err == nil && kind == string(script.ScriptKindTransport) {
		s.refreshBoundTransportScripts()
	}
	return summaries, err
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

func (s *Manager) UpdateAdoptedIPAddressScript(ip, scriptName string) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	transportScript, err := s.lookupScript(scriptName)
	if err != nil {
		return Identity{}, err
	}
	item.engine.UpdateTransportScript(transportScript)
	return *item, nil
}

func (s *Manager) UpdateAdoptedIPAddressMTU(ip string, mtu uint32) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	normalized, err := normalizeIdentityMTU(item.Interface, int(mtu))
	if err != nil {
		return Identity{}, err
	}
	item.MTU = normalized
	item.engine.SetMTU(normalized)
	return *item, nil
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
	closeListener, captureErr := s.refreshInterfaceCaptureLocked(item.InterfaceName)
	s.mu.Unlock()

	if closeListener != nil {
		closeListener.Close()
	}
	item.Close()
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
	storedScript, err := s.genericScripts.Lookup(scriptName)
	if err != nil {
		if errors.Is(err, storage.ErrStoredScriptNotFound) {
			return script.RunResult{}, fmt.Errorf("stored script %q was not found", scriptName)
		}
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
	return script.ExecuteGenericWithContext(runContext, storedScript.Compiled, ctx)
}

func (s *Manager) StopStoredGenericScript() {
	s.genericRunMu.Lock()
	cancel := s.genericRunCancel
	s.genericRunMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Manager) StartAdoptedIPAddressRecording(ip, outputPath string) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		outputPath, err = defaultRecordingOutputPath(item.IP)
		if err != nil {
			return Identity{}, err
		}
	}
	if err := item.StartRecording(outputPath); err != nil {
		return Identity{}, err
	}
	return *item, nil
}

func (s *Manager) StopAdoptedIPAddressRecording(ip string) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	item.StopRecording()
	return *item, nil
}

func (s *Manager) StartAdoptedIPAddressService(ip, serviceName string, config map[string]string) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	service, err := operations.NewService(serviceName, config)
	if err != nil {
		return Identity{}, err
	}
	if err := item.StartService(service); err != nil {
		return Identity{}, err
	}
	return *item, nil
}

func (s *Manager) StopAdoptedIPAddressService(ip, serviceName string) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	service := item.services[serviceName]
	delete(item.services, serviceName)
	if service != nil {
		_ = service.Close()
	}
	return *item, nil
}

func (s *Manager) lookupScript(scriptName string) (*script.CompiledScript, error) {
	scriptName = strings.TrimSpace(scriptName)
	if scriptName == "" {
		return nil, nil
	}
	storedScript, err := s.scripts.Lookup(scriptName)
	if err != nil {
		if errors.Is(err, storage.ErrStoredScriptNotFound) {
			return nil, fmt.Errorf("stored script %q was not found", scriptName)
		}
		return nil, err
	}
	return storedScript.Compiled, nil
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
		stored, err := s.scripts.Lookup(name)
		if err != nil {
			item.engine.UpdateTransportScript(nil)
			continue
		}
		item.engine.UpdateTransportScript(stored.Compiled)
	}
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

func (s *Manager) adoptIdentity(identity Identity, listener adoptionListener) (adopted Identity, err error) {
	defer func() {
		if err == nil {
			return
		}
		if identity.engine != nil {
			identity.Close()
		}
		s.mu.Lock()
		closeListener, _ := s.refreshInterfaceCaptureLocked(identity.InterfaceName)
		s.mu.Unlock()
		if closeListener != nil {
			closeListener.Close()
		}
	}()

	if err = identity.Init(listener); err != nil {
		return Identity{}, err
	}
	key := identityKey(identity.IP)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[key]; exists {
		return Identity{}, fmt.Errorf("IP %s is already adopted", identity.IP)
	}
	s.entries[key] = &identity
	if _, err = s.refreshInterfaceCaptureLocked(identity.InterfaceName); err != nil {
		delete(s.entries, key)
		return Identity{}, err
	}

	return identity, nil
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
	var selected *Identity
	selectedPrefix := -1
	for _, item := range s.entries {
		mask := net.CIDRMask(item.SubnetPrefix, 32)
		if network := item.IP.Mask(mask); !network.Equal(destinationIP.Mask(mask)) {
			continue
		}
		if item.SubnetPrefix > selectedPrefix {
			selected = item
			selectedPrefix = item.SubnetPrefix
		}
	}
	return selected
}

func (s *Manager) interfaceListener(iface net.Interface) (adoptionListener, error) {
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

func (s *Manager) refreshInterfaceCaptureLocked(interfaceName string) (adoptionListener, error) {
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
		if identity.InterfaceName != interfaceName {
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
	listeners := make([]adoptionListener, 0, len(s.interfaceListeners))
	for _, listener := range s.interfaceListeners {
		listeners = append(listeners, listener)
	}
	clear(s.interfaceListeners)
	s.mu.Unlock()

	for _, item := range items {
		item.Close()
	}
	for _, listener := range listeners {
		listener.Close()
	}
}
