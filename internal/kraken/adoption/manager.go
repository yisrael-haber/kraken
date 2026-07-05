package adoption

import (
	"bytes"
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
	configs            *storage.ConfigStore
	scripts            *storage.ScriptStore
}

type adoptionListener interface {
	netruntime.PacketEndpoint
	Close()
	SetCaptureFilter(filter string) error
}

func NewManager() *Manager {
	manager := &Manager{
		entries:            make(map[[4]byte]*Identity),
		interfaceListeners: make(map[string]adoptionListener),
		configs:            storage.NewConfigStore(),
		scripts:            storage.NewScriptStore(),
	}
	return manager
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

func (s *Manager) ListStoredAdoptionConfigurations() ([]storage.StoredAdoptionConfiguration, error) {
	return s.configs.List()
}

func (s *Manager) SaveStoredAdoptionConfiguration(previousLabel string, config storage.StoredAdoptionConfiguration) (storage.StoredAdoptionConfiguration, error) {
	return s.configs.Replace(previousLabel, config)
}

func (s *Manager) DeleteStoredAdoptionConfiguration(label string) error {
	return s.configs.Delete(label)
}

func (s *Manager) ListStoredScripts() ([]storage.StoredScriptSummary, error) {
	items, err := s.scriptStore().List()
	if err != nil {
		return nil, err
	}
	summaries := make([]storage.StoredScriptSummary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, item.Summary())
	}
	return summaries, nil
}

func (s *Manager) GetStoredScript(name string) (storage.StoredScript, error) {
	return s.scriptStore().Get(name)
}

func (s *Manager) SaveStoredScript(request storage.SaveStoredScriptRequest) (storage.StoredScript, error) {
	saved, err := s.scriptStore().Save(request)
	if err != nil || saved.Compiled == nil {
		return saved, err
	}
	s.mu.RLock()
	for _, item := range s.entries {
		transportScriptName := item.engine.ScriptName()
		if transportScriptName == saved.Name {
			item.engine.UpdateTransportScript(saved.Compiled)
		}
	}
	s.mu.RUnlock()
	return saved, nil
}

func (s *Manager) DeleteStoredScript(name string) error {
	return s.scriptStore().Delete(name)
}

func (s *Manager) RefreshStoredScripts() ([]storage.StoredScriptSummary, error) {
	if _, err := s.scriptStore().Refresh(); err != nil {
		return nil, err
	}
	return s.ListStoredScripts()
}

func (s *Manager) AdoptStoredAdoptionConfiguration(label string) (Identity, error) {
	config, err := s.configs.Load(label)
	if err != nil {
		return Identity{}, err
	}
	var mac net.HardwareAddr
	if config.MAC != "" {
		mac, err = net.ParseMAC(config.MAC)
		if err != nil {
			return Identity{}, err
		}
	}
	return s.AdoptIPAddress(Identity{
		Label:          config.Label,
		InterfaceName:  config.InterfaceName,
		IP:             net.ParseIP(config.IP),
		MAC:            HardwareAddr(mac),
		SubnetPrefix:   config.SubnetPrefix,
		DefaultGateway: net.ParseIP(config.DefaultGateway),
		MTU:            uint32(config.MTU),
	})
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
	closeErr := item.Close()
	if captureErr != nil {
		return captureErr
	}
	return closeErr
}

func (s *Manager) ResolveDNSAdoptedIPAddress(request operations.ResolveDNSAdoptedIPAddressRequest) (operations.ResolveDNSAdoptedIPAddressResult, error) {
	source, err := s.lookupAdoptedIP(request.SourceIP)
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	return operations.ResolveDNSWithDialer(request, source.engine.DialTCP, source.engine.DialUDP)
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
	storedScript, err := s.scriptStore().Lookup(scriptName)
	if err != nil {
		if errors.Is(err, storage.ErrStoredScriptNotFound) {
			return nil, script.MissingStoredScriptError(scriptName)
		}
		return nil, err
	}
	return storedScript.Compiled, nil
}

func (s *Manager) scriptStore() *storage.ScriptStore {
	if s == nil {
		return storage.NewScriptStore()
	}
	if s.scripts == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.scripts == nil {
			s.scripts = storage.NewScriptStore()
		}
	}
	return s.scripts
}

func (s *Manager) adoptIdentity(identity Identity, listener adoptionListener) (adopted Identity, err error) {
	defer func() {
		if err == nil {
			return
		}
		if identity.engine != nil {
			_ = identity.Close()
		}
		s.mu.Lock()
		closeListener := s.closeUnusedInterfaceListenerLocked(identity.InterfaceName)
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

func (s *Manager) ForwardFrame(destinationIP net.IP, frame buffer.Buffer) bool {
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

	created, err := netruntime.NewInterfaceListener(iface, s.ForwardFrame)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.interfaceListeners == nil {
		s.interfaceListeners = make(map[string]adoptionListener)
	}
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

func (s *Manager) closeUnusedInterfaceListenerLocked(interfaceName string) adoptionListener {
	if s.interfaceCaptureFilterLocked(interfaceName) != "" {
		return nil
	}
	if listener := s.interfaceListeners[interfaceName]; listener != nil {
		delete(s.interfaceListeners, interfaceName)
		return listener
	}
	return nil
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

func (s *Manager) Close() error {
	s.mu.Lock()
	items := make([]*Identity, 0, len(s.entries))
	for key, item := range s.entries {
		delete(s.entries, key)
		items = append(items, item)
	}
	listeners := make([]adoptionListener, 0, len(s.interfaceListeners))
	for interfaceName, listener := range s.interfaceListeners {
		delete(s.interfaceListeners, interfaceName)
		listeners = append(listeners, listener)
	}
	s.mu.Unlock()

	var closeErr error
	for _, item := range items {
		if err := item.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	for _, listener := range listeners {
		listener.Close()
	}
	return closeErr
}
