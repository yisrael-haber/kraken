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
	mu              sync.RWMutex
	entries         map[[4]byte]*Identity
	configs         *storage.ConfigStore
	scripts         *storage.ScriptStore
	routingPacketIO *netruntime.InterfacePacketIO
	routingErr      error
}

type adoptionListener interface {
	netruntime.PacketEndpoint
	CaptureIPv4Target(ip net.IP) error
}

func NewManager() *Manager {
	manager := &Manager{
		entries: make(map[[4]byte]*Identity),
		configs: storage.NewConfigStore(),
		scripts: storage.NewScriptStore(),
	}
	manager.routingErr = manager.openRouting()
	return manager
}

func (s *Manager) AdoptIPAddress(request Identity) (Identity, error) {
	if s.routingErr != nil {
		return Identity{}, s.routingErr
	}
	iface, err := net.InterfaceByName(strings.TrimSpace(request.InterfaceName))
	if err != nil {
		return Identity{}, err
	}
	listener, err := netruntime.NewInterfaceListener(*iface, s.ForwardFrame)
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

func (s *Manager) SaveStoredAdoptionConfiguration(config storage.StoredAdoptionConfiguration) (storage.StoredAdoptionConfiguration, error) {
	return s.configs.Save(config)
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

func (s *Manager) GetStoredScript(ref storage.StoredScriptRef) (storage.StoredScript, error) {
	return s.scriptStore().Get(ref)
}

func (s *Manager) SaveStoredScript(request storage.SaveStoredScriptRequest) (storage.StoredScript, error) {
	saved, err := s.scriptStore().Save(request)
	if err != nil || saved.Compiled == nil || saved.Surface != storage.SurfaceTransport {
		return saved, err
	}
	s.mu.RLock()
	for _, item := range s.entries {
		transportScriptName, _ := item.engine.ScriptNames()
		if transportScriptName == saved.Name {
			item.engine.UpdateTransportScript(saved.Compiled)
		}
	}
	s.mu.RUnlock()
	return saved, nil
}

func (s *Manager) DeleteStoredScript(ref storage.StoredScriptRef) error {
	return s.scriptStore().Delete(ref)
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
		SubnetMask:     IPv4Mask(net.ParseIP(config.SubnetMask).To4()),
		DefaultGateway: net.ParseIP(config.DefaultGateway),
		MTU:            uint32(config.MTU),
	})
}

func (s *Manager) UpdateAdoptedIPAddressScripts(ip, transportScriptName, applicationScriptName string) (Identity, error) {
	item, err := s.lookupAdoptedIP(ip)
	if err != nil {
		return Identity{}, err
	}
	transportScript, err := s.lookupScript(transportScriptName, storage.SurfaceTransport)
	if err != nil {
		return Identity{}, err
	}
	applicationScript, err := s.lookupScript(applicationScriptName, storage.SurfaceApplication)
	if err != nil {
		return Identity{}, err
	}
	item.engine.UpdateTransportScript(transportScript)
	item.engine.UpdateApplicationScript(applicationScript)
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
	captureErr := s.refreshRoutingCaptureLocked()
	s.mu.Unlock()

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

func (s *Manager) lookupScript(scriptName string, surface storage.Surface) (*script.CompiledScript, error) {
	scriptName = strings.TrimSpace(scriptName)
	if scriptName == "" {
		return nil, nil
	}
	storedScript, err := s.scriptStore().Lookup(storage.StoredScriptRef{
		Name:    scriptName,
		Surface: surface,
	})
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
		} else {
			listener.Close()
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
	if err = listener.CaptureIPv4Target(identity.IP); err != nil {
		return Identity{}, err
	}
	s.entries[key] = &identity
	if err = s.refreshRoutingCaptureLocked(); err != nil {
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
		mask := net.IPMask(item.SubnetMask)
		if network := item.IP.Mask(mask); !network.Equal(destinationIP.Mask(mask)) {
			continue
		}
		prefix, _ := mask.Size()
		if prefix > selectedPrefix {
			selected = item
			selectedPrefix = prefix
		}
	}
	return selected
}

func identityKey(ip net.IP) [4]byte {
	return *(*[4]byte)(ip)
}

func errAdoptedIPNotFound(ip net.IP) error {
	return fmt.Errorf("IP %s is not currently adopted", ip)
}

func (s *Manager) Close() error {
	s.mu.Lock()
	routingPacketIO := s.routingPacketIO
	s.routingPacketIO = nil
	items := make([]*Identity, 0, len(s.entries))
	for key, item := range s.entries {
		delete(s.entries, key)
		items = append(items, item)
	}
	s.mu.Unlock()

	var closeErr error
	if routingPacketIO != nil {
		routingPacketIO.Close()
	}
	for _, item := range items {
		if err := item.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}
