package adoption

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
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
	routingStop     chan struct{}
	routingDone     chan struct{}
}

func NewManager() *Manager {
	return &Manager{
		entries: make(map[[4]byte]*Identity),
		configs: storage.NewConfigStore(),
		scripts: storage.NewScriptStore(),
	}
}

func (s *Manager) ListAdoptionInterfaces() (interfacespkg.Selection, error) {
	return interfacespkg.List()
}

func (s *Manager) GetConfigurationDirectory() (string, error) {
	return storage.DefaultKrakenConfigRoot()
}

func (s *Manager) AdoptIPAddress(request Identity) (Identity, error) {
	listener, err := s.listener(request.InterfaceName)
	if err != nil {
		return Identity{}, err
	}
	return s.Adopt(request, listener)
}

func (s *Manager) ListAdoptedIPAddresses() []Identity {
	return s.Snapshot()
}

func (s *Manager) GetAdoptedIPAddressDetails(ip string) (Identity, error) {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return Identity{}, err
	}
	return s.Lookup(adoptedIP)
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
	items, err := s.scripts.List()
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
	return s.scripts.Get(ref)
}

func (s *Manager) SaveStoredScript(request storage.SaveStoredScriptRequest) (storage.StoredScript, error) {
	return s.scripts.Save(request)
}

func (s *Manager) DeleteStoredScript(ref storage.StoredScriptRef) error {
	return s.scripts.Delete(ref)
}

func (s *Manager) RefreshStoredScripts() ([]storage.StoredScriptSummary, error) {
	if _, err := s.scripts.Refresh(); err != nil {
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
		Interface:      net.Interface{Name: config.InterfaceName},
		IP:             net.ParseIP(config.IP),
		MAC:            HardwareAddr(mac),
		SubnetMask:     IPv4Mask(net.ParseIP(config.SubnetMask).To4()),
		DefaultGateway: net.ParseIP(config.DefaultGateway),
		MTU:            uint32(config.MTU),
	})
}

func (s *Manager) UpdateAdoptedIPAddressScripts(request UpdateAdoptedIPAddressScriptsRequest) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return Identity{}, err
	}
	if err := s.UpdateScripts(ip, request.TransportScriptName, request.ApplicationScriptName); err != nil {
		return Identity{}, err
	}
	return s.Lookup(ip)
}

func (s *Manager) UpdateAdoptedIPAddress(request UpdateAdoptedIPAddressRequest) (Identity, error) {
	currentIP, err := common.NormalizeAdoptionIP(request.CurrentIP)
	if err != nil {
		return Identity{}, err
	}
	if err := s.Release(currentIP); err != nil {
		return Identity{}, err
	}
	return s.AdoptIPAddress(request.Identity)
}

func (s *Manager) ReleaseIPAddress(ip string) error {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return err
	}
	return s.Release(adoptedIP)
}

func (s *Manager) ResolveDNSAdoptedIPAddress(request operations.ResolveDNSAdoptedIPAddressRequest) (operations.ResolveDNSAdoptedIPAddressResult, error) {
	sourceIP, err := common.NormalizeAdoptionIP(request.SourceIP)
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	source, err := s.Lookup(sourceIP)
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	serverIP, serverPort, transport, timeout, err := operations.DNSDialTarget(request)
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	var conn net.Conn
	if transport == "tcp" {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err = source.DialTCP(ctx, serverIP, serverPort)
	} else {
		conn, err = source.DialUDP(serverIP, serverPort)
	}
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	defer conn.Close()
	return operations.ResolveDNS(conn, request)
}

func (s *Manager) StartAdoptedIPAddressRecording(request StartAdoptedIPAddressRecordingRequest) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return Identity{}, err
	}
	outputPath := strings.TrimSpace(request.OutputPath)
	if outputPath == "" {
		downloadsDir, err := storage.DefaultDownloadsDir()
		if err != nil {
			return Identity{}, err
		}
		outputPath = filepath.Join(downloadsDir, fmt.Sprintf("%s-%s.pcap", ip.String(), time.Now().UTC().Format("20060102-150405")))
	}
	return s.StartRecording(ip, outputPath)
}

func (s *Manager) StopAdoptedIPAddressRecording(ip string) (Identity, error) {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return Identity{}, err
	}
	return s.StopRecording(adoptedIP)
}

func (s *Manager) ListServiceDefinitions() []ServiceDefinition {
	return ListServiceDefinitions()
}

func (s *Manager) StartAdoptedIPAddressService(request StartAdoptedIPAddressServiceRequest) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return Identity{}, err
	}
	return s.StartConfiguredService(ip, request.Service, request.Config)
}

func (s *Manager) StopAdoptedIPAddressService(request StopAdoptedIPAddressServiceRequest) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return Identity{}, err
	}
	return s.StopService(ip, request.Service)
}

func (s *Manager) Shutdown() error {
	return s.Close()
}

func (s *Manager) Adopt(request Identity, listener Listener) (Identity, error) {
	if err := prepareIdentity(&request); err != nil {
		return Identity{}, err
	}
	if err := s.startRouting(); err != nil {
		if listener != nil {
			_ = listener.Close()
		}
		return Identity{}, err
	}

	return s.adoptIdentity(request, listener)
}

func (s *Manager) listener(interfaceName string) (Listener, error) {
	iface, err := net.InterfaceByName(strings.TrimSpace(interfaceName))
	if err != nil {
		return nil, err
	}
	return netruntime.NewInterfaceListener(*iface, s.ForwardFrame)
}

func (s *Manager) Snapshot() []Identity {
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

func (s *Manager) UpdateScripts(ip net.IP, transportScriptName, applicationScriptName string) error {
	transportScriptName = strings.TrimSpace(transportScriptName)
	applicationScriptName = strings.TrimSpace(applicationScriptName)

	item, err := s.lookup(ip)
	if err != nil {
		return err
	}
	transportScript, err := s.lookupScript(transportScriptName, storage.SurfaceTransport)
	if err != nil {
		return err
	}
	applicationScript, err := s.lookupScript(applicationScriptName, storage.SurfaceApplication)
	if err != nil {
		return err
	}
	item.transportScript = transportScript
	item.applicationScript = applicationScript
	item.engine.UpdateTransportScript(transportScript)
	item.engine.UpdateApplicationScript(applicationScript)
	return nil
}

func (s *Manager) StopRecording(ip net.IP) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if recorder := item.TakeRecorder(); recorder != nil {
		recorder.Stop()
	}
	item.Recording = nil
	return *item, nil
}

func (s *Manager) StartService(ip net.IP, status ManagedService, start func(net.Listener) (ServiceProcess, error)) (Identity, error) {
	if strings.TrimSpace(status.Service) == "" {
		return Identity{}, fmt.Errorf("service is required")
	}
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if previous := item.takeService(status.Service); previous != nil {
		previous.Stop()
	}

	listener, err := item.ListenTCP(status.Port)
	if err != nil {
		return Identity{}, err
	}
	process, err := start(listener)
	if err != nil {
		_ = listener.Close()
		return Identity{}, err
	}
	service := NewManagedService(status)
	service.Start(process)
	item.storeService(service)
	return *item, nil
}

func (s *Manager) StopService(ip net.IP, service string) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if running := item.takeService(service); running != nil {
		running.Stop()
	}
	return *item, nil
}

func (s *Manager) lookupScript(scriptName string, surface storage.Surface) (*script.CompiledScript, error) {
	if scriptName == "" {
		return nil, nil
	}
	storedScript, err := s.scripts.Lookup(storage.StoredScriptRef{
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

func (s *Manager) Release(ip net.IP) error {
	key := identityKey(ip)

	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		return errAdoptedIPNotFound(ip)
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

func (s *Manager) adoptIdentity(identity Identity, listener Listener) (Identity, error) {
	key := identityKey(identity.IP)

	if listener == nil {
		return Identity{}, fmt.Errorf("listener for interface %s is not registered", identity.InterfaceName)
	}
	closeListener := true
	defer func() {
		if closeListener {
			_ = listener.Close()
		}
	}()

	if err := identity.Init(listener, identity.transportScript, identity.applicationScript); err != nil {
		return Identity{}, err
	}

	s.mu.Lock()
	if _, exists := s.entries[key]; exists {
		s.mu.Unlock()
		return Identity{}, fmt.Errorf("IP %s is already adopted", identity.IP)
	}
	s.entries[key] = &identity
	s.mu.Unlock()

	if err := listener.CaptureIPv4Target(identity.IP); err != nil {
		s.mu.Lock()
		delete(s.entries, key)
		s.mu.Unlock()
		return Identity{}, err
	}
	s.mu.Lock()
	if err := s.refreshRoutingCaptureLocked(); err != nil {
		delete(s.entries, key)
		s.mu.Unlock()
		return Identity{}, err
	}
	s.mu.Unlock()

	closeListener = false
	return identity, nil
}

func (s *Manager) Lookup(ip net.IP) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	return *item, nil
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
	item.InjectFrame(frame)
	return true
}

func (s *Manager) routeIdentity(destinationIP net.IP) *Identity {
	var selected *Identity
	selectedPrefix := -1
	for _, item := range s.entries {
		mask := net.IPMask(item.SubnetMask)
		if len(mask) != net.IPv4len {
			continue
		}
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
	return *(*[4]byte)(ip.To4())
}

func errAdoptedIPNotFound(ip net.IP) error {
	return fmt.Errorf("IP %s is not currently adopted", ip)
}

func (s *Manager) Close() error {
	s.mu.Lock()
	routingPacketIO := s.routingPacketIO
	routingStop := s.routingStop
	routingDone := s.routingDone
	s.routingPacketIO = nil
	s.routingStop = nil
	s.routingDone = nil
	items := make([]*Identity, 0, len(s.entries))
	for key, item := range s.entries {
		delete(s.entries, key)
		items = append(items, item)
	}
	s.mu.Unlock()

	var closeErr error
	if routingPacketIO != nil {
		close(routingStop)
		routingPacketIO.Close()
		<-routingDone
	}
	for _, item := range items {
		if err := item.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}
