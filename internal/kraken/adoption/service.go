package adoption

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const (
	defaultAdoptedPingCount = 4
	defaultIdentityMTU      = 1500
)

type Manager struct {
	mu         sync.RWMutex
	listenerMu sync.Mutex
	entries    map[string]Identity
	listeners  map[string]Listener
	routeMatch RouteMatchFunc
}

func NewManager(routeMatch RouteMatchFunc) *Manager {
	if routeMatch == nil {
		panic("adoption: route match dependency is required")
	}

	return &Manager{
		entries:    make(map[string]Identity),
		listeners:  make(map[string]Listener),
		routeMatch: routeMatch,
	}
}

func (s *Manager) Adopt(request Identity) (Identity, error) {
	if err := normalizeIdentity(&request); err != nil {
		return Identity{}, err
	}

	return s.adoptIdentity(request)
}

func (s *Manager) Update(request UpdateAdoptedIPAddressRequest) (Identity, error) {
	currentIP, err := common.NormalizeAdoptionIP(request.CurrentIP)
	if err != nil {
		return Identity{}, fmt.Errorf("currentIP: %w", err)
	}

	if err := normalizeIdentity(&request.Identity); err != nil {
		return Identity{}, err
	}

	return s.updateIdentity(currentIP, request.Identity)
}

func (s *Manager) Snapshot() []Identity {
	s.mu.RLock()
	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, item)
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

func (s *Manager) HasListener(interfaceName string) bool {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	_, exists := s.listeners[interfaceName]
	return exists
}

func (s *Manager) SetListener(iface net.Interface, listener Listener) error {
	if listener == nil {
		return fmt.Errorf("listener is required")
	}

	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	for _, identity := range s.snapshotEntriesForInterface(iface.Name) {
		if err := listener.EnsureIdentity(identity); err != nil {
			return err
		}
	}

	s.listeners[iface.Name] = listener
	return nil
}

func (s *Manager) Details(ipText string) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return Identity{}, err
	}

	item, listener, err := s.entryAndListenerForIP(ip)
	if err != nil {
		return Identity{}, err
	}

	item.ARPCacheEntries = listener.ARPCacheSnapshot()
	status := listener.StatusSnapshot(item.IP)
	item.Capture = status.Capture
	item.ScriptError = status.ScriptError
	item.Recording = listener.RecordingSnapshot(item.IP)
	item.Services = listener.ServiceSnapshot(item.IP)
	return item, nil
}

func (s *Manager) UpdateScripts(ipText, transportScriptName, applicationScriptName string) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}
	transportScriptName = strings.TrimSpace(transportScriptName)
	applicationScriptName = strings.TrimSpace(applicationScriptName)

	key := ip.String()

	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		return errAdoptedIPNotFound(ip)
	}

	updated := item
	updated.TransportScriptName = transportScriptName
	updated.ApplicationScriptName = applicationScriptName
	s.entries[key] = updated
	listener := s.listeners[item.InterfaceName]
	s.mu.Unlock()

	if listener == nil {
		return nil
	}

	if err := listener.EnsureIdentity(updated); err != nil {
		s.mu.Lock()
		s.entries[key] = item
		s.mu.Unlock()
		return err
	}

	return nil
}

func (s *Manager) StartRecording(ipText, outputPath string) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return Identity{}, err
	}
	if strings.TrimSpace(outputPath) == "" {
		return Identity{}, fmt.Errorf("outputPath is required")
	}

	return s.withEntryListenerDetails(ip, func(item Identity, listener Listener) error {
		_, err := listener.StartRecording(item, outputPath)
		return err
	})
}

func (s *Manager) StopRecording(ipText string) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return Identity{}, err
	}

	return s.withEntryListenerDetails(ip, func(_ Identity, listener Listener) error {
		return listener.StopRecording(ip)
	})
}

func (s *Manager) StartService(request StartAdoptedIPAddressServiceRequest) (Identity, error) {
	ip, service, err := normalizeServiceRequest(request.IP, request.Service)
	if err != nil {
		return Identity{}, err
	}

	return s.withEntryListenerDetails(ip, func(item Identity, listener Listener) error {
		_, err := listener.StartService(item, service, request.Config)
		return err
	})
}

func (s *Manager) StopService(request StopAdoptedIPAddressServiceRequest) (Identity, error) {
	ip, service, err := normalizeServiceRequest(request.IP, request.Service)
	if err != nil {
		return Identity{}, err
	}

	return s.withEntryListenerDetails(ip, func(_ Identity, listener Listener) error {
		return listener.StopService(ip, service)
	})
}

func (s *Manager) Release(ipText string) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	key := ip.String()

	var listener Listener
	var stopRecording bool

	s.listenerMu.Lock()
	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		s.listenerMu.Unlock()
		return errAdoptedIPNotFound(ip)
	}

	delete(s.entries, key)

	if !s.interfaceHasEntriesLocked(item.InterfaceName) {
		listener = s.listeners[item.InterfaceName]
		delete(s.listeners, item.InterfaceName)
	} else {
		listener = s.listeners[item.InterfaceName]
		stopRecording = listener != nil
	}
	s.mu.Unlock()
	s.listenerMu.Unlock()

	if stopRecording {
		listener.ForgetIdentity(ip)
		if err := listener.StopRecording(ip); err != nil {
			return err
		}
	}

	if listener != nil && !stopRecording {
		return listener.Close()
	}

	return nil
}

func (s *Manager) Ping(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, error) {
	sourceIP, err := common.NormalizeAdoptionIP(request.SourceIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("sourceIP: %w", err)
	}

	targetIP, err := common.NormalizeAdoptionIP(request.TargetIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("targetIP: %w", err)
	}

	count := request.Count
	if count <= 0 {
		count = defaultAdoptedPingCount
	}

	payload, err := common.ParsePayloadHex(request.PayloadHex)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("payloadHex: %w", err)
	}

	item, listener, err := s.entryAndListenerForIP(sourceIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, err
	}

	return listener.Ping(item, targetIP, count, payload)
}

func (s *Manager) ResolveDNS(request ResolveDNSAdoptedIPAddressRequest) (ResolveDNSAdoptedIPAddressResult, error) {
	sourceIP, err := common.NormalizeAdoptionIP(request.SourceIP)
	if err != nil {
		return ResolveDNSAdoptedIPAddressResult{}, fmt.Errorf("sourceIP: %w", err)
	}

	item, listener, err := s.entryAndListenerForIP(sourceIP)
	if err != nil {
		return ResolveDNSAdoptedIPAddressResult{}, err
	}

	return listener.ResolveDNS(item, request)
}

func (s *Manager) adoptInterfaceWithGatewayAndMTU(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32) (Identity, error) {
	return s.adoptIdentity(newIdentityWithGatewayAndScripts(label, iface, ip, mac, defaultGateway, mtu, "", ""))
}

func (s *Manager) adoptIdentity(identity Identity) (Identity, error) {
	key := identity.IP.String()

	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	if _, err := s.listenerLocked(identity.Interface); err != nil {
		return Identity{}, err
	}

	s.mu.Lock()
	if _, exists := s.entries[key]; exists {
		s.mu.Unlock()
		return Identity{}, errAdoptedIPAlreadyExists(identity.IP)
	}

	s.entries[key] = identity

	listener := s.listeners[identity.InterfaceName]
	s.mu.Unlock()
	if listener != nil {
		if err := listener.EnsureIdentity(identity); err != nil {
			s.mu.Lock()
			delete(s.entries, key)
			s.mu.Unlock()
			return Identity{}, err
		}
	}

	return identity, nil
}

func (s *Manager) updateInterfaceWithGatewayAndMTU(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32) (Identity, error) {
	return s.updateIdentity(currentIP, newIdentityWithGatewayAndScripts(label, iface, ip, mac, defaultGateway, mtu, "", ""))
}

func (s *Manager) updateIdentity(currentIP net.IP, updated Identity) (Identity, error) {
	currentKey := currentIP.String()
	newKey := updated.IP.String()

	var listenerToClose Listener
	var listenerToStopRecording Listener
	var listenerToEnsure Listener
	stopRecordingIP := currentIP

	s.listenerMu.Lock()
	if _, err := s.listenerLocked(updated.Interface); err != nil {
		s.listenerMu.Unlock()
		return Identity{}, err
	}

	s.mu.Lock()
	item, exists := s.entries[currentKey]
	if !exists {
		s.mu.Unlock()
		s.listenerMu.Unlock()
		return Identity{}, errAdoptedIPNotFound(currentIP)
	}

	if currentKey != newKey {
		if _, exists := s.entries[newKey]; exists {
			s.mu.Unlock()
			s.listenerMu.Unlock()
			return Identity{}, errAdoptedIPAlreadyExists(updated.IP)
		}
	}

	delete(s.entries, currentKey)

	updated.TransportScriptName = item.TransportScriptName
	updated.ApplicationScriptName = item.ApplicationScriptName
	s.entries[newKey] = updated
	listenerToEnsure = s.listeners[updated.InterfaceName]

	if item.InterfaceName != updated.InterfaceName && !s.interfaceHasEntriesLocked(item.InterfaceName) {
		listenerToClose = s.listeners[item.InterfaceName]
		delete(s.listeners, item.InterfaceName)
	} else if item.InterfaceName != updated.InterfaceName || currentKey != newKey {
		listenerToStopRecording = s.listeners[item.InterfaceName]
	}
	previousInterfaceName := item.InterfaceName
	s.mu.Unlock()

	if listenerToEnsure != nil {
		if err := listenerToEnsure.EnsureIdentity(updated); err != nil {
			s.mu.Lock()
			delete(s.entries, newKey)
			s.entries[currentKey] = item
			if listenerToClose != nil {
				s.listeners[previousInterfaceName] = listenerToClose
			}
			s.mu.Unlock()
			s.listenerMu.Unlock()
			return Identity{}, err
		}
	}
	s.listenerMu.Unlock()

	if listenerToClose != nil {
		if err := listenerToClose.Close(); err != nil {
			return Identity{}, err
		}
	}

	if listenerToStopRecording != nil {
		listenerToStopRecording.ForgetIdentity(stopRecordingIP)
		if err := listenerToStopRecording.StopRecording(stopRecordingIP); err != nil {
			return Identity{}, err
		}
	}

	return updated, nil
}

func (s *Manager) snapshotEntriesForInterface(interfaceName string) []Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		if item.InterfaceName == interfaceName {
			items = append(items, item)
		}
	}

	return items
}

func (s *Manager) entryForIP(ip net.IP) (Identity, bool) {
	s.mu.RLock()
	item, exists := s.entries[ip.String()]
	s.mu.RUnlock()
	return item, exists
}

func (s *Manager) entryAndListenerForIP(ip net.IP) (Identity, Listener, error) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	return s.entryAndListenerForIPLocked(ip)
}

func (s *Manager) withEntryListenerDetails(ip net.IP, apply func(Identity, Listener) error) (Identity, error) {
	s.listenerMu.Lock()
	item, listener, err := s.entryAndListenerForIPLocked(ip)
	if err == nil {
		err = apply(item, listener)
	}
	s.listenerMu.Unlock()
	if err != nil {
		return Identity{}, err
	}

	item.ARPCacheEntries = listener.ARPCacheSnapshot()
	status := listener.StatusSnapshot(item.IP)
	item.Capture = status.Capture
	item.ScriptError = status.ScriptError
	item.Recording = listener.RecordingSnapshot(item.IP)
	item.Services = listener.ServiceSnapshot(item.IP)
	return item, nil
}

func (s *Manager) entryAndListenerForIPLocked(ip net.IP) (Identity, Listener, error) {
	item, exists := s.entryForIP(ip)
	if !exists {
		return Identity{}, nil, errAdoptedIPNotFound(ip)
	}

	listener, err := s.listenerLocked(item.Interface)
	if err != nil {
		return Identity{}, nil, err
	}

	return item, listener, nil
}

func (s *Manager) interfaceHasEntriesLocked(interfaceName string) bool {
	for _, item := range s.entries {
		if item.InterfaceName == interfaceName {
			return true
		}
	}

	return false
}

func (s *Manager) listenerLocked(iface net.Interface) (Listener, error) {
	if existing, exists := s.listeners[iface.Name]; exists {
		if err := existing.Healthy(); err != nil {
			return nil, err
		}
		return existing, nil
	}

	return nil, fmt.Errorf("listener for interface %s is not registered", iface.Name)
}

func (s *Manager) ResolveForwarding(destinationIP net.IP) (Listener, bool) {
	destinationIP = destinationIP.To4()
	if destinationIP == nil {
		return nil, false
	}

	s.mu.RLock()
	item, exists := s.entries[destinationIP.String()]
	s.mu.RUnlock()
	if exists {
		return s.forwardingListenerForEntry(item)
	}

	route, exists := s.routeMatch(destinationIP)
	if !exists {
		return nil, false
	}

	viaIP, err := common.NormalizeAdoptionIP(route.ViaAdoptedIP)
	if err != nil {
		return nil, false
	}
	s.mu.RLock()
	item, exists = s.entries[viaIP.String()]
	s.mu.RUnlock()
	if !exists {
		return nil, false
	}

	return s.forwardingListenerForEntry(item)
}

func (s *Manager) forwardingListenerForEntry(item Identity) (Listener, bool) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	listener, err := s.listenerLocked(item.Interface)
	if err != nil {
		return nil, false
	}

	return listener, true
}

func errAdoptedIPNotFound(ip net.IP) error {
	return fmt.Errorf("IP %s is not currently adopted", ip)
}

func errAdoptedIPAlreadyExists(ip net.IP) error {
	return fmt.Errorf("IP %s is already adopted", ip)
}

func normalizeServiceRequest(ipText, serviceText string) (net.IP, string, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return nil, "", fmt.Errorf("ip: %w", err)
	}

	service := strings.ToLower(strings.TrimSpace(serviceText))
	if service == "" {
		return nil, "", fmt.Errorf("service is required")
	}

	return ip, service, nil
}

func (s *Manager) Close() error {
	s.listenerMu.Lock()
	listeners := make([]Listener, 0, len(s.listeners))
	for key, listener := range s.listeners {
		delete(s.listeners, key)
		if listener != nil {
			listeners = append(listeners, listener)
		}
	}
	s.listenerMu.Unlock()

	var closeErr error
	for _, listener := range listeners {
		if err := listener.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}

	return closeErr
}

func normalizeIdentityMTU(iface net.Interface, mtu int) (uint32, error) {
	if mtu == 0 {
		mtu = iface.MTU
	}
	if mtu == 0 {
		mtu = defaultIdentityMTU
	}
	if mtu < 68 || mtu > 65535 {
		return 0, fmt.Errorf("mtu must be between 68 and 65535")
	}
	return uint32(mtu), nil
}
