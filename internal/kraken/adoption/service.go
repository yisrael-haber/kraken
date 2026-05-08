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
	entries    map[string]*Identity
	routeMatch RouteMatchFunc
}

func NewManager(routeMatch RouteMatchFunc) *Manager {
	if routeMatch == nil {
		panic("adoption: route match dependency is required")
	}

	return &Manager{
		entries:    make(map[string]*Identity),
		routeMatch: routeMatch,
	}
}

func (s *Manager) Adopt(request Identity, listener Listener) (Identity, error) {
	if err := normalizeIdentity(&request); err != nil {
		return Identity{}, err
	}

	return s.adoptIdentity(request, listener)
}

func (s *Manager) Update(request UpdateAdoptedIPAddressRequest, listener Listener) (Identity, error) {
	currentIP, err := common.NormalizeAdoptionIP(request.CurrentIP)
	if err != nil {
		return Identity{}, fmt.Errorf("currentIP: %w", err)
	}

	if err := normalizeIdentity(&request.Identity); err != nil {
		return Identity{}, err
	}

	return s.updateIdentity(currentIP, request.Identity, listener)
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

func (s *Manager) Details(ipText string) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return Identity{}, err
	}

	item, listener, err := s.entryAndListenerForIP(ip)
	if err != nil {
		return Identity{}, err
	}

	return s.details(item, listener), nil
}

func (s *Manager) UpdateScripts(ipText, transportScriptName, applicationScriptName string) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}
	transportScriptName = strings.TrimSpace(transportScriptName)
	applicationScriptName = strings.TrimSpace(applicationScriptName)

	key := ip.String()

	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		return errAdoptedIPNotFound(ip)
	}

	previousTransportScriptName := item.TransportScriptName
	previousApplicationScriptName := item.ApplicationScriptName
	item.TransportScriptName = transportScriptName
	item.ApplicationScriptName = applicationScriptName
	listener := item.listener
	s.mu.Unlock()

	if listener == nil {
		return nil
	}

	if err := listener.EnsureIdentity(item); err != nil {
		s.mu.Lock()
		item.TransportScriptName = previousTransportScriptName
		item.ApplicationScriptName = previousApplicationScriptName
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

	item, listener, err := s.entryAndListenerForIP(ip)
	if err != nil {
		return Identity{}, err
	}
	if _, err := listener.StartRecording(item, outputPath); err != nil {
		return Identity{}, err
	}
	return s.details(item, listener), nil
}

func (s *Manager) StopRecording(ipText string) (Identity, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return Identity{}, err
	}

	item, listener, err := s.entryAndListenerForIP(ip)
	if err != nil {
		return Identity{}, err
	}
	if err := listener.StopRecording(ip); err != nil {
		return Identity{}, err
	}
	return s.details(item, listener), nil
}

func (s *Manager) StartService(request StartAdoptedIPAddressServiceRequest) (Identity, error) {
	ip, service, err := normalizeServiceRequest(request.IP, request.Service)
	if err != nil {
		return Identity{}, err
	}

	item, listener, err := s.entryAndListenerForIP(ip)
	if err != nil {
		return Identity{}, err
	}
	if _, err := listener.StartService(item, service, request.Config); err != nil {
		return Identity{}, err
	}
	return s.details(item, listener), nil
}

func (s *Manager) StopService(request StopAdoptedIPAddressServiceRequest) (Identity, error) {
	ip, service, err := normalizeServiceRequest(request.IP, request.Service)
	if err != nil {
		return Identity{}, err
	}

	item, listener, err := s.entryAndListenerForIP(ip)
	if err != nil {
		return Identity{}, err
	}
	if err := listener.StopService(ip, service); err != nil {
		return Identity{}, err
	}
	return s.details(item, listener), nil
}

func (s *Manager) Release(ipText string) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	key := ip.String()

	var listener Listener
	var retained bool

	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		return errAdoptedIPNotFound(ip)
	}

	delete(s.entries, key)
	listener = item.listener

	retained = s.interfaceHasEntriesLocked(item.InterfaceName)
	s.mu.Unlock()

	if listener == nil {
		return nil
	}

	if retained {
		listener.ForgetIdentity(ip)
		if err := listener.StopRecording(ip); err != nil {
			return err
		}
		return nil
	}

	return listener.Close()
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

func (s *Manager) adoptIdentity(identity Identity, listener Listener) (Identity, error) {
	key := identity.IP.String()

	if listener == nil {
		return Identity{}, fmt.Errorf("listener for interface %s is not registered", identity.InterfaceName)
	}
	if err := listener.Healthy(); err != nil {
		return Identity{}, err
	}
	identity.listener = listener

	s.mu.Lock()
	if _, exists := s.entries[key]; exists {
		s.mu.Unlock()
		return Identity{}, errAdoptedIPAlreadyExists(identity.IP)
	}

	s.entries[key] = &identity
	s.mu.Unlock()

	if err := listener.EnsureIdentity(&identity); err != nil {
		s.mu.Lock()
		delete(s.entries, key)
		s.mu.Unlock()
		return Identity{}, err
	}

	return identity, nil
}

func (s *Manager) updateIdentity(currentIP net.IP, updated Identity, listener Listener) (Identity, error) {
	currentKey := currentIP.String()
	newKey := updated.IP.String()

	var listenerToClose Listener
	var listenerToStopRecording Listener
	stopRecordingIP := currentIP

	if listener == nil {
		return Identity{}, fmt.Errorf("listener for interface %s is not registered", updated.InterfaceName)
	}
	if err := listener.Healthy(); err != nil {
		return Identity{}, err
	}

	s.mu.Lock()
	item, exists := s.entries[currentKey]
	if !exists {
		s.mu.Unlock()
		return Identity{}, errAdoptedIPNotFound(currentIP)
	}

	if currentKey != newKey {
		if _, exists := s.entries[newKey]; exists {
			s.mu.Unlock()
			return Identity{}, errAdoptedIPAlreadyExists(updated.IP)
		}
	}

	delete(s.entries, currentKey)

	updated.TransportScriptName = item.TransportScriptName
	updated.ApplicationScriptName = item.ApplicationScriptName
	updated.listener = listener
	s.entries[newKey] = &updated

	if item.InterfaceName != updated.InterfaceName && !s.interfaceHasEntriesLocked(item.InterfaceName) {
		listenerToClose = item.listener
	} else if item.InterfaceName != updated.InterfaceName || currentKey != newKey {
		listenerToStopRecording = item.listener
	}
	s.mu.Unlock()

	if err := listener.EnsureIdentity(&updated); err != nil {
		s.mu.Lock()
		delete(s.entries, newKey)
		s.entries[currentKey] = item
		s.mu.Unlock()
		return Identity{}, err
	}

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

func (s *Manager) entryForIP(ip net.IP) (*Identity, bool) {
	s.mu.RLock()
	item, exists := s.entries[ip.String()]
	s.mu.RUnlock()
	return item, exists
}

func (s *Manager) entryAndListenerForIP(ip net.IP) (*Identity, Listener, error) {
	item, exists := s.entryForIP(ip)
	if !exists {
		return nil, nil, errAdoptedIPNotFound(ip)
	}

	listener := item.listener
	if listener == nil {
		return nil, nil, fmt.Errorf("listener for interface %s is not registered", item.InterfaceName)
	}
	if err := listener.Healthy(); err != nil {
		return nil, nil, err
	}

	return item, listener, nil
}

func (s *Manager) details(item *Identity, listener Listener) Identity {
	status := listener.StatusSnapshot(item.IP)
	snapshot := *item
	snapshot.Capture = status.Capture
	snapshot.ScriptError = status.ScriptError
	snapshot.Recording = listener.RecordingSnapshot(item.IP)
	snapshot.Services = listener.ServiceSnapshot(item.IP)
	return snapshot
}

func (s *Manager) interfaceHasEntriesLocked(interfaceName string) bool {
	for _, item := range s.entries {
		if item.InterfaceName == interfaceName {
			return true
		}
	}

	return false
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
		return item.listener, item.listener != nil
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

	return item.listener, item.listener != nil
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
	s.mu.Lock()
	listenersByInterface := make(map[string]Listener, len(s.entries))
	for key, item := range s.entries {
		delete(s.entries, key)
		if item.listener != nil {
			listenersByInterface[item.InterfaceName] = item.listener
		}
	}
	s.mu.Unlock()

	var closeErr error
	for _, listener := range listenersByInterface {
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
