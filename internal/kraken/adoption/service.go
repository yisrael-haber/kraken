package adoption

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
)

const (
	defaultAdoptedPingCount = 4
	defaultIdentityMTU      = 1500
)

type Service struct {
	mu           sync.RWMutex
	listenerMu   sync.Mutex
	entries      map[string]Identity
	listeners    map[string]Listener
	snapshot     []AdoptedIPAddress
	snapshotLive bool
	routeMatch   RouteMatchFunc
	scriptLookup ScriptLookupFunc
	newListener  NewListenerFunc
}

func NewService(scriptLookup ScriptLookupFunc, routeMatch RouteMatchFunc, newListener NewListenerFunc) *Service {
	if scriptLookup == nil {
		panic("adoption: script lookup dependency is required")
	}
	if routeMatch == nil {
		panic("adoption: route match dependency is required")
	}
	if newListener == nil {
		panic("adoption: listener factory dependency is required")
	}

	return &Service{
		entries:      make(map[string]Identity),
		listeners:    make(map[string]Listener),
		routeMatch:   routeMatch,
		scriptLookup: scriptLookup,
		newListener:  newListener,
	}
}

func (s *Service) Adopt(request AdoptIPAddressRequest) (AdoptedIPAddress, error) {
	label, iface, ip, mac, defaultGateway, mtu, err := resolveIdentity(
		request.Label,
		request.InterfaceName,
		request.IP,
		request.MAC,
		request.DefaultGateway,
		request.MTU,
	)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return s.adoptInterfaceWithGatewayAndMTU(label, iface, ip, mac, defaultGateway, mtu)
}

func (s *Service) Update(request UpdateAdoptedIPAddressRequest) (AdoptedIPAddress, error) {
	currentIP, err := common.NormalizeAdoptionIP(request.CurrentIP)
	if err != nil {
		return AdoptedIPAddress{}, fmt.Errorf("currentIP: %w", err)
	}

	label, iface, ip, mac, defaultGateway, mtu, err := resolveIdentity(
		request.Label,
		request.InterfaceName,
		request.IP,
		request.MAC,
		request.DefaultGateway,
		request.MTU,
	)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return s.updateInterfaceWithGatewayAndMTU(currentIP, label, iface, ip, mac, defaultGateway, mtu)
}

func (s *Service) Snapshot() []AdoptedIPAddress {
	s.mu.RLock()
	if s.snapshotLive {
		items := append([]AdoptedIPAddress(nil), s.snapshot...)
		s.mu.RUnlock()
		return items
	}
	s.mu.RUnlock()

	s.mu.Lock()
	if !s.snapshotLive {
		s.snapshot = snapshotAdoptedIPAddresses(s.entries)
		s.snapshotLive = true
	}
	items := append([]AdoptedIPAddress(nil), s.snapshot...)
	s.mu.Unlock()
	return items
}

func (s *Service) Details(ipText string) (AdoptedIPAddressDetails, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	item, listener, err := s.entryAndListenerForIP(ip)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return detailsWithListener(item, listener), nil
}

func (s *Service) UpdateScripts(ipText, transportScriptName, applicationScriptName string) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}
	transportScriptName = NormalizeScriptName(transportScriptName)
	applicationScriptName = NormalizeScriptName(applicationScriptName)

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
	listener := s.listeners[item.Interface.Name]
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

func (s *Service) StartRecording(ipText, outputPath string) (AdoptedIPAddressDetails, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}
	if strings.TrimSpace(outputPath) == "" {
		return AdoptedIPAddressDetails{}, fmt.Errorf("outputPath is required")
	}

	return s.withEntryListenerDetails(ip, func(item Identity, listener Listener) error {
		_, err := listener.StartRecording(item, outputPath)
		return err
	})
}

func (s *Service) StopRecording(ipText string) (AdoptedIPAddressDetails, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return s.withEntryListenerDetails(ip, func(_ Identity, listener Listener) error {
		return listener.StopRecording(ip)
	})
}

func (s *Service) StartService(request StartAdoptedIPAddressServiceRequest) (AdoptedIPAddressDetails, error) {
	ip, service, err := normalizeServiceRequest(request.IP, request.Service)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}
	config, err := normalizeServiceConfig(request.Config)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}
	if portText := config["port"]; portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil {
			return AdoptedIPAddressDetails{}, fmt.Errorf("port: %w", err)
		}
		if port <= 0 || port > 65535 {
			return AdoptedIPAddressDetails{}, fmt.Errorf("port must be between 1 and 65535")
		}
		config["port"] = fmt.Sprintf("%d", port)
	}

	return s.withEntryListenerDetails(ip, func(item Identity, listener Listener) error {
		_, err := listener.StartService(item, service, config)
		return err
	})
}

func normalizeServiceConfig(config map[string]string) (map[string]string, error) {
	if len(config) == 0 {
		return nil, nil
	}

	normalized := make(map[string]string, len(config))
	for key, value := range config {
		name := strings.TrimSpace(key)
		if name == "" {
			return nil, fmt.Errorf("service config field name is required")
		}
		normalized[name] = strings.TrimSpace(value)
	}

	return normalized, nil
}

func (s *Service) StopService(request StopAdoptedIPAddressServiceRequest) (AdoptedIPAddressDetails, error) {
	ip, service, err := normalizeServiceRequest(request.IP, request.Service)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return s.withEntryListenerDetails(ip, func(_ Identity, listener Listener) error {
		return listener.StopService(ip, service)
	})
}

func (s *Service) Release(ipText string) error {
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
	s.invalidateSnapshotLocked()

	if !s.interfaceHasEntriesLocked(item.Interface.Name) {
		listener = s.listeners[item.Interface.Name]
		delete(s.listeners, item.Interface.Name)
	} else {
		listener = s.listeners[item.Interface.Name]
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

func (s *Service) Ping(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, error) {
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

	payload, err := packetpkg.ParsePayloadHex(request.PayloadHex)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("payloadHex: %w", err)
	}

	item, listener, err := s.entryAndListenerForIP(sourceIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, err
	}

	return listener.Ping(item, targetIP, count, payload)
}

func (s *Service) ResolveDNS(request ResolveDNSAdoptedIPAddressRequest) (ResolveDNSAdoptedIPAddressResult, error) {
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

func (s *Service) adoptInterfaceWithGatewayAndMTU(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32) (AdoptedIPAddress, error) {
	key := ip.String()

	s.mu.RLock()
	_, exists := s.entries[key]
	s.mu.RUnlock()
	if exists {
		return AdoptedIPAddress{}, errAdoptedIPAlreadyExists(ip)
	}

	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	if _, err := s.ensureListenerLocked(iface); err != nil {
		return AdoptedIPAddress{}, err
	}

	s.mu.Lock()
	if _, exists := s.entries[key]; exists {
		s.mu.Unlock()
		return AdoptedIPAddress{}, errAdoptedIPAlreadyExists(ip)
	}

	item := newIdentityWithGatewayAndScripts(label, iface, ip, mac, defaultGateway, mtu, "", "")
	s.entries[key] = item
	s.invalidateSnapshotLocked()

	listener := s.listeners[iface.Name]
	s.mu.Unlock()
	if listener != nil {
		if err := listener.EnsureIdentity(item); err != nil {
			s.mu.Lock()
			delete(s.entries, key)
			s.invalidateSnapshotLocked()
			s.mu.Unlock()
			return AdoptedIPAddress{}, err
		}
	}

	return item.snapshot(), nil
}

func (s *Service) updateInterfaceWithGatewayAndMTU(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32) (AdoptedIPAddress, error) {
	currentKey := currentIP.String()
	newKey := ip.String()

	var listenerToClose Listener
	var listenerToStopRecording Listener
	var listenerToEnsure Listener
	stopRecordingIP := currentIP

	s.listenerMu.Lock()
	if _, err := s.ensureListenerLocked(iface); err != nil {
		s.listenerMu.Unlock()
		return AdoptedIPAddress{}, err
	}

	s.mu.Lock()
	item, exists := s.entries[currentKey]
	if !exists {
		s.mu.Unlock()
		s.listenerMu.Unlock()
		return AdoptedIPAddress{}, errAdoptedIPNotFound(currentIP)
	}

	if currentKey != newKey {
		if _, exists := s.entries[newKey]; exists {
			s.mu.Unlock()
			s.listenerMu.Unlock()
			return AdoptedIPAddress{}, errAdoptedIPAlreadyExists(ip)
		}
	}

	delete(s.entries, currentKey)

	updated := newIdentityWithGatewayAndScripts(label, iface, ip, mac, defaultGateway, mtu, item.TransportScriptName, item.ApplicationScriptName)
	s.entries[newKey] = updated
	s.invalidateSnapshotLocked()
	listenerToEnsure = s.listeners[iface.Name]

	if item.Interface.Name != iface.Name && !s.interfaceHasEntriesLocked(item.Interface.Name) {
		listenerToClose = s.listeners[item.Interface.Name]
		delete(s.listeners, item.Interface.Name)
	} else if item.Interface.Name != iface.Name || currentKey != newKey {
		listenerToStopRecording = s.listeners[item.Interface.Name]
	}
	previousInterfaceName := item.Interface.Name
	s.mu.Unlock()

	if listenerToEnsure != nil {
		if err := listenerToEnsure.EnsureIdentity(updated); err != nil {
			s.mu.Lock()
			delete(s.entries, newKey)
			s.entries[currentKey] = item
			if listenerToClose != nil {
				s.listeners[previousInterfaceName] = listenerToClose
			}
			s.invalidateSnapshotLocked()
			s.mu.Unlock()
			s.listenerMu.Unlock()
			return AdoptedIPAddress{}, err
		}
	}
	s.listenerMu.Unlock()

	if listenerToClose != nil {
		if err := listenerToClose.Close(); err != nil {
			return AdoptedIPAddress{}, err
		}
	}

	if listenerToStopRecording != nil {
		listenerToStopRecording.ForgetIdentity(stopRecordingIP)
		if err := listenerToStopRecording.StopRecording(stopRecordingIP); err != nil {
			return AdoptedIPAddress{}, err
		}
	}

	return updated.snapshot(), nil
}

func (s *Service) snapshotEntriesForInterface(interfaceName string) []Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		if item.Interface.Name == interfaceName {
			items = append(items, item)
		}
	}

	return items
}

func (s *Service) invalidateSnapshotLocked() {
	s.snapshot = nil
	s.snapshotLive = false
}

func snapshotAdoptedIPAddresses(entries map[string]Identity) []AdoptedIPAddress {
	items := make([]AdoptedIPAddress, 0, len(entries))
	for _, item := range entries {
		items = append(items, item.snapshot())
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].InterfaceName != items[j].InterfaceName {
			return items[i].InterfaceName < items[j].InterfaceName
		}

		left := net.ParseIP(items[i].IP).To4()
		right := net.ParseIP(items[j].IP).To4()

		return bytes.Compare(left, right) < 0
	})

	return items
}

func (s *Service) entryForIP(ip net.IP) (Identity, bool) {
	s.mu.RLock()
	item, exists := s.entries[ip.String()]
	s.mu.RUnlock()
	return item, exists
}

func (s *Service) entryAndListenerForIP(ip net.IP) (Identity, Listener, error) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	return s.entryAndListenerForIPLocked(ip)
}

func (s *Service) withEntryListenerDetails(ip net.IP, apply func(Identity, Listener) error) (AdoptedIPAddressDetails, error) {
	s.listenerMu.Lock()
	item, listener, err := s.entryAndListenerForIPLocked(ip)
	if err == nil {
		err = apply(item, listener)
	}
	s.listenerMu.Unlock()
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return detailsWithListener(item, listener), nil
}

func (s *Service) entryAndListenerForIPLocked(ip net.IP) (Identity, Listener, error) {
	item, exists := s.entryForIP(ip)
	if !exists {
		return Identity{}, nil, errAdoptedIPNotFound(ip)
	}

	listener, err := s.ensureListenerLocked(item.Interface)
	if err != nil {
		return Identity{}, nil, err
	}

	return item, listener, nil
}

func (s *Service) interfaceHasEntriesLocked(interfaceName string) bool {
	for _, item := range s.entries {
		if item.Interface.Name == interfaceName {
			return true
		}
	}

	return false
}

func (s *Service) ensureListenerLocked(iface net.Interface) (Listener, error) {
	if existing, exists := s.listeners[iface.Name]; exists {
		if err := existing.Healthy(); err == nil {
			return existing, nil
		}

		if err := existing.Close(); err != nil && !errors.Is(err, ErrListenerStopped) {
			return nil, err
		}
		delete(s.listeners, iface.Name)
	}

	listener, err := s.newListener(iface, s.resolveForwarding, s.scriptLookup)
	if err != nil {
		return nil, err
	}

	for _, identity := range s.snapshotEntriesForInterface(iface.Name) {
		if err := listener.EnsureIdentity(identity); err != nil {
			_ = listener.Close()
			return nil, err
		}
	}

	s.listeners[iface.Name] = listener
	return listener, nil
}

func (s *Service) resolveForwarding(destinationIP net.IP) (ForwardingDecision, bool) {
	destinationIP = common.NormalizeIPv4(destinationIP)
	if destinationIP == nil {
		return ForwardingDecision{}, false
	}

	s.mu.RLock()
	item, exists := s.entries[destinationIP.String()]
	s.mu.RUnlock()
	if exists {
		return s.forwardingDecisionForEntry(item, routingpkg.StoredRoute{}, false)
	}

	route, exists := s.routeMatch(destinationIP)
	if !exists {
		return ForwardingDecision{}, false
	}

	viaIP, err := common.NormalizeAdoptionIP(route.ViaAdoptedIP)
	if err != nil {
		return ForwardingDecision{}, false
	}
	s.mu.RLock()
	item, exists = s.entries[viaIP.String()]
	s.mu.RUnlock()
	if !exists {
		return ForwardingDecision{}, false
	}

	return s.forwardingDecisionForEntry(item, route, true)
}

func (s *Service) forwardingDecisionForEntry(item Identity, route routingpkg.StoredRoute, routed bool) (ForwardingDecision, bool) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	listener, err := s.ensureListenerLocked(item.Interface)
	if err != nil {
		return ForwardingDecision{}, false
	}

	return ForwardingDecision{
		Listener: listener,
		Identity: item,
		Route:    route,
		Routed:   routed,
	}, true
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

func (s *Service) Close() error {
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
