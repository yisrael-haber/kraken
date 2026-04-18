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
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

const (
	defaultAdoptedPingCount = 4
	defaultIdentityMTU      = 1500

	ServiceEcho = "echo"
	ServiceHTTP = "http"
	ServiceSSH  = "ssh"

	ServiceFieldTypePort         = "port"
	ServiceFieldTypeText         = "text"
	ServiceFieldTypeSecret       = "secret"
	ServiceFieldTypeSelect       = "select"
	ServiceFieldTypeDirectory    = "directory"
	ServiceFieldTypeStoredScript = "stored_script"
)

var ErrListenerStopped = errors.New("adoption listener is not running")

type AdoptIPAddressRequest struct {
	Label          string `json:"label"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type AdoptedIPAddress struct {
	Label          string `json:"label"`
	IP             string `json:"ip"`
	InterfaceName  string `json:"interfaceName"`
	MAC            string `json:"mac"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type UpdateAdoptedIPAddressRequest struct {
	Label          string `json:"label"`
	CurrentIP      string `json:"currentIP"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type PingAdoptedIPAddressRequest struct {
	SourceIP   string `json:"sourceIP"`
	TargetIP   string `json:"targetIP"`
	Count      int    `json:"count,omitempty"`
	PayloadHex string `json:"payloadHex,omitempty"`
}

type UpdateAdoptedIPAddressScriptRequest struct {
	IP         string `json:"ip"`
	ScriptName string `json:"scriptName"`
}

type StartAdoptedIPAddressServiceRequest struct {
	IP      string            `json:"ip"`
	Service string            `json:"service"`
	Config  map[string]string `json:"config,omitempty"`
}

type StopAdoptedIPAddressServiceRequest struct {
	IP      string `json:"ip"`
	Service string `json:"service"`
}

type PingAdoptedIPAddressReply struct {
	Sequence  int     `json:"sequence"`
	Success   bool    `json:"success"`
	RTTMillis float64 `json:"rttMillis,omitempty"`
}

type PingAdoptedIPAddressResult struct {
	SourceIP string                      `json:"sourceIP"`
	TargetIP string                      `json:"targetIP"`
	Sent     int                         `json:"sent"`
	Received int                         `json:"received"`
	Replies  []PingAdoptedIPAddressReply `json:"replies"`
}

type ServiceFieldOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type ServiceFieldDefinition struct {
	Name          string               `json:"name"`
	Label         string               `json:"label"`
	Type          string               `json:"type"`
	Required      bool                 `json:"required,omitempty"`
	DefaultValue  string               `json:"defaultValue,omitempty"`
	Placeholder   string               `json:"placeholder,omitempty"`
	ScriptSurface string               `json:"scriptSurface,omitempty"`
	Options       []ServiceFieldOption `json:"options,omitempty"`
}

type ServiceDefinition struct {
	Service     string                   `json:"service"`
	Label       string                   `json:"label"`
	DefaultPort int                      `json:"defaultPort,omitempty"`
	Fields      []ServiceFieldDefinition `json:"fields,omitempty"`
}

type ServiceSummaryItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Code  bool   `json:"code,omitempty"`
}

type ServiceStatus struct {
	Service   string               `json:"service"`
	Active    bool                 `json:"active"`
	Port      int                  `json:"port"`
	Config    map[string]string    `json:"config,omitempty"`
	Summary   []ServiceSummaryItem `json:"summary,omitempty"`
	StartedAt string               `json:"startedAt,omitempty"`
	LastError string               `json:"lastError,omitempty"`
}

type ManagedServiceStatus struct {
	Label         string               `json:"label"`
	IP            string               `json:"ip"`
	InterfaceName string               `json:"interfaceName"`
	Service       string               `json:"service"`
	Active        bool                 `json:"active"`
	Port          int                  `json:"port"`
	Summary       []ServiceSummaryItem `json:"summary,omitempty"`
	StartedAt     string               `json:"startedAt,omitempty"`
	LastError     string               `json:"lastError,omitempty"`
}

type Identity interface {
	Label() string
	IP() net.IP
	Interface() net.Interface
	MAC() net.HardwareAddr
	DefaultGateway() net.IP
	MTU() uint32
	ScriptName() string
}

type RouteMatchFunc func(destinationIP net.IP) (routingpkg.StoredRoute, bool)
type ScriptLookupFunc func(ref scriptpkg.StoredScriptRef) (scriptpkg.StoredScript, error)
type ForwardLookupFunc func(destinationIP net.IP) (ForwardingDecision, bool)

type ForwardingDecision struct {
	Listener Listener
	Identity Identity
	Route    routingpkg.StoredRoute
	Routed   bool
}

type Listener interface {
	Close() error
	Healthy() error
	EnsureIdentity(identity Identity) error
	InjectFrame(frame []byte) error
	RouteFrame(via Identity, route routingpkg.StoredRoute, frame []byte) error
	Ping(source Identity, targetIP net.IP, count int, payload []byte) (PingAdoptedIPAddressResult, error)
	ARPCacheSnapshot() []ARPCacheItem
	StartRecording(source Identity, outputPath string) (PacketRecordingStatus, error)
	StopRecording(ip net.IP) error
	RecordingSnapshot(ip net.IP) *PacketRecordingStatus
	StartService(source Identity, service string, config map[string]string) (ServiceStatus, error)
	StopService(ip net.IP, service string) error
	ServiceSnapshot(ip net.IP) []ServiceStatus
	ForgetIdentity(ip net.IP)
}

type NewListenerFunc func(net.Interface, ForwardLookupFunc, ScriptLookupFunc) (Listener, error)

type entry struct {
	label          string
	ip             net.IP
	iface          net.Interface
	mac            net.HardwareAddr
	defaultGateway net.IP
	mtu            uint32
	scriptName     string
}

type Service struct {
	mu           sync.RWMutex
	listenerMu   sync.Mutex
	entries      map[string]entry
	listeners    map[string]Listener
	snapshot     []AdoptedIPAddress
	snapshotLive bool
	routeMatch   RouteMatchFunc
	scriptLookup ScriptLookupFunc
	newListener  NewListenerFunc
}

func NewService(scriptLookup ScriptLookupFunc, routeMatch RouteMatchFunc, newListener NewListenerFunc) *Service {
	if scriptLookup == nil {
		scriptLookup = func(scriptpkg.StoredScriptRef) (scriptpkg.StoredScript, error) {
			return scriptpkg.StoredScript{}, scriptpkg.ErrStoredScriptNotFound
		}
	}
	if routeMatch == nil {
		routeMatch = func(net.IP) (routingpkg.StoredRoute, bool) {
			return routingpkg.StoredRoute{}, false
		}
	}
	if newListener == nil {
		newListener = func(net.Interface, ForwardLookupFunc, ScriptLookupFunc) (Listener, error) {
			return nil, fmt.Errorf("adoption listeners are unavailable")
		}
	}

	return &Service{
		entries:      make(map[string]entry),
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

func (s *Service) ServiceInventory() []ManagedServiceStatus {
	s.listenerMu.Lock()
	s.mu.RLock()
	items := make([]entry, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, item)
	}
	listeners := make(map[string]Listener, len(s.listeners))
	for name, listener := range s.listeners {
		listeners[name] = listener
	}
	s.mu.RUnlock()
	s.listenerMu.Unlock()

	services := make([]ManagedServiceStatus, 0, len(items))
	for _, item := range items {
		listener := listeners[item.iface.Name]
		if listener == nil {
			continue
		}

		for _, status := range listener.ServiceSnapshot(item.ip) {
			services = append(services, ManagedServiceStatus{
				Label:         item.label,
				IP:            item.ip.String(),
				InterfaceName: item.iface.Name,
				Service:       status.Service,
				Active:        status.Active,
				Port:          status.Port,
				Summary:       cloneServiceSummaryItems(status.Summary),
				StartedAt:     status.StartedAt,
				LastError:     status.LastError,
			})
		}
	}

	sort.Slice(services, func(i, j int) bool {
		if services[i].Active != services[j].Active {
			return services[i].Active
		}
		if services[i].InterfaceName != services[j].InterfaceName {
			return services[i].InterfaceName < services[j].InterfaceName
		}

		leftIP := net.ParseIP(services[i].IP).To4()
		rightIP := net.ParseIP(services[j].IP).To4()
		if compare := bytes.Compare(leftIP, rightIP); compare != 0 {
			return compare < 0
		}

		return services[i].Service < services[j].Service
	})

	return services
}

func (s *Service) UpdateScript(ipText, scriptName string) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}
	scriptName = NormalizeScriptName(scriptName)

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
	updated.scriptName = scriptName
	s.entries[key] = updated
	listener := s.listeners[item.iface.Name]
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

	return s.withEntryListenerDetails(ip, func(item entry, listener Listener) error {
		_, err := listener.StartRecording(item, outputPath)
		return err
	})
}

func (s *Service) StopRecording(ipText string) (AdoptedIPAddressDetails, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return s.withEntryListenerDetails(ip, func(_ entry, listener Listener) error {
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

	return s.withEntryListenerDetails(ip, func(item entry, listener Listener) error {
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

func cloneServiceSummaryItems(items []ServiceSummaryItem) []ServiceSummaryItem {
	if len(items) == 0 {
		return nil
	}

	cloned := make([]ServiceSummaryItem, len(items))
	copy(cloned, items)
	return cloned
}

func (s *Service) StopService(request StopAdoptedIPAddressServiceRequest) (AdoptedIPAddressDetails, error) {
	ip, service, err := normalizeServiceRequest(request.IP, request.Service)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return s.withEntryListenerDetails(ip, func(_ entry, listener Listener) error {
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

	if !s.interfaceHasEntriesLocked(item.iface.Name) {
		listener = s.listeners[item.iface.Name]
		delete(s.listeners, item.iface.Name)
	} else {
		listener = s.listeners[item.iface.Name]
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

func (s *Service) adoptInterfaceWithGateway(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) (AdoptedIPAddress, error) {
	mtu, err := normalizeIdentityMTU(iface, 0)
	if err != nil {
		return AdoptedIPAddress{}, err
	}
	return s.adoptInterfaceWithGatewayAndMTU(label, iface, ip, mac, defaultGateway, mtu)
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

	item := newEntryWithGatewayAndScriptName(label, iface, ip, mac, defaultGateway, mtu, "")
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

func (s *Service) updateInterfaceWithGateway(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) (AdoptedIPAddress, error) {
	mtu, err := normalizeIdentityMTU(iface, 0)
	if err != nil {
		return AdoptedIPAddress{}, err
	}
	return s.updateInterfaceWithGatewayAndMTU(currentIP, label, iface, ip, mac, defaultGateway, mtu)
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

	updated := newEntryWithGatewayAndScriptName(label, iface, ip, mac, defaultGateway, mtu, item.scriptName)
	s.entries[newKey] = updated
	s.invalidateSnapshotLocked()
	listenerToEnsure = s.listeners[iface.Name]

	if item.iface.Name != iface.Name && !s.interfaceHasEntriesLocked(item.iface.Name) {
		listenerToClose = s.listeners[item.iface.Name]
		delete(s.listeners, item.iface.Name)
	} else if item.iface.Name != iface.Name || currentKey != newKey {
		listenerToStopRecording = s.listeners[item.iface.Name]
	}
	previousInterfaceName := item.iface.Name
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

func (s *Service) lookupEntry(interfaceName string, ip net.IP) (Identity, bool) {
	normalized := common.NormalizeIPv4(ip)
	if normalized == nil {
		return nil, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	item, exists := s.entries[normalized.String()]
	if !exists || item.iface.Name != interfaceName {
		return nil, false
	}

	return item, true
}

func (s *Service) snapshotEntriesForInterface(interfaceName string) []Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		if item.iface.Name == interfaceName {
			items = append(items, item)
		}
	}

	return items
}

func (s *Service) invalidateSnapshotLocked() {
	s.snapshot = nil
	s.snapshotLive = false
}

func snapshotAdoptedIPAddresses(entries map[string]entry) []AdoptedIPAddress {
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

func (s *Service) entryForIP(ip net.IP) (entry, bool) {
	s.mu.RLock()
	item, exists := s.entries[ip.String()]
	s.mu.RUnlock()
	return item, exists
}

func (s *Service) entryAndListenerForIP(ip net.IP) (entry, Listener, error) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	return s.entryAndListenerForIPLocked(ip)
}

func (s *Service) withEntryListenerDetails(ip net.IP, apply func(entry, Listener) error) (AdoptedIPAddressDetails, error) {
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

func (s *Service) entryAndListenerForIPLocked(ip net.IP) (entry, Listener, error) {
	item, exists := s.entryForIP(ip)
	if !exists {
		return entry{}, nil, errAdoptedIPNotFound(ip)
	}

	listener, err := s.ensureListenerLocked(item.iface)
	if err != nil {
		return entry{}, nil, err
	}

	return item, listener, nil
}

func (s *Service) interfaceHasEntriesLocked(interfaceName string) bool {
	for _, item := range s.entries {
		if item.iface.Name == interfaceName {
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

	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	if item, exists := s.entryForIP(destinationIP); exists {
		return s.forwardingDecisionForEntryLocked(item, routingpkg.StoredRoute{}, false)
	}

	route, exists := s.routeMatch(destinationIP)
	if !exists {
		return ForwardingDecision{}, false
	}

	viaIP, err := common.NormalizeAdoptionIP(route.ViaAdoptedIP)
	if err != nil {
		return ForwardingDecision{}, false
	}
	item, exists := s.entryForIP(viaIP)
	if !exists {
		return ForwardingDecision{}, false
	}

	return s.forwardingDecisionForEntryLocked(item, route, true)
}

func (s *Service) forwardingDecisionForEntryLocked(item entry, route routingpkg.StoredRoute, routed bool) (ForwardingDecision, bool) {
	listener, err := s.ensureListenerLocked(item.iface)
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

func ResolveInterface(name string) (net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return net.Interface{}, fmt.Errorf("interface %q not found: %w", name, err)
	}

	if iface.Flags&net.FlagLoopback != 0 {
		return net.Interface{}, fmt.Errorf("interface %q is loopback and cannot be used for ARP adoption", name)
	}

	return *iface, nil
}

func ResolveMAC(iface net.Interface, macText string) (net.HardwareAddr, error) {
	if strings.TrimSpace(macText) != "" {
		mac, err := net.ParseMAC(strings.TrimSpace(macText))
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address %q: %w", macText, err)
		}
		return mac, nil
	}

	if len(iface.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface %q does not expose a hardware address; MAC must be provided explicitly", iface.Name)
	}

	return iface.HardwareAddr, nil
}

func NormalizeScriptName(scriptName string) string {
	return strings.TrimSpace(scriptName)
}

func resolveIdentity(labelText, interfaceName, ipText, macText, defaultGatewayText string, mtuValue int) (string, net.Interface, net.IP, net.HardwareAddr, net.IP, uint32, error) {
	label, err := common.NormalizeAdoptionLabel(labelText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	if strings.TrimSpace(interfaceName) == "" {
		return "", net.Interface{}, nil, nil, nil, 0, fmt.Errorf("interfaceName is required")
	}

	iface, err := ResolveInterface(strings.TrimSpace(interfaceName))
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	mac, err := ResolveMAC(iface, macText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	defaultGateway, err := common.NormalizeDefaultGateway(defaultGatewayText, ip)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	mtu, err := normalizeIdentityMTU(iface, mtuValue)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	return label, iface, ip, mac, defaultGateway, mtu, nil
}

func newEntryWithGateway(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) entry {
	mtu, _ := normalizeIdentityMTU(iface, 0)
	return newEntryWithGatewayAndScriptName(label, iface, ip, mac, defaultGateway, mtu, "")
}

func newEntryWithGatewayAndScriptName(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32, scriptName string) entry {
	return entry{
		label:          label,
		ip:             common.CloneIPv4(ip),
		iface:          iface,
		mac:            common.CloneHardwareAddr(mac),
		defaultGateway: common.CloneIPv4(defaultGateway),
		mtu:            mtu,
		scriptName:     NormalizeScriptName(scriptName),
	}
}

func (item entry) IP() net.IP {
	return item.ip
}

func (item entry) Label() string {
	return item.label
}

func (item entry) Interface() net.Interface {
	return item.iface
}

func (item entry) MAC() net.HardwareAddr {
	return item.mac
}

func (item entry) DefaultGateway() net.IP {
	return item.defaultGateway
}

func (item entry) MTU() uint32 {
	return item.mtu
}

func (item entry) ScriptName() string {
	return item.scriptName
}

func (item entry) snapshot() AdoptedIPAddress {
	return AdoptedIPAddress{
		Label:          item.label,
		IP:             item.ip.String(),
		InterfaceName:  item.iface.Name,
		MAC:            item.mac.String(),
		DefaultGateway: common.IPString(item.defaultGateway),
		MTU:            int(item.mtu),
	}
}

func (item entry) detailsSnapshot() AdoptedIPAddressDetails {
	return AdoptedIPAddressDetails{
		Label:          item.label,
		IP:             item.ip.String(),
		InterfaceName:  item.iface.Name,
		MAC:            item.mac.String(),
		DefaultGateway: common.IPString(item.defaultGateway),
		MTU:            int(item.mtu),
		ScriptName:     NormalizeScriptName(item.scriptName),
	}
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

func detailsWithListener(item entry, listener Listener) AdoptedIPAddressDetails {
	details := item.detailsSnapshot()
	if listener == nil {
		return details
	}

	details.ARPCacheEntries = listener.ARPCacheSnapshot()
	details.Recording = listener.RecordingSnapshot(item.ip)
	details.Services = listener.ServiceSnapshot(item.ip)
	return details
}
