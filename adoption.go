package main

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
)

const defaultAdoptedPingCount = 4

type AdoptIPAddressRequest struct {
	Label          string `json:"label"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
}

type AdoptedIPAddress struct {
	Label          string `json:"label"`
	IP             string `json:"ip"`
	InterfaceName  string `json:"interfaceName"`
	MAC            string `json:"mac"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
}

type UpdateAdoptedIPAddressRequest struct {
	Label          string `json:"label"`
	CurrentIP      string `json:"currentIP"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
}

type PingAdoptedIPAddressRequest struct {
	SourceIP string `json:"sourceIP"`
	TargetIP string `json:"targetIP"`
	Count    int    `json:"count,omitempty"`
}

type AdoptedIPAddressOverrideBindings struct {
	ARPRequestOverride      string `json:"arpRequestOverride,omitempty"`
	ARPReplyOverride        string `json:"arpReplyOverride,omitempty"`
	ICMPEchoRequestOverride string `json:"icmpEchoRequestOverride,omitempty"`
	ICMPEchoReplyOverride   string `json:"icmpEchoReplyOverride,omitempty"`
}

type UpdateAdoptedIPAddressOverrideBindingsRequest struct {
	IP       string                           `json:"ip"`
	Bindings AdoptedIPAddressOverrideBindings `json:"bindings"`
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

type adoptionLookup func(ip net.IP) (adoptionEntry, bool)
type packetOverrideLookup func(name string) (StoredPacketOverride, bool)

type adoptionListener interface {
	Close() error
	Ping(source adoptionEntry, targetIP net.IP, count int) (PingAdoptedIPAddressResult, error)
	ARPCacheSnapshot() []ARPCacheItem
}

type adoptionEntry struct {
	label            string
	ip               net.IP
	iface            net.Interface
	mac              net.HardwareAddr
	defaultGateway   net.IP
	activity         *adoptionActivityLog
	overrideBindings AdoptedIPAddressOverrideBindings
}

type adoptionManager struct {
	mu             sync.RWMutex
	entries        map[string]adoptionEntry
	listeners      map[string]adoptionListener
	overrideLookup packetOverrideLookup
	newListener    func(net.Interface, adoptionLookup, packetOverrideLookup) (adoptionListener, error)
}

func newAdoptionManager(overrideLookup packetOverrideLookup) *adoptionManager {
	if overrideLookup == nil {
		overrideLookup = func(string) (StoredPacketOverride, bool) {
			return StoredPacketOverride{}, false
		}
	}

	return &adoptionManager{
		entries:        make(map[string]adoptionEntry),
		listeners:      make(map[string]adoptionListener),
		overrideLookup: overrideLookup,
		newListener:    newAdoptionListener,
	}
}

func (m *adoptionManager) adopt(request AdoptIPAddressRequest) (AdoptedIPAddress, error) {
	label, iface, ip, mac, defaultGateway, err := resolveAdoptionIdentity(
		request.Label,
		request.InterfaceName,
		request.IP,
		request.MAC,
		request.DefaultGateway,
	)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return m.adoptInterfaceWithGateway(label, iface, ip, mac, defaultGateway)
}

func (m *adoptionManager) update(request UpdateAdoptedIPAddressRequest) (AdoptedIPAddress, error) {
	currentIP, err := normalizeAdoptionIP(request.CurrentIP)
	if err != nil {
		return AdoptedIPAddress{}, fmt.Errorf("currentIP: %w", err)
	}

	label, iface, ip, mac, defaultGateway, err := resolveAdoptionIdentity(
		request.Label,
		request.InterfaceName,
		request.IP,
		request.MAC,
		request.DefaultGateway,
	)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return m.updateInterfaceWithGateway(currentIP, label, iface, ip, mac, defaultGateway)
}

func (m *adoptionManager) adoptInterface(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) (AdoptedIPAddress, error) {
	return m.adoptInterfaceWithGateway(label, iface, ip, mac, nil)
}

func (m *adoptionManager) adoptInterfaceWithGateway(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) (AdoptedIPAddress, error) {
	key := ip.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.entries[key]; exists {
		return AdoptedIPAddress{}, fmt.Errorf("IP %s is already adopted", ip)
	}

	if err := m.ensureListenerLocked(iface); err != nil {
		return AdoptedIPAddress{}, err
	}

	entry := newAdoptionEntryWithGateway(label, iface, ip, mac, defaultGateway)
	m.entries[key] = entry

	return entry.snapshot(), nil
}

func (m *adoptionManager) updateInterface(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) (AdoptedIPAddress, error) {
	return m.updateInterfaceWithGateway(currentIP, label, iface, ip, mac, nil)
}

func (m *adoptionManager) updateInterfaceWithGateway(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) (AdoptedIPAddress, error) {
	currentKey := currentIP.String()
	newKey := ip.String()

	var listenerToClose adoptionListener

	m.mu.Lock()
	entry, exists := m.entries[currentKey]
	if !exists {
		m.mu.Unlock()
		return AdoptedIPAddress{}, fmt.Errorf("IP %s is not currently adopted", currentIP)
	}

	if currentKey != newKey {
		if _, exists := m.entries[newKey]; exists {
			m.mu.Unlock()
			return AdoptedIPAddress{}, fmt.Errorf("IP %s is already adopted", ip)
		}
	}

	if err := m.ensureListenerLocked(iface); err != nil {
		m.mu.Unlock()
		return AdoptedIPAddress{}, err
	}

	delete(m.entries, currentKey)

	updated := newAdoptionEntryWithGatewayAndState(label, iface, ip, mac, defaultGateway, entry.activity, entry.overrideBindings)
	m.entries[newKey] = updated

	if entry.iface.Name != iface.Name && !m.interfaceHasEntriesLocked(entry.iface.Name) {
		listenerToClose = m.listeners[entry.iface.Name]
		delete(m.listeners, entry.iface.Name)
	}
	m.mu.Unlock()

	if listenerToClose != nil {
		if err := listenerToClose.Close(); err != nil {
			return AdoptedIPAddress{}, err
		}
	}

	return updated.snapshot(), nil
}

func (m *adoptionManager) snapshot() []AdoptedIPAddress {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := make([]AdoptedIPAddress, 0, len(m.entries))
	for _, entry := range m.entries {
		items = append(items, entry.snapshot())
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

func (m *adoptionManager) details(ipText string) (AdoptedIPAddressDetails, error) {
	ip, err := normalizeAdoptionIP(ipText)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	m.mu.RLock()
	entry, exists := m.entries[ip.String()]
	var listener adoptionListener
	if exists {
		listener = m.listeners[entry.iface.Name]
	}
	m.mu.RUnlock()
	if !exists {
		return AdoptedIPAddressDetails{}, fmt.Errorf("IP %s is not currently adopted", ip)
	}

	details := entry.detailsSnapshot()
	if listener != nil {
		details.ARPCacheEntries = listener.ARPCacheSnapshot()
	}

	return details, nil
}

func (m *adoptionManager) updateOverrideBindings(ipText string, bindings AdoptedIPAddressOverrideBindings) error {
	ip, err := normalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[ip.String()]
	if !exists {
		return fmt.Errorf("IP %s is not currently adopted", ip)
	}

	entry.overrideBindings = normalizeAdoptedIPAddressOverrideBindings(bindings)
	m.entries[ip.String()] = entry
	return nil
}

func (m *adoptionManager) clearActivity(ipText, scope string) error {
	ip, err := normalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	m.mu.RLock()
	entry, exists := m.entries[ip.String()]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("IP %s is not currently adopted", ip)
	}

	if entry.activity == nil {
		return nil
	}

	return entry.activity.clear(strings.ToLower(strings.TrimSpace(scope)))
}

func (m *adoptionManager) release(ipText string) error {
	ip, err := normalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	key := ip.String()

	var listener adoptionListener

	m.mu.Lock()
	entry, exists := m.entries[key]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("IP %s is not currently adopted", ip)
	}

	delete(m.entries, key)

	if !m.interfaceHasEntriesLocked(entry.iface.Name) {
		listener = m.listeners[entry.iface.Name]
		delete(m.listeners, entry.iface.Name)
	}
	m.mu.Unlock()

	if listener != nil {
		return listener.Close()
	}

	return nil
}

func (m *adoptionManager) ping(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, error) {
	sourceIP, err := normalizeAdoptionIP(request.SourceIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("sourceIP: %w", err)
	}

	targetIP, err := normalizeAdoptionIP(request.TargetIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("targetIP: %w", err)
	}

	count := request.Count
	if count <= 0 {
		count = defaultAdoptedPingCount
	}

	m.mu.RLock()
	entry, exists := m.entries[sourceIP.String()]
	if !exists {
		m.mu.RUnlock()
		return PingAdoptedIPAddressResult{}, fmt.Errorf("IP %s is not currently adopted", sourceIP)
	}

	listener, exists := m.listeners[entry.iface.Name]
	m.mu.RUnlock()
	if !exists {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("interface listener for %s is not available", entry.iface.Name)
	}

	return listener.Ping(entry, targetIP, count)
}

func (m *adoptionManager) lookupEntry(interfaceName string, ip net.IP) (adoptionEntry, bool) {
	normalized := normalizeIPv4(ip)
	if normalized == nil {
		return adoptionEntry{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.entries[normalized.String()]
	if !exists || entry.iface.Name != interfaceName {
		return adoptionEntry{}, false
	}

	return entry, true
}

func (m *adoptionManager) interfaceHasEntriesLocked(interfaceName string) bool {
	for _, entry := range m.entries {
		if entry.iface.Name == interfaceName {
			return true
		}
	}

	return false
}

func (m *adoptionManager) ensureListenerLocked(iface net.Interface) error {
	if _, exists := m.listeners[iface.Name]; exists {
		return nil
	}

	listener, err := m.newListener(iface, func(lookupIP net.IP) (adoptionEntry, bool) {
		return m.lookupEntry(iface.Name, lookupIP)
	}, m.overrideLookup)
	if err != nil {
		return err
	}

	m.listeners[iface.Name] = listener
	return nil
}

func newAdoptionEntry(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) adoptionEntry {
	return newAdoptionEntryWithGateway(label, iface, ip, mac, nil)
}

func newAdoptionEntryWithGateway(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) adoptionEntry {
	return newAdoptionEntryWithGatewayAndState(label, iface, ip, mac, defaultGateway, nil, AdoptedIPAddressOverrideBindings{})
}

func newAdoptionEntryWithState(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, activity *adoptionActivityLog, bindings AdoptedIPAddressOverrideBindings) adoptionEntry {
	return newAdoptionEntryWithGatewayAndState(label, iface, ip, mac, nil, activity, bindings)
}

func newAdoptionEntryWithGatewayAndState(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, activity *adoptionActivityLog, bindings AdoptedIPAddressOverrideBindings) adoptionEntry {
	if activity == nil {
		activity = newAdoptionActivityLog(0)
	}

	return adoptionEntry{
		label:            label,
		ip:               cloneIPv4(ip),
		iface:            iface,
		mac:              cloneHardwareAddr(mac),
		defaultGateway:   cloneIPv4(defaultGateway),
		activity:         activity,
		overrideBindings: normalizeAdoptedIPAddressOverrideBindings(bindings),
	}
}

func (entry adoptionEntry) snapshot() AdoptedIPAddress {
	return AdoptedIPAddress{
		Label:          entry.label,
		IP:             entry.ip.String(),
		InterfaceName:  entry.iface.Name,
		MAC:            entry.mac.String(),
		DefaultGateway: ipString(entry.defaultGateway),
	}
}

func (entry adoptionEntry) detailsSnapshot() AdoptedIPAddressDetails {
	if entry.activity == nil {
		return AdoptedIPAddressDetails{
			Label:            entry.label,
			IP:               entry.ip.String(),
			InterfaceName:    entry.iface.Name,
			MAC:              entry.mac.String(),
			DefaultGateway:   ipString(entry.defaultGateway),
			OverrideBindings: normalizeAdoptedIPAddressOverrideBindings(entry.overrideBindings),
		}
	}

	return entry.activity.snapshot(entry)
}

func resolveAdoptionInterface(name string) (net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return net.Interface{}, fmt.Errorf("interface %q not found: %w", name, err)
	}

	if iface.Flags&net.FlagLoopback != 0 {
		return net.Interface{}, fmt.Errorf("interface %q is loopback and cannot be used for ARP adoption", name)
	}

	return *iface, nil
}

func resolveAdoptionIdentity(labelText, interfaceName, ipText, macText, defaultGatewayText string) (string, net.Interface, net.IP, net.HardwareAddr, net.IP, error) {
	label, err := normalizeAdoptionLabel(labelText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	if strings.TrimSpace(interfaceName) == "" {
		return "", net.Interface{}, nil, nil, nil, fmt.Errorf("interfaceName is required")
	}

	iface, err := resolveAdoptionInterface(strings.TrimSpace(interfaceName))
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	ip, err := normalizeAdoptionIP(ipText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	mac, err := resolveAdoptionMAC(iface, macText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	defaultGateway, err := normalizeDefaultGateway(defaultGatewayText, ip)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	return label, iface, ip, mac, defaultGateway, nil
}

func normalizeAdoptionLabel(value string) (string, error) {
	label := strings.TrimSpace(value)
	if label == "" {
		return "", fmt.Errorf("label is required")
	}

	for _, char := range label {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == ' ' || char == '-' || char == '_' || char == '.':
		default:
			return "", fmt.Errorf("label may only contain letters, numbers, spaces, dots, underscores, and hyphens")
		}
	}

	if strings.HasSuffix(label, ".") || strings.HasSuffix(label, " ") {
		return "", fmt.Errorf("label may not end with a dot or space")
	}

	return label, nil
}

func normalizeAdoptionIP(value string) (net.IP, error) {
	ip := normalizeIPv4(net.ParseIP(strings.TrimSpace(value)))
	if ip == nil {
		return nil, fmt.Errorf("a valid IPv4 address is required")
	}

	return ip, nil
}

func normalizeOptionalAdoptionIP(value string) (net.IP, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}

	return normalizeAdoptionIP(trimmed)
}

func normalizeDefaultGateway(value string, adoptedIP net.IP) (net.IP, error) {
	gateway, err := normalizeOptionalAdoptionIP(value)
	if err != nil {
		return nil, fmt.Errorf("defaultGateway: %w", err)
	}
	if gateway == nil {
		return nil, nil
	}
	if gateway.Equal(net.IPv4zero) {
		return nil, fmt.Errorf("defaultGateway must not be 0.0.0.0")
	}
	if normalizeIPv4(adoptedIP) != nil && gateway.Equal(adoptedIP) {
		return nil, fmt.Errorf("defaultGateway must differ from IP")
	}

	return gateway, nil
}

func normalizeIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	if ip = ip.To4(); ip == nil {
		return nil
	}

	return ip
}

func resolveAdoptionMAC(iface net.Interface, macText string) (net.HardwareAddr, error) {
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

func cloneIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	return slices.Clone(ip.To4())
}

func cloneHardwareAddr(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) == 0 {
		return nil
	}

	return slices.Clone(mac)
}

func normalizeAdoptedIPAddressOverrideBindings(bindings AdoptedIPAddressOverrideBindings) AdoptedIPAddressOverrideBindings {
	return AdoptedIPAddressOverrideBindings{
		ARPRequestOverride:      strings.TrimSpace(bindings.ARPRequestOverride),
		ARPReplyOverride:        strings.TrimSpace(bindings.ARPReplyOverride),
		ICMPEchoRequestOverride: strings.TrimSpace(bindings.ICMPEchoRequestOverride),
		ICMPEchoReplyOverride:   strings.TrimSpace(bindings.ICMPEchoReplyOverride),
	}
}
