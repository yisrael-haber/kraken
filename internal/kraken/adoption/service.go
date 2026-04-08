package adoption

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

const defaultAdoptedPingCount = 4

var ErrListenerStopped = errors.New("adoption listener is not running")

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

type Identity interface {
	IP() net.IP
	Interface() net.Interface
	MAC() net.HardwareAddr
	DefaultGateway() net.IP
	OverrideBindings() AdoptedIPAddressOverrideBindings
	RecordARP(direction, event string, peerIP net.IP, peerMAC net.HardwareAddr, details string)
	RecordICMP(direction, event string, peerIP net.IP, id, sequence uint16, rtt time.Duration, status, details string)
}

type LookupFunc func(ip net.IP) (Identity, bool)
type OverrideLookupFunc func(name string) (packetpkg.StoredPacketOverride, error)

type Listener interface {
	Close() error
	Healthy() error
	Ping(source Identity, targetIP net.IP, count int) (PingAdoptedIPAddressResult, error)
	ARPCacheSnapshot() []ARPCacheItem
}

type NewListenerFunc func(net.Interface, LookupFunc, OverrideLookupFunc) (Listener, error)

type entry struct {
	label            string
	ip               net.IP
	iface            net.Interface
	mac              net.HardwareAddr
	defaultGateway   net.IP
	activity         *activityLog
	overrideBindings AdoptedIPAddressOverrideBindings
}

type Service struct {
	mu             sync.RWMutex
	entries        map[string]entry
	listeners      map[string]Listener
	overrideLookup OverrideLookupFunc
	newListener    NewListenerFunc
}

func NewService(overrideLookup OverrideLookupFunc, newListener NewListenerFunc) *Service {
	if overrideLookup == nil {
		overrideLookup = func(string) (packetpkg.StoredPacketOverride, error) {
			return packetpkg.StoredPacketOverride{}, packetpkg.ErrStoredPacketOverrideNotFound
		}
	}
	if newListener == nil {
		newListener = func(net.Interface, LookupFunc, OverrideLookupFunc) (Listener, error) {
			return nil, fmt.Errorf("adoption listeners are unavailable")
		}
	}

	return &Service{
		entries:        make(map[string]entry),
		listeners:      make(map[string]Listener),
		overrideLookup: overrideLookup,
		newListener:    newListener,
	}
}

func (s *Service) Adopt(request AdoptIPAddressRequest) (AdoptedIPAddress, error) {
	label, iface, ip, mac, defaultGateway, err := resolveIdentity(
		request.Label,
		request.InterfaceName,
		request.IP,
		request.MAC,
		request.DefaultGateway,
	)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return s.adoptInterfaceWithGateway(label, iface, ip, mac, defaultGateway)
}

func (s *Service) Update(request UpdateAdoptedIPAddressRequest) (AdoptedIPAddress, error) {
	currentIP, err := NormalizeAdoptionIP(request.CurrentIP)
	if err != nil {
		return AdoptedIPAddress{}, fmt.Errorf("currentIP: %w", err)
	}

	label, iface, ip, mac, defaultGateway, err := resolveIdentity(
		request.Label,
		request.InterfaceName,
		request.IP,
		request.MAC,
		request.DefaultGateway,
	)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return s.updateInterfaceWithGateway(currentIP, label, iface, ip, mac, defaultGateway)
}

func (s *Service) Snapshot() []AdoptedIPAddress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]AdoptedIPAddress, 0, len(s.entries))
	for _, item := range s.entries {
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

func (s *Service) Details(ipText string) (AdoptedIPAddressDetails, error) {
	ip, err := NormalizeAdoptionIP(ipText)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	s.mu.Lock()
	item, exists := s.entries[ip.String()]
	var listener Listener
	if exists {
		if err := s.ensureListenerLocked(item.iface); err != nil {
			s.mu.Unlock()
			return AdoptedIPAddressDetails{}, err
		}
		listener = s.listeners[item.iface.Name]
	}
	s.mu.Unlock()
	if !exists {
		return AdoptedIPAddressDetails{}, fmt.Errorf("IP %s is not currently adopted", ip)
	}

	details := item.detailsSnapshot()
	if listener != nil {
		details.ARPCacheEntries = listener.ARPCacheSnapshot()
	}

	return details, nil
}

func (s *Service) UpdateOverrideBindings(ipText string, bindings AdoptedIPAddressOverrideBindings) error {
	ip, err := NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.entries[ip.String()]
	if !exists {
		return fmt.Errorf("IP %s is not currently adopted", ip)
	}

	item.overrideBindings = NormalizeOverrideBindings(bindings)
	s.entries[ip.String()] = item
	return nil
}

func (s *Service) ClearActivity(ipText, scope string) error {
	ip, err := NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	s.mu.RLock()
	item, exists := s.entries[ip.String()]
	s.mu.RUnlock()
	if !exists {
		return fmt.Errorf("IP %s is not currently adopted", ip)
	}

	if item.activity == nil {
		return nil
	}

	return item.activity.clear(strings.ToLower(strings.TrimSpace(scope)))
}

func (s *Service) Release(ipText string) error {
	ip, err := NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	key := ip.String()

	var listener Listener

	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		return fmt.Errorf("IP %s is not currently adopted", ip)
	}

	delete(s.entries, key)

	if !s.interfaceHasEntriesLocked(item.iface.Name) {
		listener = s.listeners[item.iface.Name]
		delete(s.listeners, item.iface.Name)
	}
	s.mu.Unlock()

	if listener != nil {
		return listener.Close()
	}

	return nil
}

func (s *Service) Ping(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, error) {
	sourceIP, err := NormalizeAdoptionIP(request.SourceIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("sourceIP: %w", err)
	}

	targetIP, err := NormalizeAdoptionIP(request.TargetIP)
	if err != nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("targetIP: %w", err)
	}

	count := request.Count
	if count <= 0 {
		count = defaultAdoptedPingCount
	}

	s.mu.Lock()
	item, exists := s.entries[sourceIP.String()]
	if !exists {
		s.mu.Unlock()
		return PingAdoptedIPAddressResult{}, fmt.Errorf("IP %s is not currently adopted", sourceIP)
	}

	if err := s.ensureListenerLocked(item.iface); err != nil {
		s.mu.Unlock()
		return PingAdoptedIPAddressResult{}, err
	}
	listener := s.listeners[item.iface.Name]
	s.mu.Unlock()

	return listener.Ping(item, targetIP, count)
}

func (s *Service) adoptInterfaceWithGateway(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) (AdoptedIPAddress, error) {
	key := ip.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[key]; exists {
		return AdoptedIPAddress{}, fmt.Errorf("IP %s is already adopted", ip)
	}

	if err := s.ensureListenerLocked(iface); err != nil {
		return AdoptedIPAddress{}, err
	}

	item := newEntryWithGateway(label, iface, ip, mac, defaultGateway)
	s.entries[key] = item

	return item.snapshot(), nil
}

func (s *Service) updateInterfaceWithGateway(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) (AdoptedIPAddress, error) {
	currentKey := currentIP.String()
	newKey := ip.String()

	var listenerToClose Listener

	s.mu.Lock()
	item, exists := s.entries[currentKey]
	if !exists {
		s.mu.Unlock()
		return AdoptedIPAddress{}, fmt.Errorf("IP %s is not currently adopted", currentIP)
	}

	if currentKey != newKey {
		if _, exists := s.entries[newKey]; exists {
			s.mu.Unlock()
			return AdoptedIPAddress{}, fmt.Errorf("IP %s is already adopted", ip)
		}
	}

	if err := s.ensureListenerLocked(iface); err != nil {
		s.mu.Unlock()
		return AdoptedIPAddress{}, err
	}

	delete(s.entries, currentKey)

	updated := newEntryWithGatewayAndState(label, iface, ip, mac, defaultGateway, item.activity, item.overrideBindings)
	s.entries[newKey] = updated

	if item.iface.Name != iface.Name && !s.interfaceHasEntriesLocked(item.iface.Name) {
		listenerToClose = s.listeners[item.iface.Name]
		delete(s.listeners, item.iface.Name)
	}
	s.mu.Unlock()

	if listenerToClose != nil {
		if err := listenerToClose.Close(); err != nil {
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

func (s *Service) interfaceHasEntriesLocked(interfaceName string) bool {
	for _, item := range s.entries {
		if item.iface.Name == interfaceName {
			return true
		}
	}

	return false
}

func (s *Service) ensureListenerLocked(iface net.Interface) error {
	if existing, exists := s.listeners[iface.Name]; exists {
		if err := existing.Healthy(); err == nil {
			return nil
		}

		if err := existing.Close(); err != nil && !errors.Is(err, ErrListenerStopped) {
			return err
		}
		delete(s.listeners, iface.Name)
	}

	listener, err := s.newListener(iface, func(lookupIP net.IP) (Identity, bool) {
		return s.lookupEntry(iface.Name, lookupIP)
	}, s.overrideLookup)
	if err != nil {
		return err
	}

	s.listeners[iface.Name] = listener
	return nil
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

func NormalizeAdoptionLabel(value string) (string, error) {
	return common.NormalizeAdoptionLabel(value)
}

func NormalizeAdoptionIP(value string) (net.IP, error) {
	return common.NormalizeAdoptionIP(value)
}

func NormalizeDefaultGateway(value string, adoptedIP net.IP) (net.IP, error) {
	return common.NormalizeDefaultGateway(value, adoptedIP)
}

func NormalizeOverrideBindings(bindings AdoptedIPAddressOverrideBindings) AdoptedIPAddressOverrideBindings {
	return AdoptedIPAddressOverrideBindings{
		ARPRequestOverride:      strings.TrimSpace(bindings.ARPRequestOverride),
		ARPReplyOverride:        strings.TrimSpace(bindings.ARPReplyOverride),
		ICMPEchoRequestOverride: strings.TrimSpace(bindings.ICMPEchoRequestOverride),
		ICMPEchoReplyOverride:   strings.TrimSpace(bindings.ICMPEchoReplyOverride),
	}
}

func resolveIdentity(labelText, interfaceName, ipText, macText, defaultGatewayText string) (string, net.Interface, net.IP, net.HardwareAddr, net.IP, error) {
	label, err := NormalizeAdoptionLabel(labelText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	if strings.TrimSpace(interfaceName) == "" {
		return "", net.Interface{}, nil, nil, nil, fmt.Errorf("interfaceName is required")
	}

	iface, err := ResolveInterface(strings.TrimSpace(interfaceName))
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	ip, err := NormalizeAdoptionIP(ipText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	mac, err := ResolveMAC(iface, macText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	defaultGateway, err := NormalizeDefaultGateway(defaultGatewayText, ip)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	return label, iface, ip, mac, defaultGateway, nil
}

func newEntryWithGateway(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) entry {
	return newEntryWithGatewayAndState(label, iface, ip, mac, defaultGateway, nil, AdoptedIPAddressOverrideBindings{})
}

func newEntryWithGatewayAndState(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, activity *activityLog, bindings AdoptedIPAddressOverrideBindings) entry {
	if activity == nil {
		activity = newActivityLog(0)
	}

	return entry{
		label:            label,
		ip:               common.CloneIPv4(ip),
		iface:            iface,
		mac:              common.CloneHardwareAddr(mac),
		defaultGateway:   common.CloneIPv4(defaultGateway),
		activity:         activity,
		overrideBindings: NormalizeOverrideBindings(bindings),
	}
}

func (item entry) IP() net.IP {
	return item.ip
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

func (item entry) OverrideBindings() AdoptedIPAddressOverrideBindings {
	return item.overrideBindings
}

func (item entry) snapshot() AdoptedIPAddress {
	return AdoptedIPAddress{
		Label:          item.label,
		IP:             item.ip.String(),
		InterfaceName:  item.iface.Name,
		MAC:            item.mac.String(),
		DefaultGateway: common.IPString(item.defaultGateway),
	}
}

func (item entry) detailsSnapshot() AdoptedIPAddressDetails {
	if item.activity == nil {
		return AdoptedIPAddressDetails{
			Label:            item.label,
			IP:               item.ip.String(),
			InterfaceName:    item.iface.Name,
			MAC:              item.mac.String(),
			DefaultGateway:   common.IPString(item.defaultGateway),
			OverrideBindings: NormalizeOverrideBindings(item.overrideBindings),
		}
	}

	return item.activity.snapshot(item)
}
