package adoption

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
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
	SourceIP   string `json:"sourceIP"`
	TargetIP   string `json:"targetIP"`
	Count      int    `json:"count,omitempty"`
	PayloadHex string `json:"payloadHex,omitempty"`
}

type AdoptedIPAddressScriptBindings map[string]string

type UpdateAdoptedIPAddressScriptBindingsRequest struct {
	IP       string                         `json:"ip"`
	Bindings AdoptedIPAddressScriptBindings `json:"bindings"`
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
	Label() string
	IP() net.IP
	Interface() net.Interface
	MAC() net.HardwareAddr
	DefaultGateway() net.IP
	ScriptNameForSendPath(sendPath string) string
	RecordARP(direction, event string, peerIP net.IP, peerMAC net.HardwareAddr, details string)
	RecordICMP(direction, event string, peerIP net.IP, id, sequence uint16, rtt time.Duration, status, details string)
}

type LookupFunc func(ip net.IP) (Identity, bool)
type ScriptLookupFunc func(name string) (scriptpkg.StoredScript, error)

type Listener interface {
	Close() error
	Healthy() error
	Ping(source Identity, targetIP net.IP, count int, payload []byte) (PingAdoptedIPAddressResult, error)
	ARPCacheSnapshot() []ARPCacheItem
	StartRecording(source Identity, outputPath string) (PacketRecordingStatus, error)
	StopRecording(ip net.IP) error
	RecordingSnapshot(ip net.IP) *PacketRecordingStatus
}

type NewListenerFunc func(net.Interface, LookupFunc, ScriptLookupFunc) (Listener, error)

type entry struct {
	label          string
	ip             net.IP
	iface          net.Interface
	mac            net.HardwareAddr
	defaultGateway net.IP
	activity       *activityLog
	scriptBindings AdoptedIPAddressScriptBindings
}

type Service struct {
	mu           sync.RWMutex
	listenerMu   sync.Mutex
	entries      map[string]entry
	listeners    map[string]Listener
	scriptLookup ScriptLookupFunc
	newListener  NewListenerFunc
}

func NewService(scriptLookup ScriptLookupFunc, newListener NewListenerFunc) *Service {
	if scriptLookup == nil {
		scriptLookup = func(string) (scriptpkg.StoredScript, error) {
			return scriptpkg.StoredScript{}, scriptpkg.ErrStoredScriptNotFound
		}
	}
	if newListener == nil {
		newListener = func(net.Interface, LookupFunc, ScriptLookupFunc) (Listener, error) {
			return nil, fmt.Errorf("adoption listeners are unavailable")
		}
	}

	return &Service{
		entries:      make(map[string]entry),
		listeners:    make(map[string]Listener),
		scriptLookup: scriptLookup,
		newListener:  newListener,
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
	currentIP, err := common.NormalizeAdoptionIP(request.CurrentIP)
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

func (s *Service) UpdateScriptBindings(ipText string, bindings AdoptedIPAddressScriptBindings) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.entries[ip.String()]
	if !exists {
		return errAdoptedIPNotFound(ip)
	}

	item.scriptBindings = NormalizeScriptBindings(bindings)
	s.entries[ip.String()] = item
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

	s.listenerMu.Lock()
	item, listener, err := s.entryAndListenerForIPLocked(ip)
	if err == nil {
		_, err = listener.StartRecording(item, outputPath)
	}
	s.listenerMu.Unlock()
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return detailsWithListener(item, listener), nil
}

func (s *Service) StopRecording(ipText string) (AdoptedIPAddressDetails, error) {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	s.listenerMu.Lock()
	item, listener, err := s.entryAndListenerForIPLocked(ip)
	if err == nil {
		err = listener.StopRecording(ip)
	}
	s.listenerMu.Unlock()
	if err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return detailsWithListener(item, listener), nil
}

func (s *Service) ClearActivity(ipText, scope string) error {
	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return err
	}

	s.mu.RLock()
	item, exists := s.entries[ip.String()]
	s.mu.RUnlock()
	if !exists {
		return errAdoptedIPNotFound(ip)
	}

	if item.activity == nil {
		return nil
	}

	return item.activity.clear(strings.ToLower(strings.TrimSpace(scope)))
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
	defer s.mu.Unlock()

	if _, exists := s.entries[key]; exists {
		return AdoptedIPAddress{}, errAdoptedIPAlreadyExists(ip)
	}

	item := newEntryWithGateway(label, iface, ip, mac, defaultGateway)
	s.entries[key] = item

	return item.snapshot(), nil
}

func (s *Service) updateInterfaceWithGateway(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) (AdoptedIPAddress, error) {
	currentKey := currentIP.String()
	newKey := ip.String()

	var listenerToClose Listener
	var listenerToStopRecording Listener
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

	updated := newEntryWithGatewayAndState(label, iface, ip, mac, defaultGateway, item.activity, item.scriptBindings)
	s.entries[newKey] = updated

	if item.iface.Name != iface.Name && !s.interfaceHasEntriesLocked(item.iface.Name) {
		listenerToClose = s.listeners[item.iface.Name]
		delete(s.listeners, item.iface.Name)
	} else if item.iface.Name != iface.Name || currentKey != newKey {
		listenerToStopRecording = s.listeners[item.iface.Name]
	}
	s.mu.Unlock()
	s.listenerMu.Unlock()

	if listenerToClose != nil {
		if err := listenerToClose.Close(); err != nil {
			return AdoptedIPAddress{}, err
		}
	}

	if listenerToStopRecording != nil {
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

	listener, err := s.newListener(iface, func(lookupIP net.IP) (Identity, bool) {
		return s.lookupEntry(iface.Name, lookupIP)
	}, s.scriptLookup)
	if err != nil {
		return nil, err
	}

	s.listeners[iface.Name] = listener
	return listener, nil
}

func errAdoptedIPNotFound(ip net.IP) error {
	return fmt.Errorf("IP %s is not currently adopted", ip)
}

func errAdoptedIPAlreadyExists(ip net.IP) error {
	return fmt.Errorf("IP %s is already adopted", ip)
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

func NormalizeScriptBindings(bindings AdoptedIPAddressScriptBindings) AdoptedIPAddressScriptBindings {
	if len(bindings) == 0 {
		return nil
	}

	normalized := make(AdoptedIPAddressScriptBindings, len(bindings))
	for sendPath, scriptName := range bindings {
		normalizedSendPath := normalizeSendPath(sendPath)
		if !IsSupportedSendPath(normalizedSendPath) {
			continue
		}

		trimmedScript := strings.TrimSpace(scriptName)
		if trimmedScript == "" {
			continue
		}

		normalized[normalizedSendPath] = trimmedScript
	}

	if len(normalized) == 0 {
		return nil
	}

	return normalized
}

func resolveIdentity(labelText, interfaceName, ipText, macText, defaultGatewayText string) (string, net.Interface, net.IP, net.HardwareAddr, net.IP, error) {
	label, err := common.NormalizeAdoptionLabel(labelText)
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

	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	mac, err := ResolveMAC(iface, macText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	defaultGateway, err := common.NormalizeDefaultGateway(defaultGatewayText, ip)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, err
	}

	return label, iface, ip, mac, defaultGateway, nil
}

func newEntryWithGateway(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP) entry {
	return newEntryWithGatewayAndState(label, iface, ip, mac, defaultGateway, nil, nil)
}

func newEntryWithGatewayAndState(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, activity *activityLog, bindings AdoptedIPAddressScriptBindings) entry {
	if activity == nil {
		activity = newActivityLog(0)
	}

	return entry{
		label:          label,
		ip:             common.CloneIPv4(ip),
		iface:          iface,
		mac:            common.CloneHardwareAddr(mac),
		defaultGateway: common.CloneIPv4(defaultGateway),
		activity:       activity,
		scriptBindings: NormalizeScriptBindings(bindings),
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

func (item entry) ScriptNameForSendPath(sendPath string) string {
	return item.scriptBindings.ScriptForSendPath(sendPath)
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
			Label:          item.label,
			IP:             item.ip.String(),
			InterfaceName:  item.iface.Name,
			MAC:            item.mac.String(),
			DefaultGateway: common.IPString(item.defaultGateway),
			ScriptBindings: NormalizeScriptBindings(item.scriptBindings),
		}
	}

	return item.activity.snapshot(item)
}

func detailsWithListener(item entry, listener Listener) AdoptedIPAddressDetails {
	details := item.detailsSnapshot()
	if listener == nil {
		return details
	}

	details.ARPCacheEntries = listener.ARPCacheSnapshot()
	details.Recording = listener.RecordingSnapshot(item.ip)
	return details
}

const (
	SendPathARPRequest      = "arp-request"
	SendPathARPReply        = "arp-reply"
	SendPathICMPEchoRequest = "icmp-echo-request"
	SendPathICMPEchoReply   = "icmp-echo-reply"
)

var supportedSendPaths = []string{
	SendPathARPRequest,
	SendPathARPReply,
	SendPathICMPEchoRequest,
	SendPathICMPEchoReply,
}

var supportedSendPathSet = map[string]struct{}{
	SendPathARPRequest:      {},
	SendPathARPReply:        {},
	SendPathICMPEchoRequest: {},
	SendPathICMPEchoReply:   {},
}

func SupportedSendPaths() []string {
	return slices.Clone(supportedSendPaths)
}

func IsSupportedSendPath(sendPath string) bool {
	_, supported := supportedSendPathSet[normalizeSendPath(sendPath)]
	return supported
}

func ValidateScriptBindings(bindings AdoptedIPAddressScriptBindings) error {
	for sendPath := range bindings {
		normalizedSendPath := normalizeSendPath(sendPath)
		if normalizedSendPath == "" {
			return fmt.Errorf("send path is required")
		}
		if !IsSupportedSendPath(normalizedSendPath) {
			return fmt.Errorf("unsupported send path %q", sendPath)
		}
	}

	return nil
}

func (bindings AdoptedIPAddressScriptBindings) ScriptForSendPath(sendPath string) string {
	if len(bindings) == 0 {
		return ""
	}

	return strings.TrimSpace(bindings[normalizeSendPath(sendPath)])
}

func normalizeSendPath(sendPath string) string {
	return strings.TrimSpace(sendPath)
}
