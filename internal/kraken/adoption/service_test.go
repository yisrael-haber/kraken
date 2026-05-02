package adoption

import (
	"maps"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	storage "github.com/yisrael-haber/kraken/internal/kraken/storage"
)

type fakeAdoptionListener struct {
	closeCalls         int
	closeErr           error
	pingCalls          int
	ensureCalls        int
	ensuredIPs         []string
	ensuredScripts     []string
	ensureErr          error
	lastSource         string
	lastGateway        string
	lastTarget         string
	lastCount          int
	lastPayload        []byte
	arpCacheEntries    []ARPCacheItem
	healthyErr         error
	recordingByIP      map[string]*PacketRecordingStatus
	startRecordErr     error
	stopRecordErr      error
	startRecordPath    string
	stopRecordIP       string
	servicesByIP       map[string]map[string]*ServiceStatus
	startServiceErr    error
	stopServiceErr     error
	startServiceIP     string
	startServiceConfig map[string]string
	stopServiceIP      string
	stopServiceName    string
}

func (listener *fakeAdoptionListener) Close() error {
	listener.closeCalls++
	return listener.closeErr
}

func (listener *fakeAdoptionListener) Healthy() error {
	return listener.healthyErr
}

func (listener *fakeAdoptionListener) EnsureIdentity(identity Identity) error {
	if listener.ensureErr != nil {
		return listener.ensureErr
	}
	if identity.IP == nil {
		return nil
	}

	listener.ensureCalls++
	listener.ensuredIPs = append(listener.ensuredIPs, identity.IP.String())
	listener.ensuredScripts = append(listener.ensuredScripts, identity.TransportScriptName)
	return nil
}

func (listener *fakeAdoptionListener) InjectFrame([]byte) error {
	return nil
}

func (listener *fakeAdoptionListener) Ping(source Identity, targetIP net.IP, count int, payload []byte) (PingAdoptedIPAddressResult, error) {
	listener.pingCalls++
	listener.lastSource = source.IP.String()
	listener.lastGateway = ipString(source.DefaultGateway)
	listener.lastTarget = targetIP.String()
	listener.lastCount = count
	listener.lastPayload = append([]byte(nil), payload...)

	return PingAdoptedIPAddressResult{
		SourceIP: source.IP.String(),
		TargetIP: targetIP.String(),
		Sent:     count,
	}, nil
}

func (listener *fakeAdoptionListener) ResolveDNS(source Identity, request ResolveDNSAdoptedIPAddressRequest) (ResolveDNSAdoptedIPAddressResult, error) {
	return ResolveDNSAdoptedIPAddressResult{
		SourceIP:  source.IP.String(),
		Server:    request.Server,
		Name:      request.Name,
		Type:      request.Type,
		Transport: request.Transport,
	}, nil
}

func (listener *fakeAdoptionListener) ARPCacheSnapshot() []ARPCacheItem {
	return append([]ARPCacheItem(nil), listener.arpCacheEntries...)
}

func (listener *fakeAdoptionListener) StatusSnapshot(net.IP) ListenerStatus {
	return ListenerStatus{}
}

func (listener *fakeAdoptionListener) StartRecording(source Identity, outputPath string) (PacketRecordingStatus, error) {
	if listener.startRecordErr != nil {
		return PacketRecordingStatus{}, listener.startRecordErr
	}
	if listener.recordingByIP == nil {
		listener.recordingByIP = make(map[string]*PacketRecordingStatus)
	}

	listener.startRecordPath = outputPath
	status := &PacketRecordingStatus{
		Active:     true,
		OutputPath: outputPath,
		StartedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	listener.recordingByIP[source.IP.String()] = status
	return *status, nil
}

func (listener *fakeAdoptionListener) StopRecording(ip net.IP) error {
	if listener.stopRecordErr != nil {
		return listener.stopRecordErr
	}
	if ip == nil {
		return nil
	}

	listener.stopRecordIP = ip.String()
	if listener.recordingByIP != nil {
		delete(listener.recordingByIP, ip.String())
	}
	return nil
}

func (listener *fakeAdoptionListener) RecordingSnapshot(ip net.IP) *PacketRecordingStatus {
	if ip == nil || listener.recordingByIP == nil {
		return nil
	}

	status := listener.recordingByIP[ip.String()]
	if status == nil {
		return nil
	}

	cloned := *status
	return &cloned
}

func (listener *fakeAdoptionListener) StartService(source Identity, service string, config map[string]string) (ServiceStatus, error) {
	if listener.startServiceErr != nil {
		return ServiceStatus{}, listener.startServiceErr
	}
	if listener.servicesByIP == nil {
		listener.servicesByIP = make(map[string]map[string]*ServiceStatus)
	}

	listener.startServiceIP = source.IP.String()
	listener.startServiceConfig = cloneStringMap(config)
	port, _ := strconv.Atoi(config["port"])
	status := &ServiceStatus{
		Service:   service,
		Active:    true,
		Port:      port,
		Config:    cloneStringMap(config),
		Summary:   nil,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	byService := listener.servicesByIP[source.IP.String()]
	if byService == nil {
		byService = make(map[string]*ServiceStatus)
		listener.servicesByIP[source.IP.String()] = byService
	}
	byService[service] = status
	return *status, nil
}

func (listener *fakeAdoptionListener) StopService(ip net.IP, service string) error {
	if listener.stopServiceErr != nil {
		return listener.stopServiceErr
	}
	if ip == nil {
		return nil
	}

	listener.stopServiceIP = ip.String()
	listener.stopServiceName = service
	if listener.servicesByIP != nil {
		byService := listener.servicesByIP[ip.String()]
		delete(byService, service)
		if len(byService) == 0 {
			delete(listener.servicesByIP, ip.String())
		}
	}
	return nil
}

func (listener *fakeAdoptionListener) ServiceSnapshot(ip net.IP) []ServiceStatus {
	if ip == nil || listener.servicesByIP == nil {
		return nil
	}

	byService := listener.servicesByIP[ip.String()]
	if len(byService) == 0 {
		return nil
	}

	items := make([]ServiceStatus, 0, len(byService))
	for _, status := range byService {
		if status != nil {
			items = append(items, *status)
		}
	}
	return items
}

func (listener *fakeAdoptionListener) ForgetIdentity(net.IP) {}

func cloneStringMap(values map[string]string) map[string]string {
	return maps.Clone(values)
}

var testListeners map[string]*fakeAdoptionListener

func testAdoptionManager(t *testing.T) (*Manager, map[string]*fakeAdoptionListener) {
	listeners := map[string]*fakeAdoptionListener{}
	testListeners = listeners

	manager := &Manager{
		entries:   make(map[string]Identity),
		listeners: make(map[string]Listener),
	}

	t.Helper()
	return manager, listeners
}

func (s *Manager) setTestListener(iface net.Interface) {
	if _, exists := s.listeners[iface.Name]; exists {
		return
	}
	listener := &fakeAdoptionListener{
		recordingByIP: make(map[string]*PacketRecordingStatus),
		servicesByIP:  make(map[string]map[string]*ServiceStatus),
	}
	testListeners[iface.Name] = listener
	_ = s.SetListener(iface, listener)
}

func (s *Manager) adoptInterface(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) (Identity, error) {
	s.setTestListener(iface)
	return s.adoptInterfaceWithGatewayAndMTU(label, iface, ip, mac, nil, 0)
}

func (s *Manager) updateInterface(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) (Identity, error) {
	s.setTestListener(iface)
	return s.updateInterfaceWithGatewayAndMTU(currentIP, label, iface, ip, mac, nil, 0)
}

func TestAdoptionManagerReusesListenerPerInterface(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	_, err := manager.adoptInterface(
		"first-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt first IP: %v", err)
	}

	_, err = manager.adoptInterface(
		"second-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.11").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt second IP: %v", err)
	}

	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(listeners))
	}
	if len(manager.Snapshot()) != 2 {
		t.Fatalf("expected 2 adoption entries, got %d", len(manager.Snapshot()))
	}
}

func TestAdoptionManagerStopsListenerAfterLastAddressRelease(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	_, err := manager.adoptInterface(
		"first-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.20").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt first IP: %v", err)
	}

	_, err = manager.adoptInterface(
		"second-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.21").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt second IP: %v", err)
	}

	if err := manager.Release("192.168.56.20"); err != nil {
		t.Fatalf("release first IP: %v", err)
	}
	if listeners["eth0"].closeCalls != 0 {
		t.Fatalf("expected listener to remain open, closeCalls=%d", listeners["eth0"].closeCalls)
	}

	if err := manager.Release("192.168.56.21"); err != nil {
		t.Fatalf("release second IP: %v", err)
	}
	if listeners["eth0"].closeCalls != 1 {
		t.Fatalf("expected listener to close once, closeCalls=%d", listeners["eth0"].closeCalls)
	}
}

func TestAdoptionManagerLookupIsScopedPerInterface(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	first, err := manager.adoptInterface(
		"first-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("10.10.10.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt first interface IP: %v", err)
	}

	_, err = manager.adoptInterface(
		"second-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("10.10.10.11").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("adopt second interface IP: %v", err)
	}

	target, ok := manager.entryForIP(net.ParseIP("10.10.10.10"))
	if !ok || target.InterfaceName != "eth0" {
		t.Fatal("expected lookup on eth0 to find adopted IP")
	}
	if target.IP.String() != first.IP.String() {
		t.Fatalf("expected lookup IP %s, got %s", first.IP.String(), target.IP.String())
	}

	target, ok = manager.entryForIP(net.ParseIP("10.10.10.11"))
	if ok && target.InterfaceName == "eth0" {
		t.Fatal("expected eth0 lookup to ignore eth1 adoption")
	}
}

func TestAdoptionManagerResolveForwardingPrefersDirectAdoption(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	target, err := manager.adoptInterface(
		"target-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("10.0.0.99").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("adopt target IP: %v", err)
	}

	manager.routeMatch = func(net.IP) (storage.StoredRoute, bool) {
		return storage.StoredRoute{
			Label:           "lab-segment",
			DestinationCIDR: "10.0.0.0/24",
			ViaAdoptedIP:    "192.168.56.10",
		}, true
	}

	forwarded, ok := manager.ResolveForwarding(target.IP)
	if !ok {
		t.Fatal("expected forwarding decision for adopted destination")
	}
	if forwarded != listeners["eth1"] {
		t.Fatal("expected direct target listener")
	}
}

func TestAdoptionManagerResolveForwardingMatchesRouteViaAdoptedIP(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	via, err := manager.adoptInterface(
		"via-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt via IP: %v", err)
	}

	manager.routeMatch = func(ip net.IP) (storage.StoredRoute, bool) {
		if got := ip.String(); got != "10.0.0.99" {
			t.Fatalf("expected route lookup for 10.0.0.99, got %s", got)
		}
		return storage.StoredRoute{
			Label:           "lab-segment",
			DestinationCIDR: "10.0.0.0/24",
			ViaAdoptedIP:    via.IP.String(),
		}, true
	}

	forwarded, ok := manager.ResolveForwarding(net.ParseIP("10.0.0.99"))
	if !ok {
		t.Fatal("expected routed forwarding decision")
	}
	if forwarded != listeners["eth0"] {
		t.Fatal("expected route via listener")
	}
}

func TestAdoptionManagerResolveForwardingSkipsRouteWithoutAdoptedVia(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	manager.routeMatch = func(net.IP) (storage.StoredRoute, bool) {
		return storage.StoredRoute{
			Label:           "lab-segment",
			DestinationCIDR: "10.0.0.0/24",
			ViaAdoptedIP:    "192.168.56.10",
		}, true
	}

	if _, ok := manager.ResolveForwarding(net.ParseIP("10.0.0.99")); ok {
		t.Fatal("expected route without adopted via IP to be ignored")
	}
}

func TestAdoptionManagerRejectsDuplicateIP(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	_, err := manager.adoptInterface(
		"first-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.30").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	_, err = manager.adoptInterface(
		"second-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("192.168.56.30").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err == nil {
		t.Fatal("expected duplicate IP adoption to fail")
	}
}

func TestAdoptionManagerPingUsesInterfaceListener(t *testing.T) {
	manager, listeners := testAdoptionManager(t)
	iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}
	manager.setTestListener(iface)

	Identity, err := manager.adoptInterfaceWithGatewayAndMTU(
		"source-adoption",
		iface,
		net.ParseIP("192.168.56.40").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		0,
	)
	if err != nil {
		t.Fatalf("adopt source IP: %v", err)
	}

	result, err := manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP: Identity.IP.String(),
		TargetIP: "192.168.56.1",
	})
	if err != nil {
		t.Fatalf("ping adopted IP: %v", err)
	}

	listener := listeners["eth0"]
	if listener.pingCalls != 1 {
		t.Fatalf("expected 1 ping call, got %d", listener.pingCalls)
	}
	if listener.lastSource != Identity.IP.String() {
		t.Fatalf("expected source IP %s, got %s", Identity.IP, listener.lastSource)
	}
	if listener.lastGateway != "192.168.56.1" {
		t.Fatalf("expected source gateway 192.168.56.1, got %s", listener.lastGateway)
	}
	if listener.lastTarget != "192.168.56.1" {
		t.Fatalf("expected target IP 192.168.56.1, got %s", listener.lastTarget)
	}
	if listener.lastCount != defaultAdoptedPingCount {
		t.Fatalf("expected default ping count %d, got %d", defaultAdoptedPingCount, listener.lastCount)
	}
	if len(listener.lastPayload) != 0 {
		t.Fatalf("expected default ping payload to be empty, got %v", listener.lastPayload)
	}
	if result.Sent != defaultAdoptedPingCount {
		t.Fatalf("expected result sent=%d, got %d", defaultAdoptedPingCount, result.Sent)
	}
}

func TestAdoptionManagerPingPassesPayloadToListener(t *testing.T) {
	manager, listeners := testAdoptionManager(t)
	iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}
	manager.setTestListener(iface)

	Identity, err := manager.adoptInterfaceWithGatewayAndMTU(
		"payload-adoption",
		iface,
		net.ParseIP("192.168.56.41").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		0,
	)
	if err != nil {
		t.Fatalf("adopt source IP: %v", err)
	}

	_, err = manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP:   Identity.IP.String(),
		TargetIP:   "192.168.56.1",
		PayloadHex: "deadbeef",
	})
	if err != nil {
		t.Fatalf("ping adopted IP with payload: %v", err)
	}

	if got := listeners["eth0"].lastPayload; len(got) != 4 || got[0] != 0xde || got[1] != 0xad || got[2] != 0xbe || got[3] != 0xef {
		t.Fatalf("expected ping payload deadbeef, got %v", got)
	}
}

func TestAdoptionManagerPingRejectsInvalidPayloadHex(t *testing.T) {
	manager, _ := testAdoptionManager(t)
	iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}
	manager.setTestListener(iface)

	Identity, err := manager.adoptInterfaceWithGatewayAndMTU(
		"invalid-payload-adoption",
		iface,
		net.ParseIP("192.168.56.42").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		0,
	)
	if err != nil {
		t.Fatalf("adopt source IP: %v", err)
	}

	_, err = manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP:   Identity.IP.String(),
		TargetIP:   "192.168.56.1",
		PayloadHex: "XYZ",
	})
	if err == nil || !strings.Contains(err.Error(), "payloadHex") {
		t.Fatalf("expected payloadHex validation error, got %v", err)
	}
}

func TestAdoptionManagerUpdateChangesIdentity(t *testing.T) {
	manager, listeners := testAdoptionManager(t)
	iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}
	manager.setTestListener(iface)

	original, err := manager.adoptInterfaceWithGatewayAndMTU(
		"original-adoption",
		iface,
		net.ParseIP("192.168.56.50").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		0,
	)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	updated, err := manager.updateInterfaceWithGatewayAndMTU(
		original.IP.To4(),
		"updated-adoption",
		iface,
		net.ParseIP("192.168.56.51").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x77},
		net.ParseIP("192.168.56.254").To4(),
		0,
	)
	if err != nil {
		t.Fatalf("update adoption: %v", err)
	}

	if updated.IP.String() != "192.168.56.51" {
		t.Fatalf("expected updated IP 192.168.56.51, got %s", updated.IP)
	}
	if updated.MAC.String() != "02:00:00:00:00:77" {
		t.Fatalf("expected updated MAC 02:00:00:00:00:77, got %s", updated.MAC)
	}
	if updated.DefaultGateway.String() != "192.168.56.254" {
		t.Fatalf("expected updated default gateway 192.168.56.254, got %s", updated.DefaultGateway)
	}
	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener after same-interface update, got %d", len(listeners))
	}
	if len(manager.Snapshot()) != 1 {
		t.Fatalf("expected 1 adoption Identity after update, got %d", len(manager.Snapshot()))
	}
	if target, ok := manager.entryForIP(net.ParseIP("192.168.56.50")); ok && target.InterfaceName == "eth0" {
		t.Fatal("expected old IP lookup to be removed after update")
	}
	if target, ok := manager.entryForIP(net.ParseIP("192.168.56.51")); !ok || target.InterfaceName != "eth0" {
		t.Fatal("expected new IP lookup to succeed after update")
	}
}

func TestAdoptionManagerUpdateMovesInterfaceAndClosesOldListener(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	original, err := manager.adoptInterface(
		"original-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("10.0.0.50").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	updated, err := manager.updateInterface(
		original.IP.To4(),
		"moved-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		original.IP.To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("move adoption: %v", err)
	}

	if updated.InterfaceName != "eth1" {
		t.Fatalf("expected updated interface eth1, got %s", updated.InterfaceName)
	}
	if listeners["eth0"].closeCalls != 1 {
		t.Fatalf("expected old listener to close once, closeCalls=%d", listeners["eth0"].closeCalls)
	}
	if _, ok := manager.listeners["eth1"]; !ok {
		t.Fatal("expected new interface listener to exist")
	}
	if _, ok := manager.listeners["eth0"]; ok {
		t.Fatal("expected old interface listener to be removed")
	}
}

func TestAdoptionManagerUpdateRejectsDuplicateTargetIP(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	first, err := manager.adoptInterface(
		"first-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.60").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt first IP: %v", err)
	}

	_, err = manager.adoptInterface(
		"second-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("192.168.56.61").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("adopt second IP: %v", err)
	}

	_, err = manager.updateInterface(
		first.IP.To4(),
		"duplicate-target",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.61").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err == nil {
		t.Fatal("expected duplicate target IP update to fail")
	}

	if target, ok := manager.entryForIP(first.IP); !ok || target.InterfaceName != "eth0" {
		t.Fatal("expected original adoption to remain after failed update")
	}
}

func TestAdoptionManagerDetailsRejectMissingIP(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	if _, err := manager.Details("192.168.56.99"); err == nil {
		t.Fatal("expected missing IP details lookup to fail")
	}
}

func TestAdoptionManagerDetailsIncludeListenerARPCache(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"arp-cache-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.98").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	listeners["eth0"].arpCacheEntries = []ARPCacheItem{
		{IP: "192.168.56.1", MAC: "02:00:00:00:00:01", UpdatedAt: "2026-04-05T10:00:00Z"},
		{IP: "192.168.56.2", MAC: "02:00:00:00:00:02", UpdatedAt: "2026-04-05T10:01:00Z"},
	}

	details, err := manager.Details(adopted.IP.String())
	if err != nil {
		t.Fatalf("fetch details: %v", err)
	}

	if len(details.ARPCacheEntries) != 2 {
		t.Fatalf("expected 2 ARP cache entries, got %d", len(details.ARPCacheEntries))
	}
	if details.ARPCacheEntries[0].IP != "192.168.56.1" {
		t.Fatalf("expected first ARP cache IP 192.168.56.1, got %s", details.ARPCacheEntries[0].IP)
	}
	if details.ARPCacheEntries[1].MAC != "02:00:00:00:00:02" {
		t.Fatalf("expected second ARP cache MAC 02:00:00:00:00:02, got %s", details.ARPCacheEntries[1].MAC)
	}
}

func TestAdoptionManagerDetailsIncludeDefaultGateway(t *testing.T) {
	manager, _ := testAdoptionManager(t)
	iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}
	manager.setTestListener(iface)

	adopted, err := manager.adoptInterfaceWithGatewayAndMTU(
		"gateway-adoption",
		iface,
		net.ParseIP("192.168.56.94").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		0,
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	details, err := manager.Details(adopted.IP.String())
	if err != nil {
		t.Fatalf("fetch details: %v", err)
	}

	if details.DefaultGateway.String() != "192.168.56.1" {
		t.Fatalf("expected default gateway 192.168.56.1, got %s", details.DefaultGateway)
	}
}

func TestAdoptionManagerUpdateScriptsReflectsInDetails(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"script-binding-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.97").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	err = manager.UpdateScripts(adopted.IP.String(), "Traffic Script", "DNS Script")
	if err != nil {
		t.Fatalf("update script: %v", err)
	}

	details, err := manager.Details(adopted.IP.String())
	if err != nil {
		t.Fatalf("fetch details: %v", err)
	}

	if details.TransportScriptName != "Traffic Script" {
		t.Fatalf("expected transport script name to be preserved, got %q", details.TransportScriptName)
	}
	if details.ApplicationScriptName != "DNS Script" {
		t.Fatalf("expected application script name to be preserved, got %q", details.ApplicationScriptName)
	}
}

func TestAdoptionManagerUpdateScriptsRefreshesListenerIdentity(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"script-refresh-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.94").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	listener := listeners["eth0"]
	if listener == nil {
		t.Fatal("expected listener for eth0")
	}
	if listener.ensureCalls != 1 {
		t.Fatalf("expected 1 ensure call after adoption, got %d", listener.ensureCalls)
	}

	if err := manager.UpdateScripts(adopted.IP.String(), "Traffic Script", "DNS Script"); err != nil {
		t.Fatalf("update script: %v", err)
	}

	if listener.ensureCalls != 2 {
		t.Fatalf("expected listener EnsureIdentity to be called again, got %d calls", listener.ensureCalls)
	}
	if got := listener.ensuredScripts[len(listener.ensuredScripts)-1]; got != "Traffic Script" {
		t.Fatalf("expected refreshed script name Traffic Script, got %q", got)
	}
}

func TestAdoptionManagerUpdatePreservesScriptNames(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"script-binding-update-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.96").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	err = manager.UpdateScripts(adopted.IP.String(), "Default Script", "Application Script")
	if err != nil {
		t.Fatalf("update script: %v", err)
	}

	updated, err := manager.updateInterface(
		adopted.IP.To4(),
		"updated-script-binding-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("192.168.56.95").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("update adoption: %v", err)
	}

	details, err := manager.Details(updated.IP.String())
	if err != nil {
		t.Fatalf("fetch updated details: %v", err)
	}

	if details.TransportScriptName != "Default Script" {
		t.Fatalf("expected transport script name to survive update, got %q", details.TransportScriptName)
	}
	if details.ApplicationScriptName != "Application Script" {
		t.Fatalf("expected application script name to survive update, got %q", details.ApplicationScriptName)
	}
}

func TestAdoptionManagerStartAndStopRecordingReflectInDetails(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"recording-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.88").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	details, err := manager.StartRecording(adopted.IP.String(), "/tmp/192.168.56.88.pcap")
	if err != nil {
		t.Fatalf("start recording: %v", err)
	}

	if details.Recording == nil || !details.Recording.Active {
		t.Fatalf("expected active recording details, got %+v", details.Recording)
	}
	if details.Recording.OutputPath != "/tmp/192.168.56.88.pcap" {
		t.Fatalf("expected output path to be preserved, got %q", details.Recording.OutputPath)
	}
	if listeners["eth0"].startRecordPath != "/tmp/192.168.56.88.pcap" {
		t.Fatalf("expected listener to receive output path, got %q", listeners["eth0"].startRecordPath)
	}

	details, err = manager.StopRecording(adopted.IP.String())
	if err != nil {
		t.Fatalf("stop recording: %v", err)
	}
	if details.Recording != nil {
		t.Fatalf("expected recording details to be cleared after stop, got %+v", details.Recording)
	}
	if listeners["eth0"].stopRecordIP != adopted.IP.String() {
		t.Fatalf("expected listener stop IP %q, got %q", adopted.IP.String(), listeners["eth0"].stopRecordIP)
	}
}

func TestAdoptionManagerStartAndStopServiceReflectInDetails(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"tcp-service-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.118").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	details, err := manager.StartService(StartAdoptedIPAddressServiceRequest{
		IP:      adopted.IP.String(),
		Service: "echo",
		Config: map[string]string{
			"port": "7007",
		},
	})
	if err != nil {
		t.Fatalf("start service: %v", err)
	}

	if len(details.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(details.Services))
	}
	if details.Services[0].Service != "echo" || !details.Services[0].Active || details.Services[0].Port != 7007 {
		t.Fatalf("unexpected service details %+v", details.Services[0])
	}
	if listeners["eth0"].startServiceIP != adopted.IP.String() {
		t.Fatalf("expected listener start IP %q, got %q", adopted.IP.String(), listeners["eth0"].startServiceIP)
	}

	details, err = manager.StartService(StartAdoptedIPAddressServiceRequest{
		IP:      adopted.IP.String(),
		Service: "http",
		Config: map[string]string{
			"port":          "8443",
			"rootDirectory": t.TempDir(),
			"protocol":      "https",
		},
	})
	if err != nil {
		t.Fatalf("start HTTPS service: %v", err)
	}
	if len(details.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(details.Services))
	}
	httpService := findServiceStatus(details.Services, "http")
	if httpService == nil || httpService.Config["protocol"] != "https" || httpService.Port != 8443 {
		t.Fatalf("unexpected HTTPS service details %+v", httpService)
	}
	if listeners["eth0"].startServiceConfig["protocol"] != "https" {
		t.Fatal("expected listener to receive protocol for HTTP service")
	}

	details, err = manager.StopService(StopAdoptedIPAddressServiceRequest{
		IP:      adopted.IP.String(),
		Service: "echo",
	})
	if err != nil {
		t.Fatalf("stop service: %v", err)
	}
	if len(details.Services) != 1 {
		t.Fatalf("expected HTTPS service to remain after echo stop, got %+v", details.Services)
	}
	httpService = findServiceStatus(details.Services, "http")
	if httpService == nil || httpService.Config["protocol"] != "https" {
		t.Fatalf("expected HTTPS service to remain active, got %+v", details.Services)
	}
	if listeners["eth0"].stopServiceIP != adopted.IP.String() || listeners["eth0"].stopServiceName != "echo" {
		t.Fatalf("unexpected stop call ip=%q service=%q", listeners["eth0"].stopServiceIP, listeners["eth0"].stopServiceName)
	}
}

func findServiceStatus(items []ServiceStatus, service string) *ServiceStatus {
	for index := range items {
		if items[index].Service == service {
			return &items[index]
		}
	}
	return nil
}

func TestAdoptionManagerStartServiceValidatesInput(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	if _, err := manager.StartService(StartAdoptedIPAddressServiceRequest{
		IP:      "192.168.56.10",
		Service: "smtp",
		Config: map[string]string{
			"port": "25",
		},
	}); err == nil || !strings.Contains(err.Error(), "not currently adopted") {
		t.Fatalf("expected service validation error, got %v", err)
	}
}

func TestAdoptionManagerReleaseStopsRecordingWhenListenerStaysOpen(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	first, err := manager.adoptInterface(
		"recording-release-a",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.77").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt first IP: %v", err)
	}
	_, err = manager.adoptInterface(
		"recording-release-b",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.78").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt second IP: %v", err)
	}
	if _, err := manager.StartRecording(first.IP.String(), "/tmp/192.168.56.77.pcap"); err != nil {
		t.Fatalf("start recording: %v", err)
	}

	if err := manager.Release(first.IP.String()); err != nil {
		t.Fatalf("release recording IP: %v", err)
	}
	if listeners["eth0"].stopRecordIP != first.IP.String() {
		t.Fatalf("expected release to stop recording for %q, got %q", first.IP.String(), listeners["eth0"].stopRecordIP)
	}
	if listeners["eth0"].closeCalls != 0 {
		t.Fatalf("expected listener to remain open, closeCalls=%d", listeners["eth0"].closeCalls)
	}
}
