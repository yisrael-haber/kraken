package adoption

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
)

type fakeAdoptionListener struct {
	closeCalls            int
	closeErr              error
	pingCalls             int
	ensureCalls           int
	ensuredIPs            []string
	ensuredScripts        []string
	ensureErr             error
	lastSource            string
	lastGateway           string
	lastTarget            string
	lastCount             int
	lastPayload           []byte
	arpCacheEntries       []ARPCacheItem
	healthyErr            error
	recordingByIP         map[string]*PacketRecordingStatus
	startRecordErr        error
	stopRecordErr         error
	startRecordPath       string
	stopRecordIP          string
	tcpServicesByIP       map[string]map[string]*TCPServiceStatus
	startTCPServiceErr    error
	stopTCPServiceErr     error
	startTCPServiceIP     string
	startTCPServiceTLS    bool
	startTCPServiceScript string
	stopTCPServiceIP      string
	stopTCPServiceName    string
	injectedFrames        int
	routedFrames          int
	lastRouteLabel        string
	lastRouteViaIP        string
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
	if identity == nil {
		return nil
	}

	listener.ensureCalls++
	listener.ensuredIPs = append(listener.ensuredIPs, identity.IP().String())
	listener.ensuredScripts = append(listener.ensuredScripts, identity.ScriptName())
	return nil
}

func (listener *fakeAdoptionListener) InjectFrame([]byte) error {
	listener.injectedFrames++
	return nil
}

func (listener *fakeAdoptionListener) RouteFrame(via Identity, route routingpkg.StoredRoute, frame []byte) error {
	listener.routedFrames++
	listener.lastRouteLabel = route.Label
	if via != nil {
		listener.lastRouteViaIP = via.IP().String()
	}
	_ = frame
	return nil
}

func (listener *fakeAdoptionListener) Ping(source Identity, targetIP net.IP, count int, payload []byte) (PingAdoptedIPAddressResult, error) {
	listener.pingCalls++
	listener.lastSource = source.IP().String()
	listener.lastGateway = common.IPString(source.DefaultGateway())
	listener.lastTarget = targetIP.String()
	listener.lastCount = count
	listener.lastPayload = append([]byte(nil), payload...)

	return PingAdoptedIPAddressResult{
		SourceIP: source.IP().String(),
		TargetIP: targetIP.String(),
		Sent:     count,
	}, nil
}

func (listener *fakeAdoptionListener) ARPCacheSnapshot() []ARPCacheItem {
	return append([]ARPCacheItem(nil), listener.arpCacheEntries...)
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
	listener.recordingByIP[source.IP().String()] = status
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

func (listener *fakeAdoptionListener) StartTCPService(source Identity, service string, port int, rootDirectory string, useTLS bool, scriptName string) (TCPServiceStatus, error) {
	if listener.startTCPServiceErr != nil {
		return TCPServiceStatus{}, listener.startTCPServiceErr
	}
	if listener.tcpServicesByIP == nil {
		listener.tcpServicesByIP = make(map[string]map[string]*TCPServiceStatus)
	}

	listener.startTCPServiceIP = source.IP().String()
	listener.startTCPServiceTLS = useTLS
	listener.startTCPServiceScript = scriptName
	status := &TCPServiceStatus{
		Service:       service,
		Active:        true,
		Port:          port,
		RootDirectory: rootDirectory,
		UseTLS:        useTLS,
		ScriptName:    scriptName,
		StartedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	byService := listener.tcpServicesByIP[source.IP().String()]
	if byService == nil {
		byService = make(map[string]*TCPServiceStatus)
		listener.tcpServicesByIP[source.IP().String()] = byService
	}
	byService[service] = status
	return *status, nil
}

func (listener *fakeAdoptionListener) StopTCPService(ip net.IP, service string) error {
	if listener.stopTCPServiceErr != nil {
		return listener.stopTCPServiceErr
	}
	if ip == nil {
		return nil
	}

	listener.stopTCPServiceIP = ip.String()
	listener.stopTCPServiceName = service
	if listener.tcpServicesByIP != nil {
		byService := listener.tcpServicesByIP[ip.String()]
		delete(byService, service)
		if len(byService) == 0 {
			delete(listener.tcpServicesByIP, ip.String())
		}
	}
	return nil
}

func (listener *fakeAdoptionListener) TCPServiceSnapshot(ip net.IP) []TCPServiceStatus {
	if ip == nil || listener.tcpServicesByIP == nil {
		return nil
	}

	byService := listener.tcpServicesByIP[ip.String()]
	if len(byService) == 0 {
		return nil
	}

	items := make([]TCPServiceStatus, 0, len(byService))
	for _, status := range byService {
		if status != nil {
			items = append(items, *status)
		}
	}
	return items
}

func (listener *fakeAdoptionListener) ForgetIdentity(net.IP) {}

func testAdoptionManager(t *testing.T) (*Service, map[string]*fakeAdoptionListener) {
	listeners := map[string]*fakeAdoptionListener{}

	manager := &Service{
		entries:   make(map[string]entry),
		listeners: make(map[string]Listener),
		newListener: func(iface net.Interface, forward ForwardLookupFunc, resolveScript ScriptLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{
				recordingByIP:   make(map[string]*PacketRecordingStatus),
				tcpServicesByIP: make(map[string]map[string]*TCPServiceStatus),
			}
			listeners[iface.Name] = listener
			_ = forward
			_ = resolveScript
			return listener, nil
		},
	}

	t.Helper()
	return manager, listeners
}

func (s *Service) adoptInterface(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) (AdoptedIPAddress, error) {
	return s.adoptInterfaceWithGateway(label, iface, ip, mac, nil)
}

func (s *Service) updateInterface(currentIP net.IP, label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) (AdoptedIPAddress, error) {
	return s.updateInterfaceWithGateway(currentIP, label, iface, ip, mac, nil)
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

func TestAdoptionManagerListenerCreationDoesNotBlockSnapshots(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	started := make(chan struct{})
	release := make(chan struct{})
	manager.newListener = func(iface net.Interface, forward ForwardLookupFunc, resolveScript ScriptLookupFunc) (Listener, error) {
		close(started)
		<-release

		listener := &fakeAdoptionListener{}
		_ = iface
		_ = forward
		_ = resolveScript
		return listener, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = manager.adoptInterface(
			"first-adoption",
			net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
			net.ParseIP("192.168.56.10").To4(),
			net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("listener creation did not start")
	}

	snapshotDone := make(chan struct{})
	go func() {
		defer close(snapshotDone)
		_ = manager.Snapshot()
	}()

	select {
	case <-snapshotDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("snapshot was blocked by listener creation")
	}

	close(release)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("adoption did not complete after listener creation was released")
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

	target, ok := manager.lookupEntry("eth0", net.ParseIP("10.10.10.10"))
	if !ok {
		t.Fatal("expected lookup on eth0 to find adopted IP")
	}
	if target.IP().String() != first.IP {
		t.Fatalf("expected lookup IP %s, got %s", first.IP, target.IP().String())
	}

	_, ok = manager.lookupEntry("eth0", net.ParseIP("10.10.10.11"))
	if ok {
		t.Fatal("expected eth0 lookup to ignore eth1 adoption")
	}
}

func TestAdoptionManagerResolveForwardingPrefersDirectAdoption(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	target, err := manager.adoptInterface(
		"target-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("10.0.0.99").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("adopt target IP: %v", err)
	}

	manager.routeMatch = func(net.IP) (routingpkg.StoredRoute, bool) {
		return routingpkg.StoredRoute{
			Label:           "lab-segment",
			DestinationCIDR: "10.0.0.0/24",
			ViaAdoptedIP:    "192.168.56.10",
		}, true
	}

	decision, ok := manager.resolveForwarding(net.ParseIP(target.IP))
	if !ok {
		t.Fatal("expected forwarding decision for adopted destination")
	}
	if decision.Routed {
		t.Fatal("expected direct adopted delivery to win over routing rule")
	}
	if got := decision.Identity.IP().String(); got != target.IP {
		t.Fatalf("expected direct target %s, got %s", target.IP, got)
	}
}

func TestAdoptionManagerResolveForwardingMatchesRouteViaAdoptedIP(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	via, err := manager.adoptInterface(
		"via-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt via IP: %v", err)
	}

	manager.routeMatch = func(ip net.IP) (routingpkg.StoredRoute, bool) {
		if got := ip.String(); got != "10.0.0.99" {
			t.Fatalf("expected route lookup for 10.0.0.99, got %s", got)
		}
		return routingpkg.StoredRoute{
			Label:           "lab-segment",
			DestinationCIDR: "10.0.0.0/24",
			ViaAdoptedIP:    via.IP,
		}, true
	}

	decision, ok := manager.resolveForwarding(net.ParseIP("10.0.0.99"))
	if !ok {
		t.Fatal("expected routed forwarding decision")
	}
	if !decision.Routed {
		t.Fatal("expected routed forwarding decision")
	}
	if got := decision.Identity.IP().String(); got != via.IP {
		t.Fatalf("expected route via %s, got %s", via.IP, got)
	}
	if decision.Route.Label != "lab-segment" {
		t.Fatalf("expected route label lab-segment, got %q", decision.Route.Label)
	}
}

func TestAdoptionManagerResolveForwardingSkipsRouteWithoutAdoptedVia(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	manager.routeMatch = func(net.IP) (routingpkg.StoredRoute, bool) {
		return routingpkg.StoredRoute{
			Label:           "lab-segment",
			DestinationCIDR: "10.0.0.0/24",
			ViaAdoptedIP:    "192.168.56.10",
		}, true
	}

	if _, ok := manager.resolveForwarding(net.ParseIP("10.0.0.99")); ok {
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

	entry, err := manager.adoptInterfaceWithGateway(
		"source-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.40").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	)
	if err != nil {
		t.Fatalf("adopt source IP: %v", err)
	}

	result, err := manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP: entry.IP,
		TargetIP: "192.168.56.1",
	})
	if err != nil {
		t.Fatalf("ping adopted IP: %v", err)
	}

	listener := listeners["eth0"]
	if listener.pingCalls != 1 {
		t.Fatalf("expected 1 ping call, got %d", listener.pingCalls)
	}
	if listener.lastSource != entry.IP {
		t.Fatalf("expected source IP %s, got %s", entry.IP, listener.lastSource)
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

	entry, err := manager.adoptInterfaceWithGateway(
		"payload-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.41").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	)
	if err != nil {
		t.Fatalf("adopt source IP: %v", err)
	}

	_, err = manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP:   entry.IP,
		TargetIP:   "192.168.56.1",
		PayloadHex: "DE AD BE EF",
	})
	if err != nil {
		t.Fatalf("ping adopted IP with payload: %v", err)
	}

	if got := listeners["eth0"].lastPayload; len(got) != 4 || got[0] != 0xde || got[1] != 0xad || got[2] != 0xbe || got[3] != 0xef {
		t.Fatalf("expected ping payload DE AD BE EF, got %v", got)
	}
}

func TestAdoptionManagerPingRejectsInvalidPayloadHex(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	entry, err := manager.adoptInterfaceWithGateway(
		"invalid-payload-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.42").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	)
	if err != nil {
		t.Fatalf("adopt source IP: %v", err)
	}

	_, err = manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP:   entry.IP,
		TargetIP:   "192.168.56.1",
		PayloadHex: "XYZ",
	})
	if err == nil || !strings.Contains(err.Error(), "payloadHex") {
		t.Fatalf("expected payloadHex validation error, got %v", err)
	}
}

func TestAdoptionManagerUpdateChangesIdentity(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	original, err := manager.adoptInterfaceWithGateway(
		"original-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.50").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	updated, err := manager.updateInterfaceWithGateway(
		net.ParseIP(original.IP).To4(),
		"updated-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.51").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x77},
		net.ParseIP("192.168.56.254").To4(),
	)
	if err != nil {
		t.Fatalf("update adoption: %v", err)
	}

	if updated.IP != "192.168.56.51" {
		t.Fatalf("expected updated IP 192.168.56.51, got %s", updated.IP)
	}
	if updated.MAC != "02:00:00:00:00:77" {
		t.Fatalf("expected updated MAC 02:00:00:00:00:77, got %s", updated.MAC)
	}
	if updated.DefaultGateway != "192.168.56.254" {
		t.Fatalf("expected updated default gateway 192.168.56.254, got %s", updated.DefaultGateway)
	}
	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener after same-interface update, got %d", len(listeners))
	}
	if len(manager.Snapshot()) != 1 {
		t.Fatalf("expected 1 adoption entry after update, got %d", len(manager.Snapshot()))
	}
	if _, ok := manager.lookupEntry("eth0", net.ParseIP("192.168.56.50")); ok {
		t.Fatal("expected old IP lookup to be removed after update")
	}
	if _, ok := manager.lookupEntry("eth0", net.ParseIP("192.168.56.51")); !ok {
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
		net.ParseIP(original.IP).To4(),
		"moved-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP(original.IP).To4(),
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
		net.ParseIP(first.IP).To4(),
		"duplicate-target",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.61").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err == nil {
		t.Fatal("expected duplicate target IP update to fail")
	}

	if _, ok := manager.lookupEntry("eth0", net.ParseIP(first.IP)); !ok {
		t.Fatal("expected original adoption to remain after failed update")
	}
}

func TestAdoptionManagerUpdateLeavesOriginalOnListenerCreationFailure(t *testing.T) {
	manager, listeners := testAdoptionManager(t)

	original, err := manager.adoptInterface(
		"original-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.70").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	manager.newListener = func(iface net.Interface, forward ForwardLookupFunc, resolveScript ScriptLookupFunc) (Listener, error) {
		if iface.Name == "eth1" {
			return nil, net.InvalidAddrError("listener unavailable")
		}
		listener := &fakeAdoptionListener{}
		listeners[iface.Name] = listener
		_ = forward
		_ = resolveScript
		return listener, nil
	}

	_, err = manager.updateInterface(
		net.ParseIP(original.IP).To4(),
		"listener-failure",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("192.168.56.71").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err == nil {
		t.Fatal("expected listener creation failure to abort update")
	}

	if _, ok := manager.lookupEntry("eth0", net.ParseIP(original.IP)); !ok {
		t.Fatal("expected original adoption to remain after listener creation failure")
	}
	if _, ok := manager.lookupEntry("eth1", net.ParseIP("192.168.56.71")); ok {
		t.Fatal("expected target adoption to remain absent after listener creation failure")
	}
	if listeners["eth0"].closeCalls != 0 {
		t.Fatalf("expected original listener to remain open, closeCalls=%d", listeners["eth0"].closeCalls)
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

	details, err := manager.Details(adopted.IP)
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

	adopted, err := manager.adoptInterfaceWithGateway(
		"gateway-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.94").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	details, err := manager.Details(adopted.IP)
	if err != nil {
		t.Fatalf("fetch details: %v", err)
	}

	if details.DefaultGateway != "192.168.56.1" {
		t.Fatalf("expected default gateway 192.168.56.1, got %s", details.DefaultGateway)
	}
}

func TestAdoptionManagerUpdateScriptReflectsInDetails(t *testing.T) {
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

	err = manager.UpdateScript(adopted.IP, "Traffic Script")
	if err != nil {
		t.Fatalf("update script: %v", err)
	}

	details, err := manager.Details(adopted.IP)
	if err != nil {
		t.Fatalf("fetch details: %v", err)
	}

	if details.ScriptName != "Traffic Script" {
		t.Fatalf("expected script name to be preserved, got %q", details.ScriptName)
	}
}

func TestAdoptionManagerUpdateScriptRefreshesListenerIdentity(t *testing.T) {
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

	if err := manager.UpdateScript(adopted.IP, "Traffic Script"); err != nil {
		t.Fatalf("update script: %v", err)
	}

	if listener.ensureCalls != 2 {
		t.Fatalf("expected listener EnsureIdentity to be called again, got %d calls", listener.ensureCalls)
	}
	if got := listener.ensuredScripts[len(listener.ensuredScripts)-1]; got != "Traffic Script" {
		t.Fatalf("expected refreshed script name Traffic Script, got %q", got)
	}
}

func TestAdoptionManagerUpdatePreservesScriptName(t *testing.T) {
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

	err = manager.UpdateScript(adopted.IP, "Default Script")
	if err != nil {
		t.Fatalf("update script: %v", err)
	}

	updated, err := manager.updateInterface(
		net.ParseIP(adopted.IP).To4(),
		"updated-script-binding-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("192.168.56.95").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("update adoption: %v", err)
	}

	details, err := manager.Details(updated.IP)
	if err != nil {
		t.Fatalf("fetch updated details: %v", err)
	}

	if details.ScriptName != "Default Script" {
		t.Fatalf("expected script name to survive update, got %q", details.ScriptName)
	}
}

func TestNormalizeScriptNameTrimsWhitespace(t *testing.T) {
	if got := NormalizeScriptName("  traffic-script  "); got != "traffic-script" {
		t.Fatalf("expected trimmed script name, got %q", got)
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

	details, err := manager.StartRecording(adopted.IP, "/tmp/192.168.56.88.pcap")
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

	details, err = manager.StopRecording(adopted.IP)
	if err != nil {
		t.Fatalf("stop recording: %v", err)
	}
	if details.Recording != nil {
		t.Fatalf("expected recording details to be cleared after stop, got %+v", details.Recording)
	}
	if listeners["eth0"].stopRecordIP != adopted.IP {
		t.Fatalf("expected listener stop IP %q, got %q", adopted.IP, listeners["eth0"].stopRecordIP)
	}
}

func TestAdoptionManagerStartAndStopTCPServiceReflectInDetails(t *testing.T) {
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

	details, err := manager.StartTCPService(StartAdoptedIPAddressTCPServiceRequest{
		IP:      adopted.IP,
		Service: TCPServiceEcho,
		Port:    7007,
	})
	if err != nil {
		t.Fatalf("start TCP service: %v", err)
	}

	if len(details.TCPServices) != 1 {
		t.Fatalf("expected 1 TCP service, got %d", len(details.TCPServices))
	}
	if details.TCPServices[0].Service != TCPServiceEcho || !details.TCPServices[0].Active || details.TCPServices[0].Port != 7007 {
		t.Fatalf("unexpected TCP service details %+v", details.TCPServices[0])
	}
	if details.TCPServices[0].UseTLS {
		t.Fatalf("echo service should not report TLS, got %+v", details.TCPServices[0])
	}
	if listeners["eth0"].startTCPServiceIP != adopted.IP {
		t.Fatalf("expected listener start IP %q, got %q", adopted.IP, listeners["eth0"].startTCPServiceIP)
	}

	details, err = manager.StartTCPService(StartAdoptedIPAddressTCPServiceRequest{
		IP:            adopted.IP,
		Service:       TCPServiceHTTP,
		Port:          8443,
		RootDirectory: t.TempDir(),
		UseTLS:        true,
	})
	if err != nil {
		t.Fatalf("start HTTPS service: %v", err)
	}
	if len(details.TCPServices) != 2 {
		t.Fatalf("expected 2 TCP services, got %d", len(details.TCPServices))
	}
	httpService := findTCPServiceStatus(details.TCPServices, TCPServiceHTTP)
	if httpService == nil || !httpService.UseTLS || httpService.Port != 8443 {
		t.Fatalf("unexpected HTTPS service details %+v", httpService)
	}
	if !listeners["eth0"].startTCPServiceTLS {
		t.Fatal("expected listener to receive TLS flag for HTTP service")
	}

	details, err = manager.StopTCPService(StopAdoptedIPAddressTCPServiceRequest{
		IP:      adopted.IP,
		Service: TCPServiceEcho,
	})
	if err != nil {
		t.Fatalf("stop TCP service: %v", err)
	}
	if len(details.TCPServices) != 1 {
		t.Fatalf("expected HTTPS service to remain after echo stop, got %+v", details.TCPServices)
	}
	httpService = findTCPServiceStatus(details.TCPServices, TCPServiceHTTP)
	if httpService == nil || !httpService.UseTLS {
		t.Fatalf("expected HTTPS service to remain active, got %+v", details.TCPServices)
	}
	if listeners["eth0"].stopTCPServiceIP != adopted.IP || listeners["eth0"].stopTCPServiceName != TCPServiceEcho {
		t.Fatalf("unexpected stop call ip=%q service=%q", listeners["eth0"].stopTCPServiceIP, listeners["eth0"].stopTCPServiceName)
	}
}

func findTCPServiceStatus(items []TCPServiceStatus, service string) *TCPServiceStatus {
	for index := range items {
		if items[index].Service == service {
			return &items[index]
		}
	}
	return nil
}

func TestAdoptionManagerStartTCPServiceValidatesInput(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	if _, err := manager.StartTCPService(StartAdoptedIPAddressTCPServiceRequest{
		IP:      "192.168.56.10",
		Service: "smtp",
		Port:    25,
	}); err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("expected service validation error, got %v", err)
	}

	if _, err := manager.StartTCPService(StartAdoptedIPAddressTCPServiceRequest{
		IP:      "192.168.56.10",
		Service: TCPServiceEcho,
		Port:    0,
	}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected port validation error, got %v", err)
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
	if _, err := manager.StartRecording(first.IP, "/tmp/192.168.56.77.pcap"); err != nil {
		t.Fatalf("start recording: %v", err)
	}

	if err := manager.Release(first.IP); err != nil {
		t.Fatalf("release recording IP: %v", err)
	}
	if listeners["eth0"].stopRecordIP != first.IP {
		t.Fatalf("expected release to stop recording for %q, got %q", first.IP, listeners["eth0"].stopRecordIP)
	}
	if listeners["eth0"].closeCalls != 0 {
		t.Fatalf("expected listener to remain open, closeCalls=%d", listeners["eth0"].closeCalls)
	}
}

func TestAdoptionManagerPingRecreatesUnhealthyListener(t *testing.T) {
	var created []*fakeAdoptionListener

	manager := &Service{
		entries:   make(map[string]entry),
		listeners: make(map[string]Listener),
		newListener: func(iface net.Interface, forward ForwardLookupFunc, resolveScript ScriptLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{}
			created = append(created, listener)
			_ = iface
			_ = forward
			_ = resolveScript
			return listener, nil
		},
	}

	adopted, err := manager.adoptInterfaceWithGateway(
		"recovery-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.90").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("expected exactly one listener after adopt, got %d", len(created))
	}

	created[0].healthyErr = errors.New("capture loop exited")

	result, err := manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP: adopted.IP,
		TargetIP: "192.168.56.1",
	})
	if err != nil {
		t.Fatalf("ping with recreated listener: %v", err)
	}

	if len(created) != 2 {
		t.Fatalf("expected listener recreation, got %d listeners", len(created))
	}
	if created[0].closeCalls != 1 {
		t.Fatalf("expected unhealthy listener to close once, closeCalls=%d", created[0].closeCalls)
	}
	if created[1].pingCalls != 1 {
		t.Fatalf("expected replacement listener to receive the ping, pingCalls=%d", created[1].pingCalls)
	}
	if result.Sent != defaultAdoptedPingCount {
		t.Fatalf("expected replacement ping result sent=%d, got %d", defaultAdoptedPingCount, result.Sent)
	}
}

func TestAdoptionManagerDetailsRecreatesUnhealthyListener(t *testing.T) {
	var created []*fakeAdoptionListener

	manager := &Service{
		entries:   make(map[string]entry),
		listeners: make(map[string]Listener),
		newListener: func(iface net.Interface, forward ForwardLookupFunc, resolveScript ScriptLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{}
			if len(created) == 1 {
				listener.arpCacheEntries = []ARPCacheItem{
					{IP: "192.168.56.1", MAC: "02:00:00:00:00:01", UpdatedAt: "2026-04-08T10:00:00Z"},
				}
			}
			created = append(created, listener)
			_ = iface
			_ = forward
			_ = resolveScript
			return listener, nil
		},
	}

	adopted, err := manager.adoptInterface(
		"details-recovery-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.91").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("expected exactly one listener after adopt, got %d", len(created))
	}

	created[0].healthyErr = errors.New("capture loop exited")

	details, err := manager.Details(adopted.IP)
	if err != nil {
		t.Fatalf("details with recreated listener: %v", err)
	}

	if len(created) != 2 {
		t.Fatalf("expected listener recreation during details lookup, got %d listeners", len(created))
	}
	if created[0].closeCalls != 1 {
		t.Fatalf("expected unhealthy listener to close once, closeCalls=%d", created[0].closeCalls)
	}
	if len(details.ARPCacheEntries) != 1 {
		t.Fatalf("expected replacement listener ARP cache to be used, got %d entries", len(details.ARPCacheEntries))
	}
	if details.ARPCacheEntries[0].IP != "192.168.56.1" {
		t.Fatalf("expected replacement listener ARP cache IP 192.168.56.1, got %s", details.ARPCacheEntries[0].IP)
	}
}

func TestAdoptionManagerPingReturnsListenerCloseErrorDuringRecovery(t *testing.T) {
	var created []*fakeAdoptionListener
	closeErr := errors.New("close failed")

	manager := &Service{
		entries:   make(map[string]entry),
		listeners: make(map[string]Listener),
		newListener: func(iface net.Interface, forward ForwardLookupFunc, resolveScript ScriptLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{}
			created = append(created, listener)
			_ = iface
			_ = forward
			_ = resolveScript
			return listener, nil
		},
	}

	adopted, err := manager.adoptInterface(
		"close-error-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.92").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("expected exactly one listener after adopt, got %d", len(created))
	}

	created[0].healthyErr = errors.New("capture loop exited")
	created[0].closeErr = closeErr

	_, err = manager.Ping(PingAdoptedIPAddressRequest{
		SourceIP: adopted.IP,
		TargetIP: "192.168.56.1",
	})
	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error %v, got %v", closeErr, err)
	}

	if len(created) != 1 {
		t.Fatalf("expected recovery to stop before creating a replacement listener, got %d listeners", len(created))
	}
	if created[0].closeCalls != 1 {
		t.Fatalf("expected unhealthy listener close to be attempted once, closeCalls=%d", created[0].closeCalls)
	}
	if current, exists := manager.listeners["eth0"]; !exists || current != created[0] {
		t.Fatal("expected original unhealthy listener to remain registered after close failure")
	}
}
