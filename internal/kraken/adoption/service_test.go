package adoption

import (
	"errors"
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type fakeAdoptionListener struct {
	closeCalls      int
	closeErr        error
	pingCalls       int
	lastSource      string
	lastGateway     string
	lastTarget      string
	lastCount       int
	arpCacheEntries []ARPCacheItem
	healthyErr      error
}

func (listener *fakeAdoptionListener) Close() error {
	listener.closeCalls++
	return listener.closeErr
}

func (listener *fakeAdoptionListener) Healthy() error {
	return listener.healthyErr
}

func (listener *fakeAdoptionListener) Ping(source Identity, targetIP net.IP, count int) (PingAdoptedIPAddressResult, error) {
	listener.pingCalls++
	listener.lastSource = source.IP().String()
	listener.lastGateway = common.IPString(source.DefaultGateway())
	listener.lastTarget = targetIP.String()
	listener.lastCount = count

	return PingAdoptedIPAddressResult{
		SourceIP: source.IP().String(),
		TargetIP: targetIP.String(),
		Sent:     count,
	}, nil
}

func (listener *fakeAdoptionListener) ARPCacheSnapshot() []ARPCacheItem {
	return append([]ARPCacheItem(nil), listener.arpCacheEntries...)
}

func testAdoptionManager(t *testing.T) (*Service, map[string]*fakeAdoptionListener) {
	listeners := map[string]*fakeAdoptionListener{}

	manager := &Service{
		entries:   make(map[string]entry),
		listeners: make(map[string]Listener),
		newListener: func(iface net.Interface, lookup LookupFunc, resolveOverride OverrideLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{}
			listeners[iface.Name] = listener
			_ = lookup
			_ = resolveOverride
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

func newAdoptionEntryWithState(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, activity *activityLog, bindings AdoptedIPAddressOverrideBindings) entry {
	return newEntryWithGatewayAndState(label, iface, ip, mac, nil, activity, bindings)
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
	if result.Sent != defaultAdoptedPingCount {
		t.Fatalf("expected result sent=%d, got %d", defaultAdoptedPingCount, result.Sent)
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

	manager.newListener = func(iface net.Interface, lookup LookupFunc, resolveOverride OverrideLookupFunc) (Listener, error) {
		if iface.Name == "eth1" {
			return nil, net.InvalidAddrError("listener unavailable")
		}
		listener := &fakeAdoptionListener{}
		listeners[iface.Name] = listener
		_ = lookup
		_ = resolveOverride
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

func TestAdoptionActivityKeepsNewestEvents(t *testing.T) {
	entry := newAdoptionEntryWithState(
		"activity-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.80").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		newActivityLog(2),
		AdoptedIPAddressOverrideBindings{},
	)

	entry.RecordARP("inbound", "recv-request", net.ParseIP("192.168.56.1"), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "")
	entry.RecordARP("outbound", "send-reply", net.ParseIP("192.168.56.1"), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "")
	entry.RecordARP("outbound", "send-request", net.ParseIP("192.168.56.2"), nil, "")

	details := entry.detailsSnapshot()
	if len(details.ARPEvents) != 2 {
		t.Fatalf("expected 2 retained ARP events, got %d", len(details.ARPEvents))
	}
	if details.ARPEvents[0].Event != "send-request" {
		t.Fatalf("expected newest event send-request, got %s", details.ARPEvents[0].Event)
	}
	if details.ARPEvents[1].Event != "send-reply" {
		t.Fatalf("expected second newest event send-reply, got %s", details.ARPEvents[1].Event)
	}
}

func TestAdoptionManagerUpdatePreservesActivityHistory(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	original, err := manager.adoptInterface(
		"original-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.81").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	entry, ok := manager.lookupEntry("eth0", net.ParseIP(original.IP))
	if !ok {
		t.Fatal("expected original adoption lookup to succeed")
	}
	entry.RecordICMP("inbound", "recv-echo-request", net.ParseIP("192.168.56.1"), 7, 1, 0, "received", "")

	updated, err := manager.updateInterface(
		net.ParseIP(original.IP).To4(),
		"updated-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("192.168.56.82").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("update adoption: %v", err)
	}

	details, err := manager.Details(updated.IP)
	if err != nil {
		t.Fatalf("fetch updated details: %v", err)
	}
	if details.InterfaceName != "eth1" {
		t.Fatalf("expected updated details interface eth1, got %s", details.InterfaceName)
	}
	if len(details.ICMPEvents) != 1 {
		t.Fatalf("expected retained ICMP history, got %d events", len(details.ICMPEvents))
	}
	if details.ICMPEvents[0].Event != "recv-echo-request" {
		t.Fatalf("expected retained event recv-echo-request, got %s", details.ICMPEvents[0].Event)
	}

	if _, err := manager.Details(original.IP); err == nil {
		t.Fatal("expected old IP details lookup to fail after update")
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

func TestAdoptionManagerUpdateOverrideBindingsReflectInDetails(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"override-binding-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.97").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	err = manager.UpdateOverrideBindings(adopted.IP, AdoptedIPAddressOverrideBindings{
		ARPRequestOverride:      "ARP Request Override",
		ARPReplyOverride:        "ARP Reply Override",
		ICMPEchoRequestOverride: "ICMP Request Override",
		ICMPEchoReplyOverride:   "ICMP Reply Override",
	})
	if err != nil {
		t.Fatalf("update override bindings: %v", err)
	}

	details, err := manager.Details(adopted.IP)
	if err != nil {
		t.Fatalf("fetch details: %v", err)
	}

	if details.OverrideBindings.ARPRequestOverride != "ARP Request Override" {
		t.Fatalf("expected ARP request override to be preserved, got %q", details.OverrideBindings.ARPRequestOverride)
	}
	if details.OverrideBindings.ARPReplyOverride != "ARP Reply Override" {
		t.Fatalf("expected ARP reply override to be preserved, got %q", details.OverrideBindings.ARPReplyOverride)
	}
	if details.OverrideBindings.ICMPEchoRequestOverride != "ICMP Request Override" {
		t.Fatalf("expected ICMP request override to be preserved, got %q", details.OverrideBindings.ICMPEchoRequestOverride)
	}
	if details.OverrideBindings.ICMPEchoReplyOverride != "ICMP Reply Override" {
		t.Fatalf("expected ICMP reply override to be preserved, got %q", details.OverrideBindings.ICMPEchoReplyOverride)
	}
}

func TestAdoptionManagerUpdatePreservesOverrideBindings(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"override-binding-update-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.96").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	err = manager.UpdateOverrideBindings(adopted.IP, AdoptedIPAddressOverrideBindings{
		ARPRequestOverride:      "Default ARP Override",
		ICMPEchoRequestOverride: "Default ICMP Override",
	})
	if err != nil {
		t.Fatalf("update override bindings: %v", err)
	}

	updated, err := manager.updateInterface(
		net.ParseIP(adopted.IP).To4(),
		"updated-override-binding-adoption",
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

	if details.OverrideBindings.ARPRequestOverride != "Default ARP Override" {
		t.Fatalf("expected ARP request override to survive update, got %q", details.OverrideBindings.ARPRequestOverride)
	}
	if details.OverrideBindings.ICMPEchoRequestOverride != "Default ICMP Override" {
		t.Fatalf("expected ICMP request override to survive update, got %q", details.OverrideBindings.ICMPEchoRequestOverride)
	}
}

func TestAdoptionManagerClearActivityScope(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"clear-scope-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.83").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	entry, ok := manager.lookupEntry("eth0", net.ParseIP(adopted.IP))
	if !ok {
		t.Fatal("expected adopted IP lookup to succeed")
	}
	entry.RecordARP("inbound", "recv-request", net.ParseIP("192.168.56.1"), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "")
	entry.RecordICMP("outbound", "send-echo-request", net.ParseIP("192.168.56.1"), 9, 1, 0, "sent", "")

	if err := manager.ClearActivity(adopted.IP, "arp"); err != nil {
		t.Fatalf("clear ARP activity: %v", err)
	}

	details, err := manager.Details(adopted.IP)
	if err != nil {
		t.Fatalf("fetch details after ARP clear: %v", err)
	}
	if len(details.ARPEvents) != 0 {
		t.Fatalf("expected ARP events to be cleared, got %d", len(details.ARPEvents))
	}
	if len(details.ICMPEvents) != 1 {
		t.Fatalf("expected ICMP events to remain, got %d", len(details.ICMPEvents))
	}

	if err := manager.ClearActivity(adopted.IP, "icmp"); err != nil {
		t.Fatalf("clear ICMP activity: %v", err)
	}

	details, err = manager.Details(adopted.IP)
	if err != nil {
		t.Fatalf("fetch details after ICMP clear: %v", err)
	}
	if len(details.ICMPEvents) != 0 {
		t.Fatalf("expected ICMP events to be cleared, got %d", len(details.ICMPEvents))
	}
}

func TestAdoptionManagerClearActivityRejectsUnknownScope(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"unknown-scope-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.84").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	if err := manager.ClearActivity(adopted.IP, "all"); err == nil {
		t.Fatal("expected unknown activity scope to fail")
	}
}

func TestAdoptionManagerPingRecreatesUnhealthyListener(t *testing.T) {
	var created []*fakeAdoptionListener

	manager := &Service{
		entries:   make(map[string]entry),
		listeners: make(map[string]Listener),
		newListener: func(iface net.Interface, lookup LookupFunc, resolveOverride OverrideLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{}
			created = append(created, listener)
			_ = iface
			_ = lookup
			_ = resolveOverride
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
		newListener: func(iface net.Interface, lookup LookupFunc, resolveOverride OverrideLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{}
			if len(created) == 1 {
				listener.arpCacheEntries = []ARPCacheItem{
					{IP: "192.168.56.1", MAC: "02:00:00:00:00:01", UpdatedAt: "2026-04-08T10:00:00Z"},
				}
			}
			created = append(created, listener)
			_ = iface
			_ = lookup
			_ = resolveOverride
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
		newListener: func(iface net.Interface, lookup LookupFunc, resolveOverride OverrideLookupFunc) (Listener, error) {
			listener := &fakeAdoptionListener{}
			created = append(created, listener)
			_ = iface
			_ = lookup
			_ = resolveOverride
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
