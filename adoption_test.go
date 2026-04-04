package main

import (
	"net"
	"testing"
)

type fakeAdoptionListener struct {
	closeCalls int
	pingCalls  int
	lastSource string
	lastTarget string
	lastCount  int
}

func (listener *fakeAdoptionListener) Close() error {
	listener.closeCalls++
	return nil
}

func (listener *fakeAdoptionListener) Ping(source adoptionEntry, targetIP net.IP, count int) (PingAdoptedIPAddressResult, error) {
	listener.pingCalls++
	listener.lastSource = source.ip.String()
	listener.lastTarget = targetIP.String()
	listener.lastCount = count

	return PingAdoptedIPAddressResult{
		SourceIP: source.ip.String(),
		TargetIP: targetIP.String(),
		Sent:     count,
	}, nil
}

func testAdoptionManager(t *testing.T) (*adoptionManager, map[string]*fakeAdoptionListener) {
	listeners := map[string]*fakeAdoptionListener{}

	manager := &adoptionManager{
		entries:   make(map[string]adoptionEntry),
		listeners: make(map[string]adoptionListener),
		newListener: func(iface net.Interface, lookup adoptionLookup) (adoptionListener, error) {
			listener := &fakeAdoptionListener{}
			listeners[iface.Name] = listener
			_ = lookup
			return listener, nil
		},
	}

	t.Helper()
	return manager, listeners
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
	if len(manager.snapshot()) != 2 {
		t.Fatalf("expected 2 adoption entries, got %d", len(manager.snapshot()))
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

	if err := manager.release("192.168.56.20"); err != nil {
		t.Fatalf("release first IP: %v", err)
	}
	if listeners["eth0"].closeCalls != 0 {
		t.Fatalf("expected listener to remain open, closeCalls=%d", listeners["eth0"].closeCalls)
	}

	if err := manager.release("192.168.56.21"); err != nil {
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
	if target.ip.String() != first.IP {
		t.Fatalf("expected lookup IP %s, got %s", first.IP, target.ip.String())
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

	entry, err := manager.adoptInterface(
		"source-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.40").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt source IP: %v", err)
	}

	result, err := manager.ping(PingAdoptedIPAddressRequest{
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

	original, err := manager.adoptInterface(
		"original-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.50").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	updated, err := manager.updateInterface(
		net.ParseIP(original.IP).To4(),
		"updated-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.51").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x77},
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
	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener after same-interface update, got %d", len(listeners))
	}
	if len(manager.snapshot()) != 1 {
		t.Fatalf("expected 1 adoption entry after update, got %d", len(manager.snapshot()))
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

	manager.newListener = func(iface net.Interface, lookup adoptionLookup) (adoptionListener, error) {
		if iface.Name == "eth1" {
			return nil, net.InvalidAddrError("listener unavailable")
		}
		listener := &fakeAdoptionListener{}
		listeners[iface.Name] = listener
		_ = lookup
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
	entry := newAdoptionEntryWithActivity(
		"activity-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.80").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		newAdoptionActivityLog(2),
	)

	entry.recordARP("inbound", "recv-request", net.ParseIP("192.168.56.1"), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "")
	entry.recordARP("outbound", "send-reply", net.ParseIP("192.168.56.1"), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "")
	entry.recordARP("outbound", "send-request", net.ParseIP("192.168.56.2"), nil, "")

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
	entry.recordICMP("inbound", "recv-echo-request", net.ParseIP("192.168.56.1"), 7, 1, 0, "received", "")

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

	details, err := manager.details(updated.IP)
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

	if _, err := manager.details(original.IP); err == nil {
		t.Fatal("expected old IP details lookup to fail after update")
	}
}

func TestAdoptionManagerDetailsRejectMissingIP(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	if _, err := manager.details("192.168.56.99"); err == nil {
		t.Fatal("expected missing IP details lookup to fail")
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
	entry.recordARP("inbound", "recv-request", net.ParseIP("192.168.56.1"), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, "")
	entry.recordICMP("outbound", "send-echo-request", net.ParseIP("192.168.56.1"), 9, 1, 0, "sent", "")

	if err := manager.clearActivity(adopted.IP, "arp"); err != nil {
		t.Fatalf("clear ARP activity: %v", err)
	}

	details, err := manager.details(adopted.IP)
	if err != nil {
		t.Fatalf("fetch details after ARP clear: %v", err)
	}
	if len(details.ARPEvents) != 0 {
		t.Fatalf("expected ARP events to be cleared, got %d", len(details.ARPEvents))
	}
	if len(details.ICMPEvents) != 1 {
		t.Fatalf("expected ICMP events to remain, got %d", len(details.ICMPEvents))
	}

	if err := manager.clearActivity(adopted.IP, "icmp"); err != nil {
		t.Fatalf("clear ICMP activity: %v", err)
	}

	details, err = manager.details(adopted.IP)
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

	if err := manager.clearActivity(adopted.IP, "all"); err == nil {
		t.Fatal("expected unknown activity scope to fail")
	}
}
