package adoption

import (
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"gvisor.dev/gvisor/pkg/buffer"
)

type fakeAdoptionListener struct {
	closeCalls int
}

func (listener *fakeAdoptionListener) Close() error {
	listener.closeCalls++
	return nil
}

func (listener *fakeAdoptionListener) PacketIO() *netruntime.InterfacePacketIO {
	return &netruntime.InterfacePacketIO{}
}

func (listener *fakeAdoptionListener) CaptureIPv4Target(ip net.IP) error {
	return nil
}

var testListeners map[string]*fakeAdoptionListener

func testAdoptionManager(t *testing.T) (*Manager, map[string]*fakeAdoptionListener) {
	listeners := map[string]*fakeAdoptionListener{}
	testListeners = listeners

	scripts := storage.NewScriptStoreAtDir(t.TempDir())
	for _, name := range []string{"Traffic Script", "Default Script"} {
		if _, err := scripts.Save(storage.SaveStoredScriptRequest{
			Name:    name,
			Surface: storage.SurfaceTransport,
			Source:  "def main(packet, ctx):\n    pass\n",
		}); err != nil {
			t.Fatalf("save test script: %v", err)
		}
	}
	for _, name := range []string{"DNS Script", "Application Script"} {
		if _, err := scripts.Save(storage.SaveStoredScriptRequest{
			Name:    name,
			Surface: storage.SurfaceApplication,
			Source:  "def main(buffer, ctx):\n    pass\n",
		}); err != nil {
			t.Fatalf("save test script: %v", err)
		}
	}

	manager := &Manager{
		entries: make(map[[4]byte]*Identity),
		scripts: scripts,
	}

	t.Helper()
	return manager, listeners
}

func setTestListener(iface net.Interface) {
	if _, exists := testListeners[iface.Name]; exists {
		return
	}
	testListeners[iface.Name] = &fakeAdoptionListener{}
}

func (s *Manager) adoptInterface(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr) (Identity, error) {
	setTestListener(iface)
	return s.adoptTestIdentity(label, iface, ip, mac, nil, 0)
}

func (s *Manager) adoptTestIdentity(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32) (Identity, error) {
	setTestListener(iface)
	return s.adoptIdentity(testIdentity(label, iface, ip, mac, defaultGateway, mtu), testListeners[iface.Name])
}

func testIdentity(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32) Identity {
	return Identity{
		Label:          label,
		Interface:      iface,
		InterfaceName:  iface.Name,
		IP:             ip,
		MAC:            HardwareAddr(mac),
		SubnetMask:     IPv4Mask(net.CIDRMask(24, 32)),
		DefaultGateway: defaultGateway,
		MTU:            mtu,
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

	target, err := manager.lookup(net.ParseIP("10.10.10.10").To4())
	if err != nil || target.InterfaceName != "eth0" {
		t.Fatal("expected lookup on eth0 to find adopted IP")
	}
	if target.IP.String() != first.IP.String() {
		t.Fatalf("expected lookup IP %s, got %s", first.IP.String(), target.IP.String())
	}

	target, err = manager.lookup(net.ParseIP("10.10.10.11").To4())
	if err == nil && target.InterfaceName == "eth0" {
		t.Fatal("expected eth0 lookup to ignore eth1 adoption")
	}
}

func TestAdoptionManagerForwardFramePrefersDirectAdoption(t *testing.T) {
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

	if !manager.ForwardFrame(target.IP, buffer.MakeWithData(nil)) {
		t.Fatal("expected frame to forward to adopted destination")
	}
}

func TestAdoptionManagerForwardFrameMatchesAdoptedSubnet(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	_, err := manager.adoptInterface(
		"segment-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt via IP: %v", err)
	}

	if !manager.ForwardFrame(net.ParseIP("192.168.56.99"), buffer.MakeWithData(nil)) {
		t.Fatal("expected same-subnet frame forwarding")
	}
}

func TestAdoptionManagerForwardFrameSkipsDestinationOutsideAdoptedSubnets(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	_, err := manager.adoptInterface(
		"segment-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt via IP: %v", err)
	}

	frame := buffer.MakeWithData(nil)
	if manager.ForwardFrame(net.ParseIP("10.0.0.99"), frame) {
		t.Fatal("expected destination outside adopted subnets to be ignored")
	}
	frame.Release()
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

func TestAdoptionManagerReplaceChangesIdentity(t *testing.T) {
	manager, listeners := testAdoptionManager(t)
	iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}
	setTestListener(iface)

	original, err := manager.adoptTestIdentity("original-adoption", iface, net.ParseIP("192.168.56.50").To4(), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}, net.ParseIP("192.168.56.1").To4(), 0)
	if err != nil {
		t.Fatalf("adopt original IP: %v", err)
	}

	if err := manager.release(original.IP); err != nil {
		t.Fatalf("release original IP: %v", err)
	}
	updated, err := manager.adoptTestIdentity("updated-adoption", iface, net.ParseIP("192.168.56.51").To4(), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x77}, net.ParseIP("192.168.56.254").To4(), 0)
	if err != nil {
		t.Fatalf("adopt replacement: %v", err)
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
		t.Fatalf("expected 1 listener after same-interface replacement, got %d", len(listeners))
	}
	if len(manager.snapshot()) != 1 {
		t.Fatalf("expected 1 adoption Identity after replacement, got %d", len(manager.snapshot()))
	}
	if target, err := manager.lookup(net.ParseIP("192.168.56.50").To4()); err == nil && target.InterfaceName == "eth0" {
		t.Fatal("expected old IP lookup to be removed after replacement")
	}
	if target, err := manager.lookup(net.ParseIP("192.168.56.51").To4()); err != nil || target.InterfaceName != "eth0" {
		t.Fatal("expected new IP lookup to succeed after replacement")
	}
}

func TestAdoptionManagerReplaceMovesInterfaceAndClosesOldListener(t *testing.T) {
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

	if err := manager.release(original.IP); err != nil {
		t.Fatalf("release original IP: %v", err)
	}
	updated, err := manager.adoptInterface(
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
	if _, ok := listeners["eth1"]; !ok {
		t.Fatal("expected new interface listener to exist")
	}
	if listeners["eth1"].closeCalls != 0 {
		t.Fatalf("expected new listener to remain open, closeCalls=%d", listeners["eth1"].closeCalls)
	}
}

func TestAdoptionManagerDetailsRejectMissingIP(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	if _, err := manager.lookup(net.ParseIP("192.168.56.99").To4()); err == nil {
		t.Fatal("expected missing IP details lookup to fail")
	}
}

func TestAdoptionManagerDetailsIncludeDefaultGateway(t *testing.T) {
	manager, _ := testAdoptionManager(t)
	iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}
	setTestListener(iface)

	adopted, err := manager.adoptTestIdentity("gateway-adoption", iface, net.ParseIP("192.168.56.94").To4(), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}, net.ParseIP("192.168.56.1").To4(), 0)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	details, err := manager.lookup(adopted.IP)
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

	err = manager.updateScripts(adopted.IP, " Traffic Script ", " DNS Script ")
	if err != nil {
		t.Fatalf("update script: %v", err)
	}

	details, err := manager.lookup(adopted.IP)
	if err != nil {
		t.Fatalf("fetch details: %v", err)
	}

	if details.engine.TransportScriptName() != "Traffic Script" {
		t.Fatalf("expected transport script name to be trimmed, got %q", details.engine.TransportScriptName())
	}
	if details.engine.ApplicationScriptName() != "DNS Script" {
		t.Fatalf("expected application script name to be trimmed, got %q", details.engine.ApplicationScriptName())
	}
}

func TestAdoptionManagerUpdateScriptsPreservesBinding(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"script-refresh-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.94").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	if err := manager.updateScripts(adopted.IP, "Traffic Script", "DNS Script"); err != nil {
		t.Fatalf("update script: %v", err)
	}

	details, err := manager.lookup(adopted.IP)
	if err != nil {
		t.Fatalf("details: %v", err)
	}
	if details.engine.TransportScriptName() != "Traffic Script" {
		t.Fatalf("expected refreshed script name Traffic Script, got %q", details.engine.TransportScriptName())
	}
}

func TestAdoptionManagerReplacementStartsFreshIdentity(t *testing.T) {
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

	err = manager.updateScripts(adopted.IP, "Default Script", "Application Script")
	if err != nil {
		t.Fatalf("update script: %v", err)
	}

	if err := manager.release(adopted.IP); err != nil {
		t.Fatalf("release adopted IP: %v", err)
	}
	updated, err := manager.adoptInterface(
		"updated-script-binding-adoption",
		net.Interface{Name: "eth1", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}},
		net.ParseIP("192.168.56.95").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
	)
	if err != nil {
		t.Fatalf("adopt replacement: %v", err)
	}

	details, err := manager.lookup(updated.IP)
	if err != nil {
		t.Fatalf("fetch updated details: %v", err)
	}

	if details.engine.TransportScriptName() != "" {
		t.Fatalf("expected transport script name to reset on update, got %q", details.engine.TransportScriptName())
	}
	if details.engine.ApplicationScriptName() != "" {
		t.Fatalf("expected application script name to reset on update, got %q", details.engine.ApplicationScriptName())
	}
}

func TestAdoptionManagerStartAndStopServiceReflectInDetails(t *testing.T) {
	manager, _ := testAdoptionManager(t)

	adopted, err := manager.adoptInterface(
		"tcp-service-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.118").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	details, err := manager.StartAdoptedIPAddressService(StartAdoptedIPAddressServiceRequest{
		IP:      adopted.IP.String(),
		Service: "echo",
		Config:  map[string]string{"port": "7007"},
	})
	if err != nil {
		t.Fatalf("start service: %v", err)
	}

	services := details.Services()
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Service != "echo" || !services[0].Active || services[0].Port != 7007 {
		t.Fatalf("unexpected service details %+v", services[0])
	}

	details, err = manager.StartAdoptedIPAddressService(StartAdoptedIPAddressServiceRequest{
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
	services = details.Services()
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	httpService := findService(services, "http")
	if httpService == nil || httpService.Config["protocol"] != "https" || httpService.Port != 8443 {
		t.Fatalf("unexpected HTTPS service details %+v", httpService)
	}

	details, err = manager.StopAdoptedIPAddressService(StopAdoptedIPAddressServiceRequest{IP: adopted.IP.String(), Service: "echo"})
	if err != nil {
		t.Fatalf("stop service: %v", err)
	}
	services = details.Services()
	if len(services) != 1 {
		t.Fatalf("expected HTTPS service to remain after echo stop, got %+v", services)
	}
	httpService = findService(services, "http")
	if httpService == nil || httpService.Config["protocol"] != "https" {
		t.Fatalf("expected HTTPS service to remain active, got %+v", services)
	}
}

func findService(items []operations.ServiceMetadata, service string) *operations.ServiceMetadata {
	for index := range items {
		if items[index].Service == service {
			return &items[index]
		}
	}
	return nil
}

func TestAdoptionManagerStartServiceFailureLeavesNoLiveService(t *testing.T) {
	manager, _ := testAdoptionManager(t)
	adopted, err := manager.adoptInterface(
		"failed-service-adoption",
		net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		net.ParseIP("192.168.56.119").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	)
	if err != nil {
		t.Fatalf("adopt IP: %v", err)
	}

	if _, err := manager.StartAdoptedIPAddressService(StartAdoptedIPAddressServiceRequest{
		IP:      adopted.IP.String(),
		Service: "http",
		Config:  map[string]string{"port": "8080", "rootDirectory": "/definitely/missing/kraken-test-root"},
	}); err == nil {
		t.Fatal("expected start error")
	}

	details, err := manager.lookup(adopted.IP)
	if err != nil {
		t.Fatalf("details: %v", err)
	}
	if services := details.Services(); len(services) != 0 {
		t.Fatalf("expected failed service to leave no status, got %+v", services)
	}
}
