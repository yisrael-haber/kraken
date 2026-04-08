package capture

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type fakeIdentity struct {
	ip             net.IP
	iface          net.Interface
	mac            net.HardwareAddr
	defaultGateway net.IP
	bindings       adoption.AdoptedIPAddressOverrideBindings
}

func (identity fakeIdentity) IP() net.IP { return identity.ip }

func (identity fakeIdentity) Interface() net.Interface { return identity.iface }

func (identity fakeIdentity) MAC() net.HardwareAddr { return identity.mac }

func (identity fakeIdentity) DefaultGateway() net.IP { return identity.defaultGateway }

func (identity fakeIdentity) OverrideBindings() adoption.AdoptedIPAddressOverrideBindings {
	return identity.bindings
}

func (identity fakeIdentity) RecordARP(string, string, net.IP, net.HardwareAddr, string) {}

func (identity fakeIdentity) RecordICMP(string, string, net.IP, uint16, uint16, time.Duration, string, string) {
}

func TestARPCacheLookupEvictsExpiredEntries(t *testing.T) {
	cache := &arpCache{
		entries: map[string]arpCacheEntry{
			"192.168.56.1": {
				mac:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
				updated: time.Now().Add(-2 * time.Second),
			},
		},
		ttl:           time.Second,
		sweepInterval: time.Minute,
		maxEntries:    8,
	}

	if _, ok := cache.lookup(net.ParseIP("192.168.56.1").To4()); ok {
		t.Fatal("expected expired ARP cache entry to miss")
	}

	cache.mu.RLock()
	_, exists := cache.entries["192.168.56.1"]
	cache.mu.RUnlock()
	if exists {
		t.Fatal("expected expired ARP cache entry to be removed after lookup")
	}
}

func TestARPCacheStoreSweepsExpiredEntriesAndCapsSize(t *testing.T) {
	now := time.Now()
	cache := &arpCache{
		entries: map[string]arpCacheEntry{
			"10.0.0.1": {
				mac:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
				updated: now.Add(-5 * time.Second),
			},
			"10.0.0.2": {
				mac:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
				updated: now.Add(-2 * time.Second),
			},
			"10.0.0.3": {
				mac:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x03},
				updated: now.Add(-time.Second),
			},
		},
		ttl:           3 * time.Second,
		sweepInterval: time.Millisecond,
		maxEntries:    2,
		lastSweep:     now.Add(-time.Second),
	}

	cache.store(net.ParseIP("10.0.0.4").To4(), net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x04})

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	if len(cache.entries) != 2 {
		t.Fatalf("expected ARP cache size to be capped at 2 entries, got %d", len(cache.entries))
	}
	if _, exists := cache.entries["10.0.0.1"]; exists {
		t.Fatal("expected expired ARP cache entry 10.0.0.1 to be swept")
	}
	if _, exists := cache.entries["10.0.0.2"]; exists {
		t.Fatal("expected oldest live ARP cache entry 10.0.0.2 to be evicted when the cache exceeds its cap")
	}
	if _, exists := cache.entries["10.0.0.3"]; !exists {
		t.Fatal("expected newer live ARP cache entry 10.0.0.3 to be retained")
	}
	if _, exists := cache.entries["10.0.0.4"]; !exists {
		t.Fatal("expected newly stored ARP cache entry 10.0.0.4 to be retained")
	}
}

func TestShouldRouteDirect(t *testing.T) {
	routes := []net.IPNet{
		{
			IP:   net.ParseIP("192.168.56.0").To4(),
			Mask: net.CIDRMask(24, 32),
		},
	}

	if !shouldRouteDirect(net.ParseIP("192.168.56.77").To4(), routes) {
		t.Fatal("expected on-subnet target to route directly")
	}
	if shouldRouteDirect(net.ParseIP("8.8.8.8").To4(), routes) {
		t.Fatal("expected off-subnet target to require next hop")
	}
	if !shouldRouteDirect(net.ParseIP("8.8.8.8").To4(), nil) {
		t.Fatal("expected direct routing fallback when no interface routes are known")
	}
}

func TestOutboundNextHopIPUsesDefaultGatewayForOffSubnetTraffic(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("list interfaces: %v", err)
	}

	var iface *net.Interface
	for index := range interfaces {
		if interfaces[index].Flags&net.FlagLoopback == 0 {
			continue
		}
		iface = &interfaces[index]
		break
	}
	if iface == nil {
		t.Skip("no loopback interface available")
	}

	nextHop := outboundNextHopIP(fakeIdentity{
		ip:             net.ParseIP("127.0.0.2").To4(),
		iface:          *iface,
		mac:            net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		defaultGateway: net.ParseIP("127.0.0.1").To4(),
	}, net.ParseIP("8.8.8.8").To4())
	if common.IPString(nextHop) != "127.0.0.1" {
		t.Fatalf("expected next hop 127.0.0.1, got %s", common.IPString(nextHop))
	}
}

func TestPcapAdoptionListenerHealthy(t *testing.T) {
	t.Run("reports run error before stopped state", func(t *testing.T) {
		runErr := errors.New("capture loop exited")
		listener := &pcapAdoptionListener{
			done:   make(chan struct{}),
			runErr: runErr,
		}
		close(listener.done)

		if err := listener.Healthy(); !errors.Is(err, runErr) {
			t.Fatalf("expected run error %v, got %v", runErr, err)
		}
	})

	t.Run("reports stopped listener", func(t *testing.T) {
		listener := &pcapAdoptionListener{
			done: make(chan struct{}),
		}
		close(listener.done)

		if err := listener.Healthy(); !errors.Is(err, adoption.ErrListenerStopped) {
			t.Fatalf("expected ErrListenerStopped, got %v", err)
		}
	})

	t.Run("reports healthy while running", func(t *testing.T) {
		listener := &pcapAdoptionListener{
			done: make(chan struct{}),
		}

		if err := listener.Healthy(); err != nil {
			t.Fatalf("expected listener to be healthy, got %v", err)
		}
	})
}
