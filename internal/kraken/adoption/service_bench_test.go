package adoption

import (
	"fmt"
	"net"
	"testing"
	"time"

	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
)

func BenchmarkServiceSnapshot(b *testing.B) {
	service := &Service{
		entries:   make(map[string]entry),
		listeners: make(map[string]Listener),
	}

	for i := 1; i <= 128; i++ {
		ip := net.IPv4(192, 168, 56, byte(i))
		service.entries[ip.String()] = newEntryWithGateway(
			fmt.Sprintf("host-%03d", i),
			net.Interface{Name: "eth0"},
			ip,
			net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(i)},
			net.IPv4(192, 168, 56, 1),
		)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		items := service.Snapshot()
		if len(items) != 128 {
			b.Fatalf("expected 128 adopted IPs, got %d", len(items))
		}
	}
}

func BenchmarkServiceDetails(b *testing.B) {
	ip := net.IPv4(192, 168, 56, 10)
	item := newEntryWithGateway("bench", net.Interface{Name: "eth0"}, ip, net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}, net.IPv4(192, 168, 56, 1))

	listener := &fakeAdoptionListener{
		arpCacheEntries: []ARPCacheItem{{
			IP:        "192.168.56.20",
			MAC:       "02:00:00:00:00:20",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}},
		recordingByIP: map[string]*PacketRecordingStatus{
			ip.String(): {
				Active:     true,
				OutputPath: "/tmp/bench.pcap",
				StartedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			},
		},
		tcpServicesByIP: map[string]map[string]*TCPServiceStatus{
			ip.String(): {
				TCPServiceHTTP: {
					Service:   TCPServiceHTTP,
					Active:    true,
					Port:      8080,
					StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
				},
			},
		},
	}

	service := &Service{
		entries: map[string]entry{
			ip.String(): item,
		},
		listeners: map[string]Listener{
			"eth0": listener,
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		details, err := service.Details(ip.String())
		if err != nil {
			b.Fatalf("details: %v", err)
		}
		if details.IP != ip.String() {
			b.Fatalf("unexpected details %+v", details)
		}
	}
}

func BenchmarkServiceResolveForwardingDirect(b *testing.B) {
	targetIP := net.IPv4(10, 0, 0, 99)
	service := &Service{
		entries: map[string]entry{
			targetIP.String(): newEntryWithGateway(
				"target",
				net.Interface{Name: "eth0"},
				targetIP,
				net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
				nil,
			),
		},
		listeners: map[string]Listener{
			"eth0": &fakeAdoptionListener{},
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decision, ok := service.resolveForwarding(targetIP)
		if !ok || decision.Routed || decision.Identity == nil {
			b.Fatal("expected direct forwarding decision")
		}
	}
}

func BenchmarkServiceResolveForwardingRoute(b *testing.B) {
	viaIP := net.IPv4(192, 168, 56, 10)
	destinationIP := net.IPv4(10, 0, 0, 99)
	route := routingpkg.StoredRoute{
		Label:           "lab-segment",
		DestinationCIDR: "10.0.0.0/24",
		ViaAdoptedIP:    viaIP.String(),
	}
	service := &Service{
		entries: map[string]entry{
			viaIP.String(): newEntryWithGateway(
				"via",
				net.Interface{Name: "eth0"},
				viaIP,
				net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
				net.IPv4(192, 168, 56, 1),
			),
		},
		listeners: map[string]Listener{
			"eth0": &fakeAdoptionListener{},
		},
		routeMatch: func(ip net.IP) (routingpkg.StoredRoute, bool) {
			return route, ip.Equal(destinationIP)
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decision, ok := service.resolveForwarding(destinationIP)
		if !ok || !decision.Routed || decision.Identity == nil {
			b.Fatal("expected routed forwarding decision")
		}
	}
}
