package adoption

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

func BenchmarkServiceSnapshot(b *testing.B) {
	service := &Manager{
		entries: make(map[string]*Identity),
	}

	for i := 1; i <= 128; i++ {
		ip := net.IPv4(192, 168, 56, byte(i))
		identity := newIdentityWithGatewayAndScripts(
			fmt.Sprintf("host-%03d", i),
			net.Interface{Name: "eth0"},
			ip,
			net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(i)},
			net.IPv4(192, 168, 56, 1),
			0,
			"",
			"",
		)
		service.entries[ip.String()] = &identity
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
	item := newIdentityWithGatewayAndScripts("bench", net.Interface{Name: "eth0"}, ip, net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}, net.IPv4(192, 168, 56, 1), 0, "", "")

	listener := &fakeAdoptionListener{
		recordingByIP: map[string]*PacketRecordingStatus{
			ip.String(): {
				Active:     true,
				OutputPath: "/tmp/bench.pcap",
				StartedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			},
		},
		servicesByIP: map[string]map[string]*ServiceStatus{
			ip.String(): {
				"http": {
					Service: "http",
					Active:  true,
					Port:    8080,
					Config: map[string]string{
						"port":          "8080",
						"protocol":      "http",
						"rootDirectory": "/tmp/root",
					},
					StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
				},
			},
		},
	}
	item.listener = listener

	service := &Manager{
		entries: map[string]*Identity{
			ip.String(): &item,
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		details, err := service.Details(ip.String())
		if err != nil {
			b.Fatalf("details: %v", err)
		}
		if details.IP.String() != ip.String() {
			b.Fatalf("unexpected details %+v", details)
		}
	}
}

func BenchmarkServiceResolveForwardingDirect(b *testing.B) {
	targetIP := net.IPv4(10, 0, 0, 99)
	listener := &fakeAdoptionListener{}
	identity := newIdentityWithGatewayAndScripts(
		"target",
		net.Interface{Name: "eth0"},
		targetIP,
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		nil,
		0,
		"",
		"",
	)
	identity.listener = listener
	service := &Manager{
		entries: map[string]*Identity{
			targetIP.String(): &identity,
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		forwarded, ok := service.ResolveForwarding(targetIP)
		if !ok || forwarded == nil {
			b.Fatal("expected direct forwarding decision")
		}
	}
}

func BenchmarkServiceResolveForwardingRoute(b *testing.B) {
	viaIP := net.IPv4(192, 168, 56, 10)
	destinationIP := net.IPv4(10, 0, 0, 99)
	listener := &fakeAdoptionListener{}
	identity := newIdentityWithGatewayAndScripts(
		"via",
		net.Interface{Name: "eth0"},
		viaIP,
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
		0,
		"",
		"",
	)
	identity.listener = listener
	route := storage.StoredRoute{
		Label:           "lab-segment",
		DestinationCIDR: "10.0.0.0/24",
		ViaAdoptedIP:    viaIP.String(),
	}
	service := &Manager{
		entries: map[string]*Identity{
			viaIP.String(): &identity,
		},
		routeMatch: func(ip net.IP) (storage.StoredRoute, bool) {
			return route, ip.Equal(destinationIP)
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		forwarded, ok := service.ResolveForwarding(destinationIP)
		if !ok || forwarded == nil {
			b.Fatal("expected routed forwarding decision")
		}
	}
}
