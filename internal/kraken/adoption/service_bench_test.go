package adoption

import (
	"fmt"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
)

func BenchmarkServiceSnapshot(b *testing.B) {
	service := &Manager{
		entries: make(map[[4]byte]Identity),
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
		service.entries[identityKey(ip)] = identity
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
	}
	item.listener = listener
	item.Recording = listener.recordingByIP[ip.String()]
	item.Services = []ServiceStatus{{
		Service: "http",
		Active:  true,
		Port:    8080,
		Config: map[string]string{
			"port":          "8080",
			"protocol":      "http",
			"rootDirectory": "/tmp/root",
		},
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}}

	service := &Manager{
		entries: map[[4]byte]Identity{
			identityKey(ip): item,
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		details, err := service.Lookup(ip)
		if err != nil {
			b.Fatalf("details: %v", err)
		}
		if details.IP.String() != ip.String() {
			b.Fatalf("unexpected details %+v", details)
		}
	}
}

func BenchmarkServiceForwardFrameDirect(b *testing.B) {
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
		entries: map[[4]byte]Identity{
			identityKey(targetIP): identity,
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !service.ForwardFrame(targetIP, buffer.MakeWithData(nil)) {
			b.Fatal("expected direct frame forwarding")
		}
	}
}

func BenchmarkServiceForwardFrameRoute(b *testing.B) {
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
	service := &Manager{
		entries: map[[4]byte]Identity{
			identityKey(viaIP): identity,
		},
		routeMatch: func(ip net.IP) (net.IP, bool) {
			return viaIP, ip.Equal(destinationIP)
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !service.ForwardFrame(destinationIP, buffer.MakeWithData(nil)) {
			b.Fatal("expected routed frame forwarding")
		}
	}
}
