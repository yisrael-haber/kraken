package adoption

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
)

func BenchmarkServiceForwardFrameDirect(b *testing.B) {
	targetIP := net.IPv4(10, 0, 0, 99)
	service := &Manager{
		entries: map[[4]byte]*Identity{
			identityKey(targetIP): {
				IP:       targetIP,
				listener: &fakeAdoptionListener{},
			},
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
	service := &Manager{
		entries: map[[4]byte]*Identity{
			identityKey(viaIP): {
				IP:       viaIP,
				listener: &fakeAdoptionListener{},
			},
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
