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
				IP:         targetIP,
				SubnetMask: IPv4Mask(net.CIDRMask(24, 32)),
				listener:   &fakeAdoptionListener{},
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

func BenchmarkServiceForwardFrameSubnet(b *testing.B) {
	segmentIP := net.IPv4(192, 168, 56, 10)
	destinationIP := net.IPv4(192, 168, 56, 99)
	service := &Manager{
		entries: map[[4]byte]*Identity{
			identityKey(segmentIP): {
				IP:         segmentIP,
				SubnetMask: IPv4Mask(net.CIDRMask(24, 32)),
				listener:   &fakeAdoptionListener{},
			},
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !service.ForwardFrame(destinationIP, buffer.MakeWithData(nil)) {
			b.Fatal("expected routed frame forwarding")
		}
	}
}
