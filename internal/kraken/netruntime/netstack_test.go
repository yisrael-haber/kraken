package netruntime

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestBuildNetstackRoutesAddsDefaultGatewayWhenConfigured(t *testing.T) {
	routes, err := buildNetstackRoutes([]net.IPNet{
		{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		},
	}, net.IPv4(192, 168, 56, 1))
	if err != nil {
		t.Fatalf("build routes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if routes[1].Gateway != tcpip.AddrFrom4([4]byte{192, 168, 56, 1}) {
		t.Fatalf("expected gateway route to use 192.168.56.1, got %v", routes[1].Gateway)
	}
}
