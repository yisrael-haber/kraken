package common

import (
	"net"
	"testing"
)

func TestNormalizeAdoptionLabelTrimsOuterSpaceOnly(t *testing.T) {
	label, err := NormalizeAdoptionLabel("  lab device 01  ")
	if err != nil {
		t.Fatalf("normalize label: %v", err)
	}
	if label != "lab device 01" {
		t.Fatalf("expected trimmed label, got %q", label)
	}

	for _, value := range []string{"", "   ", "lab/device", "lab\tdevice"} {
		if _, err := NormalizeAdoptionLabel(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestNormalizeAdoptionIPAcceptsTrimmedIPv4Only(t *testing.T) {
	ip, err := NormalizeAdoptionIP(" 192.168.56.10 ")
	if err != nil {
		t.Fatalf("normalize IPv4: %v", err)
	}
	if got := ip.String(); got != "192.168.56.10" {
		t.Fatalf("expected 192.168.56.10, got %s", got)
	}

	for _, value := range []string{"", "2001:db8::1", "192.168.56.10 garbage"} {
		if _, err := NormalizeAdoptionIP(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestNormalizeDefaultGatewayRejectsZeroSelfAndIPv6(t *testing.T) {
	adopted := net.IPv4(192, 168, 56, 10)
	if gateway, err := NormalizeDefaultGateway("", adopted); err != nil || gateway != nil {
		t.Fatalf("empty gateway should be unset, got %v err %v", gateway, err)
	}

	for _, value := range []string{"0.0.0.0", "192.168.56.10", "2001:db8::1"} {
		if _, err := NormalizeDefaultGateway(value, adopted); err == nil {
			t.Fatalf("expected gateway %q to be rejected", value)
		}
	}
}
