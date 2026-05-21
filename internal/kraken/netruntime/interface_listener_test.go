package netruntime

import "testing"

func TestClassifyInboundFrameCapturesTargetIP(t *testing.T) {
	arpInfo, ok := classifyInboundFrame([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 0x20, 0x08, 0x06,
		0, 1, 0x08, 0, 6, 4, 0, 1, 0x02, 0, 0, 0, 0, 0x20, 192, 168, 56, 20,
		0, 0, 0, 0, 0, 0, 192, 168, 56, 10,
	})
	if !ok || arpInfo.String() != "192.168.56.10" {
		t.Fatalf("expected ARP target IP 192.168.56.10, got %s classified=%t", arpInfo, ok)
	}

	ipv4Info, ok := classifyInboundFrame([]byte{
		0x02, 0, 0, 0, 0, 0x10, 0x02, 0, 0, 0, 0, 0x20, 0x08, 0,
		0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 168, 56, 20, 192, 168, 56, 10,
	})
	if !ok || ipv4Info.String() != "192.168.56.10" {
		t.Fatalf("expected IPv4 target IP 192.168.56.10, got %s classified=%t", ipv4Info, ok)
	}
}
