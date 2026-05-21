package adoption

import (
	"net"
	"strings"
	"testing"
)

func TestBuildRecordingBPFFilterIncludesIPAndARPClauses(t *testing.T) {
	ifaceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	filter := buildRecordingBPFFilter(Identity{
		IP:  net.ParseIP("192.168.56.10").To4(),
		MAC: HardwareAddr(ifaceMAC),
	}, ifaceMAC)

	for _, fragment := range []string{
		"(ip host 192.168.56.10)",
		"(arp and (arp src host 192.168.56.10 or arp dst host 192.168.56.10))",
	} {
		if !strings.Contains(filter, fragment) {
			t.Fatalf("expected filter %q to contain %q", filter, fragment)
		}
	}
	if strings.Contains(filter, "ether host") {
		t.Fatalf("expected shared interface MAC to avoid extra ether host clause, got %q", filter)
	}
}

func TestBuildRecordingBPFFilterIncludesCustomMACClause(t *testing.T) {
	filter := buildRecordingBPFFilter(Identity{
		IP:  net.ParseIP("192.168.56.11").To4(),
		MAC: HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
	}, net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10})

	if !strings.Contains(filter, "(ether host 02:aa:bb:cc:dd:ee)") {
		t.Fatalf("expected custom MAC clause in filter, got %q", filter)
	}
}
