package operations

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestBuildDNSQueryPayloadTCPPrefixesMessage(t *testing.T) {
	payload, err := buildDNSQueryPayload("example.com", layers.DNSTypeA, 0x1234, "tcp")
	if err != nil {
		t.Fatalf("build DNS query payload: %v", err)
	}
	if len(payload) < 3 {
		t.Fatalf("expected prefixed DNS payload, got %d bytes", len(payload))
	}

	length := int(binary.BigEndian.Uint16(payload[:2]))
	if length != len(payload)-2 {
		t.Fatalf("expected TCP DNS prefix length %d, got %d", len(payload)-2, length)
	}
}
