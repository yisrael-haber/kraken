package operations

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseDNSServerBareIPv4UsesDefaultPort(t *testing.T) {
	ip, port, err := parseDNSServer("8.8.8.8")
	if err != nil {
		t.Fatalf("parse DNS server: %v", err)
	}
	if got := ip.String(); got != "8.8.8.8" {
		t.Fatalf("expected server ip 8.8.8.8, got %q", got)
	}
	if port != 53 {
		t.Fatalf("expected default port 53, got %d", port)
	}
}

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

	decoded := &layers.DNS{}
	if err := decoded.DecodeFromBytes(payload[2:], gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("decode DNS query: %v", err)
	}
	if decoded.ID != 0x1234 {
		t.Fatalf("expected query id 0x1234, got 0x%04x", decoded.ID)
	}
	if got := string(decoded.Questions[0].Name); got != "example.com" {
		t.Fatalf("expected question name example.com, got %q", got)
	}
}
