package operations

import (
	"encoding/binary"
	"net"
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

func TestSummarizeDNSMessageExplainsRecordFields(t *testing.T) {
	records := summarizeDNSMessage(&layers.DNS{Answers: []layers.DNSResourceRecord{{
		Name:  []byte("example.com"),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
		TTL:   284,
		IP:    net.ParseIP("192.0.2.1"),
	}}})
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	record := records[0]
	if record.Section != "Answer" || record.Type != "A" || record.Class != "IN" || record.TTL != 284 || record.Value != "192.0.2.1" {
		t.Fatalf("unexpected record: %+v", record)
	}
}
