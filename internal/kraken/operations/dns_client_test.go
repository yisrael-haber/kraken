package operations

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestSummarizeDNSMessageExplainsRecordFields(t *testing.T) {
	records := summarizeDNSMessage(&dns.Msg{Answer: []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 284},
		A:   net.ParseIP("192.0.2.1"),
	}}})
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	record := records[0]
	if record.Section != "Answer" || record.Type != "A" || record.Class != "IN" || record.TTL != 284 || record.Value != "192.0.2.1" {
		t.Fatalf("unexpected record: %+v", record)
	}
}
