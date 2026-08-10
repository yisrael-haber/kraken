package operations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultDNSResolveTimeoutMillis = 3000
	defaultDNSPort                 = 53
	maxDNSUDPResponseSize          = 4096
)

type ResolveDNSAdoptedIPAddressRequest struct {
	SourceIP      string `json:"sourceIP"`
	Server        string `json:"server"`
	Name          string `json:"name"`
	Type          string `json:"type,omitempty"`
	Transport     string `json:"transport,omitempty"`
	TimeoutMillis int    `json:"timeoutMillis,omitempty"`
}

type ResolveDNSAdoptedIPAddressResult struct {
	ResolveDNSAdoptedIPAddressRequest
	RTTMillis    float64     `json:"rttMillis,omitempty"`
	ResponseID   int         `json:"responseID,omitempty"`
	ResponseCode string      `json:"responseCode,omitempty"`
	Records      []DNSRecord `json:"records,omitempty"`
}

type DNSRecord struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Class   string `json:"class"`
	TTL     uint32 `json:"ttl"`
	Value   string `json:"value"`
}

func ResolveDNSWithDialer(request ResolveDNSAdoptedIPAddressRequest, dialTCP func(context.Context, net.IP, int) (net.Conn, error), dialUDP func(net.IP, int) (net.Conn, error)) (result ResolveDNSAdoptedIPAddressResult, resultErr error) {
	serverIP, serverPort, queryType, err := normalizeDNSRequest(&request)
	if err != nil {
		return result, err
	}
	timeout := time.Duration(request.TimeoutMillis) * time.Millisecond
	var conn net.Conn
	if request.Transport == "tcp" {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err = dialTCP(ctx, serverIP, serverPort)
	} else {
		conn, err = dialUDP(serverIP, serverPort)
	}
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, conn.Close())
	}()

	query := new(dns.Msg).SetQuestion(dns.Fqdn(request.Name), queryType)
	response, rtt, err := (&dns.Client{
		Timeout: timeout,
		UDPSize: maxDNSUDPResponseSize,
	}).ExchangeWithConn(query, &dns.Conn{Conn: conn})
	if err != nil {
		return result, err
	}

	result = ResolveDNSAdoptedIPAddressResult{
		ResolveDNSAdoptedIPAddressRequest: request,
		RTTMillis:                         float64(rtt) / float64(time.Millisecond),
		ResponseID:                        int(response.Id),
		ResponseCode:                      dns.RcodeToString[response.Rcode],
		Records:                           summarizeDNSMessage(response),
	}
	return result, nil
}

func summarizeDNSMessage(message *dns.Msg) []DNSRecord {
	result := make([]DNSRecord, 0, len(message.Answer)+len(message.Ns)+len(message.Extra))
	for _, item := range message.Answer {
		result = append(result, summarizeDNSRecord("Answer", item))
	}
	for _, item := range message.Ns {
		result = append(result, summarizeDNSRecord("Authority", item))
	}
	for _, item := range message.Extra {
		result = append(result, summarizeDNSRecord("Additional", item))
	}
	return result
}

func summarizeDNSRecord(section string, record dns.RR) DNSRecord {
	header := record.Header()
	return DNSRecord{
		Section: section,
		Name:    strings.TrimSuffix(header.Name, "."),
		Type:    dns.Type(header.Rrtype).String(),
		Class:   dns.Class(header.Class).String(),
		TTL:     header.Ttl,
		Value:   strings.TrimSpace(strings.TrimPrefix(record.String(), header.String())),
	}
}

func parseDNSServer(value string) (net.IP, int, error) {
	server := strings.TrimSpace(value)
	if server == "" {
		return nil, 0, fmt.Errorf("a DNS server is required")
	}

	if address, err := netip.ParseAddr(server); err == nil && address.Is4() {
		return net.IP(address.AsSlice()), defaultDNSPort, nil
	}

	address, err := netip.ParseAddrPort(server)
	if err != nil || !address.Addr().Is4() || address.Port() == 0 {
		return nil, 0, fmt.Errorf("DNS server must be an IPv4 address or IPv4:port")
	}
	return net.IP(address.Addr().AsSlice()), int(address.Port()), nil
}

func normalizeDNSRequest(request *ResolveDNSAdoptedIPAddressRequest) (net.IP, int, uint16, error) {
	request.SourceIP = strings.TrimSpace(request.SourceIP)
	request.Server = strings.TrimSpace(request.Server)
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" {
		return nil, 0, 0, fmt.Errorf("a DNS question name is required")
	}
	request.Type = strings.ToUpper(strings.TrimSpace(request.Type))
	if request.Type == "" {
		request.Type = "A"
	}
	queryType, exists := dns.StringToType[request.Type]
	if !exists {
		return nil, 0, 0, fmt.Errorf("unsupported DNS query type %q", request.Type)
	}
	request.Transport = strings.ToLower(strings.TrimSpace(request.Transport))
	if request.Transport != "tcp" {
		request.Transport = "udp"
	}
	if request.TimeoutMillis <= 0 {
		request.TimeoutMillis = defaultDNSResolveTimeoutMillis
	}
	serverIP, serverPort, err := parseDNSServer(request.Server)
	if err != nil {
		return nil, 0, 0, err
	}
	return serverIP, serverPort, queryType, nil
}
