package operations

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	defaultDNSResolveTimeout = 3 * time.Second
	defaultDNSPort           = 53
	maxDNSUDPResponseSize    = 4096
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
	SourceIP     string      `json:"sourceIP"`
	Server       string      `json:"server"`
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Transport    string      `json:"transport"`
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

func DNSDialTarget(request ResolveDNSAdoptedIPAddressRequest) (net.IP, int, string, time.Duration, error) {
	serverIP, serverPort, err := parseDNSServer(request.Server)
	if err != nil {
		return nil, 0, "", 0, err
	}
	return serverIP, serverPort, normalizeDNSClientTransport(request.Transport), dnsTimeout(request), nil
}

func ResolveDNSWithDialer(request ResolveDNSAdoptedIPAddressRequest, dialTCP func(context.Context, net.IP, int) (net.Conn, error), dialUDP func(net.IP, int) (net.Conn, error)) (ResolveDNSAdoptedIPAddressResult, error) {
	serverIP, serverPort, transport, timeout, err := DNSDialTarget(request)
	if err != nil {
		return ResolveDNSAdoptedIPAddressResult{}, err
	}
	var conn net.Conn
	if transport == "tcp" {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err = dialTCP(ctx, serverIP, serverPort)
	} else {
		conn, err = dialUDP(serverIP, serverPort)
	}
	if err != nil {
		return ResolveDNSAdoptedIPAddressResult{}, err
	}
	defer conn.Close()
	return ResolveDNS(conn, request)
}

func ResolveDNS(conn net.Conn, request ResolveDNSAdoptedIPAddressRequest) (ResolveDNSAdoptedIPAddressResult, error) {
	result := ResolveDNSAdoptedIPAddressResult{
		SourceIP:  strings.TrimSpace(request.SourceIP),
		Server:    strings.TrimSpace(request.Server),
		Name:      strings.TrimSpace(request.Name),
		Transport: normalizeDNSClientTransport(request.Transport),
	}

	questionName := strings.TrimSpace(request.Name)
	if questionName == "" {
		return result, fmt.Errorf("a DNS question name is required")
	}

	queryType, err := parseDNSQueryType(request.Type)
	if err != nil {
		return result, err
	}
	result.Type = queryType.String()

	_ = conn.SetDeadline(time.Now().Add(dnsTimeout(request)))

	var rawID [2]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return result, fmt.Errorf("random DNS message id: %w", err)
	}
	payload, err := buildDNSQueryPayload(questionName, queryType, binary.BigEndian.Uint16(rawID[:]), result.Transport)
	if err != nil {
		return result, err
	}

	sentAt := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return result, err
	}
	result.RTTMillis = float64(time.Since(sentAt)) / float64(time.Millisecond)

	var response []byte
	if result.Transport == "tcp" {
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return result, err
		}
		response = make([]byte, int(binary.BigEndian.Uint16(header)))
		_, err = io.ReadFull(conn, response)
	} else {
		response = make([]byte, maxDNSUDPResponseSize)
		n, readErr := conn.Read(response)
		response = response[:n]
		err = readErr
	}
	if err != nil {
		return result, err
	}

	decoded := &layers.DNS{}
	if err := decoded.DecodeFromBytes(response, gopacket.NilDecodeFeedback); err != nil {
		return result, fmt.Errorf("decode DNS response: %w", err)
	}

	result.ResponseID = int(decoded.ID)
	result.ResponseCode = decoded.ResponseCode.String()
	result.Records = summarizeDNSMessage(decoded)
	return result, nil
}

func dnsTimeout(request ResolveDNSAdoptedIPAddressRequest) time.Duration {
	if request.TimeoutMillis > 0 {
		return time.Duration(request.TimeoutMillis) * time.Millisecond
	}
	return defaultDNSResolveTimeout
}

func buildDNSQueryPayload(name string, queryType layers.DNSType, queryID uint16, transport string) ([]byte, error) {
	dns := &layers.DNS{
		ID:      queryID,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte(strings.TrimSpace(name)),
			Type:  queryType,
			Class: layers.DNSClassIN,
		}},
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		return nil, fmt.Errorf("serialize DNS query: %w", err)
	}

	payload := append([]byte(nil), buffer.Bytes()...)
	if transport != "tcp" {
		return payload, nil
	}

	framed := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(payload)))
	copy(framed[2:], payload)
	return framed, nil
}

func summarizeDNSMessage(message *layers.DNS) []DNSRecord {
	if message == nil {
		return nil
	}

	result := make([]DNSRecord, 0, len(message.Answers)+len(message.Authorities)+len(message.Additionals))
	for _, item := range message.Answers {
		result = append(result, summarizeDNSRecord("Answer", item))
	}
	for _, item := range message.Authorities {
		result = append(result, summarizeDNSRecord("Authority", item))
	}
	for _, item := range message.Additionals {
		result = append(result, summarizeDNSRecord("Additional", item))
	}
	return result
}

func summarizeDNSRecord(section string, record layers.DNSResourceRecord) DNSRecord {
	return DNSRecord{
		Section: section,
		Name:    string(record.Name),
		Type:    record.Type.String(),
		Class:   record.Class.String(),
		TTL:     record.TTL,
		Value:   record.String(),
	}
}

func parseDNSServer(value string) (net.IP, int, error) {
	server := strings.TrimSpace(value)
	if server == "" {
		return nil, 0, fmt.Errorf("a DNS server is required")
	}

	if ip := net.ParseIP(server).To4(); ip != nil {
		return ip, defaultDNSPort, nil
	}

	host, portText, err := net.SplitHostPort(server)
	if err != nil {
		return nil, 0, fmt.Errorf("DNS server must be an IPv4 address or IPv4:port")
	}
	ip := net.ParseIP(strings.TrimSpace(host)).To4()
	if ip == nil {
		return nil, 0, fmt.Errorf("DNS server must be an IPv4 address")
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, fmt.Errorf("DNS server port must be between 1 and 65535")
	}

	return ip, port, nil
}

func parseDNSQueryType(value string) (layers.DNSType, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "A":
		return layers.DNSTypeA, nil
	case "AAAA":
		return layers.DNSTypeAAAA, nil
	case "CNAME":
		return layers.DNSTypeCNAME, nil
	case "MX":
		return layers.DNSTypeMX, nil
	case "NS":
		return layers.DNSTypeNS, nil
	case "PTR":
		return layers.DNSTypePTR, nil
	case "SOA":
		return layers.DNSTypeSOA, nil
	case "SRV":
		return layers.DNSTypeSRV, nil
	case "TXT":
		return layers.DNSTypeTXT, nil
	default:
		return 0, fmt.Errorf("unsupported DNS query type %q", strings.TrimSpace(value))
	}
}

func normalizeDNSClientTransport(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "tcp") {
		return "tcp"
	}
	return "udp"
}
