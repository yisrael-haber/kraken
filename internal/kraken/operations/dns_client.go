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
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

const (
	defaultDNSResolveTimeout = 3 * time.Second
	defaultDNSPort           = 53
	maxDNSUDPResponseSize    = 4096
)

func (listener *pcapAdoptionListener) ResolveDNS(source adoption.Identity, request adoption.ResolveDNSAdoptedIPAddressRequest) (adoption.ResolveDNSAdoptedIPAddressResult, error) {
	result := adoption.ResolveDNSAdoptedIPAddressResult{
		Server:    strings.TrimSpace(request.Server),
		Name:      strings.TrimSpace(request.Name),
		Type:      normalizeDNSQueryTypeLabel(request.Type),
		Transport: normalizeDNSClientTransport(request.Transport),
	}

	if source.IP.To4() == nil {
		return result, fmt.Errorf("a valid IPv4 source is required")
	}
	result.SourceIP = source.IP.String()

	serverIP, serverPort, serverText, err := parseDNSServer(request.Server)
	if err != nil {
		return result, err
	}
	result.Server = serverText

	questionName := strings.TrimSpace(request.Name)
	if questionName == "" {
		return result, fmt.Errorf("a DNS question name is required")
	}

	queryType, err := parseDNSQueryType(request.Type)
	if err != nil {
		return result, err
	}
	result.Type = queryType.String()

	timeout := defaultDNSResolveTimeout
	if request.TimeoutMillis > 0 {
		timeout = time.Duration(request.TimeoutMillis) * time.Millisecond
	}

	group, err := listener.engineForIdentity(source)
	if err != nil {
		return result, err
	}

	serviceInfo := scriptpkg.ApplicationServiceInfo{
		Name:     "dns",
		Port:     serverPort,
		Protocol: "dns",
	}
	binding, err := resolveApplicationScriptBinding(source, listener.resolveScript, serviceInfo, nil, nil, nil)
	if err != nil {
		return result, err
	}

	response, rtt, err := group.resolveDNS(source.IP.To4(), serverIP, serverPort, questionName, queryType, result.Transport, timeout, binding)
	if err != nil {
		return result, err
	}
	result.RTTMillis = float64(rtt) / float64(time.Millisecond)

	payload := response
	if result.Transport == "tcp" {
		if trimmed, prefixed := trimTCPDNSPrefix(response); prefixed {
			payload = trimmed
		}
	}

	decoded := &layers.DNS{}
	if err := decoded.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return result, fmt.Errorf("decode DNS response: %w", err)
	}

	result.ResponseID = int(decoded.ID)
	result.ResponseCode = decoded.ResponseCode.String()
	result.Records = summarizeDNSMessage(decoded)

	return result, nil
}

func (group *adoptedEngine) resolveDNS(
	sourceIP net.IP,
	serverIP net.IP,
	serverPort int,
	name string,
	queryType layers.DNSType,
	transport string,
	timeout time.Duration,
	binding *applicationScriptBinding,
) ([]byte, time.Duration, error) {
	conn, err := group.dialDNS(sourceIP, serverIP, serverPort, transport, timeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	queryID, err := randomDNSMessageID()
	if err != nil {
		return nil, 0, err
	}
	payload, err := buildDNSQueryPayload(name, queryType, queryID, transport)
	if err != nil {
		return nil, 0, err
	}

	connection := scriptpkg.ApplicationConnection{
		LocalAddress:  conn.LocalAddr().String(),
		RemoteAddress: conn.RemoteAddr().String(),
		Transport:     transport,
	}
	if binding != nil {
		payload, err = binding.apply("outbound", payload, connection)
		if err != nil {
			return nil, 0, err
		}
	}
	if transport == "tcp" {
		payload = ensureTCPDNSPrefix(payload)
	}

	sentAt := time.Now()
	if err := writeAll(conn, payload); err != nil {
		return nil, 0, err
	}

	response, err := readDNSResponse(conn, transport)
	if err != nil {
		return nil, 0, err
	}
	rtt := time.Since(sentAt)

	if binding != nil {
		response, err = binding.apply("inbound", response, connection)
		if err != nil {
			return nil, 0, err
		}
	}

	return response, rtt, nil
}

func (group *adoptedEngine) dialDNS(sourceIP net.IP, serverIP net.IP, serverPort int, transport string, timeout time.Duration) (net.Conn, error) {
	sourceIP = sourceIP.To4()
	serverIP = serverIP.To4()
	if group == nil || sourceIP == nil || serverIP == nil {
		return nil, fmt.Errorf("DNS client requires valid IPv4 source and server addresses")
	}

	switch transport {
	case "tcp":
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return group.dialTCP(ctx, sourceIP, serverIP, serverPort)
	default:
		return group.dialUDP(sourceIP, serverIP, serverPort)
	}
}

func parseDNSServer(value string) (net.IP, int, string, error) {
	server := strings.TrimSpace(value)
	if server == "" {
		return nil, 0, "", fmt.Errorf("a DNS server is required")
	}

	if ip := net.ParseIP(server).To4(); ip != nil {
		return ip, defaultDNSPort, net.JoinHostPort(ip.String(), strconv.Itoa(defaultDNSPort)), nil
	}

	host, portText, err := net.SplitHostPort(server)
	if err != nil {
		return nil, 0, "", fmt.Errorf("DNS server must be an IPv4 address or IPv4:port")
	}
	ip := net.ParseIP(strings.TrimSpace(host)).To4()
	if ip == nil {
		return nil, 0, "", fmt.Errorf("DNS server must be an IPv4 address")
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, "", fmt.Errorf("DNS server port must be between 1 and 65535")
	}

	return ip, port, net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
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

func normalizeDNSQueryTypeLabel(value string) string {
	parsed, err := parseDNSQueryType(value)
	if err != nil {
		return "A"
	}
	return parsed.String()
}

func normalizeDNSClientTransport(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp":
		return "tcp"
	default:
		return "udp"
	}
}

func randomDNSMessageID() (uint16, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("random DNS message id: %w", err)
	}
	return binary.BigEndian.Uint16(raw[:]), nil
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

func ensureTCPDNSPrefix(payload []byte) []byte {
	if trimmed, prefixed := trimTCPDNSPrefix(payload); prefixed {
		framed := make([]byte, 2+len(trimmed))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(trimmed)))
		copy(framed[2:], trimmed)
		return framed
	}

	framed := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(payload)))
	copy(framed[2:], payload)
	return framed
}

func readDNSResponse(conn net.Conn, transport string) ([]byte, error) {
	if transport == "tcp" {
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, err
		}
		length := int(binary.BigEndian.Uint16(header))
		payload := make([]byte, 2+length)
		copy(payload[:2], header)
		if _, err := io.ReadFull(conn, payload[2:]); err != nil {
			return nil, err
		}
		return payload, nil
	}

	buffer := make([]byte, maxDNSUDPResponseSize)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buffer[:n]...), nil
}

func summarizeDNSMessage(message *layers.DNS) []string {
	if message == nil {
		return nil
	}

	result := make([]string, 0, len(message.Questions)+len(message.Answers)+len(message.Authorities)+len(message.Additionals))
	for _, item := range message.Questions {
		result = append(result, fmt.Sprintf("question %s %s %s", string(item.Name), item.Class, item.Type))
	}
	for _, item := range message.Answers {
		result = append(result, fmt.Sprintf("answer %s %d %s", string(item.Name), item.TTL, item.String()))
	}
	for _, item := range message.Authorities {
		result = append(result, fmt.Sprintf("authority %s %d %s", string(item.Name), item.TTL, item.String()))
	}
	for _, item := range message.Additionals {
		result = append(result, fmt.Sprintf("additional %s %d %s", string(item.Name), item.TTL, item.String()))
	}
	return result
}

func trimTCPDNSPrefix(payload []byte) ([]byte, bool) {
	if len(payload) < 2 {
		return payload, false
	}
	length := int(binary.BigEndian.Uint16(payload[:2]))
	if length == len(payload)-2 {
		return payload[2:], true
	}
	return payload, false
}
