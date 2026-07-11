package operations

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	defaultPingInterval = time.Second
	defaultPingTimeout  = time.Second
	defaultPingCount    = 4
	maxPingCount        = 1000
	maxPingPayload      = 65507
)

type PingAdoptedIPAddressRequest struct {
	SourceIP       string `json:"sourceIP"`
	Destination    string `json:"destination"`
	IntervalMillis int    `json:"intervalMillis,omitempty"`
	TimeoutMillis  int    `json:"timeoutMillis,omitempty"`
	Count          int    `json:"count,omitempty"`
	PayloadSize    int    `json:"payloadSize,omitempty"`
}

type PingAdoptedIPAddressResult struct {
	SourceIP       string      `json:"sourceIP"`
	Destination    string      `json:"destination"`
	IntervalMillis int         `json:"intervalMillis"`
	TimeoutMillis  int         `json:"timeoutMillis"`
	Count          int         `json:"count"`
	PayloadSize    int         `json:"payloadSize"`
	Sent           int         `json:"sent"`
	Received       int         `json:"received"`
	LossPercent    float64     `json:"lossPercent"`
	MinRTTMillis   float64     `json:"minRttMillis,omitempty"`
	AvgRTTMillis   float64     `json:"avgRttMillis,omitempty"`
	MaxRTTMillis   float64     `json:"maxRttMillis,omitempty"`
	Cancelled      bool        `json:"cancelled,omitempty"`
	Probes         []PingProbe `json:"probes,omitempty"`
}

type PingProbe struct {
	Sequence  int     `json:"sequence"`
	Status    string  `json:"status"`
	RTTMillis float64 `json:"rttMillis,omitempty"`
	Bytes     int     `json:"bytes,omitempty"`
	Error     string  `json:"error,omitempty"`
}

type PingDialer func(net.IP, uint16) (net.Conn, error)

func PingWithDialer(ctx context.Context, request PingAdoptedIPAddressRequest, dial PingDialer) (PingAdoptedIPAddressResult, error) {
	return PingWithDialerProgress(ctx, request, dial, nil)
}

func PingWithDialerProgress(ctx context.Context, request PingAdoptedIPAddressRequest, dial PingDialer, report func(PingAdoptedIPAddressResult)) (PingAdoptedIPAddressResult, error) {
	result, destination, interval, timeout, count, payloadSize, err := normalizePingRequest(request)
	if err != nil {
		return result, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if dial == nil {
		return result, fmt.Errorf("ICMP dialer is unavailable")
	}

	var identifierBytes [2]byte
	if _, err := rand.Read(identifierBytes[:]); err != nil {
		return result, fmt.Errorf("random ICMP identifier: %w", err)
	}
	identifier := binary.BigEndian.Uint16(identifierBytes[:])
	conn, err := dial(destination, identifier)
	if err != nil {
		return result, err
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	for sequence := 1; sequence <= count; sequence++ {
		if ctx.Err() != nil {
			result.Cancelled = true
			break
		}
		startedAt := time.Now()
		probe := PingProbe{Sequence: sequence}
		result.Sent++
		requestPacket := buildICMPEchoRequest(identifier, uint16(sequence), payloadSize)
		if err := conn.SetWriteDeadline(startedAt.Add(timeout)); err != nil {
			return result, err
		}
		if _, err := conn.Write(requestPacket); err != nil {
			if ctx.Err() != nil {
				result.Cancelled = true
				probe.Status = "cancelled"
			} else {
				probe.Status = "error"
				probe.Error = err.Error()
			}
			result.Probes = append(result.Probes, probe)
		} else {
			probe = readPingReply(ctx, conn, identifier, uint16(sequence), startedAt, timeout)
			result.Probes = append(result.Probes, probe)
			if probe.Status == "reply" {
				result.Received++
			}
			if ctx.Err() != nil {
				result.Cancelled = true
			}
		}
		summarizePingResult(&result)
		if report != nil {
			report(result)
		}
		if result.Cancelled {
			break
		}

		if sequence < count && !waitForNextPing(ctx, startedAt.Add(interval)) {
			result.Cancelled = true
			break
		}
	}

	summarizePingResult(&result)
	return result, nil
}

func normalizePingRequest(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, net.IP, time.Duration, time.Duration, int, int, error) {
	result := PingAdoptedIPAddressResult{
		SourceIP:    strings.TrimSpace(request.SourceIP),
		Destination: strings.TrimSpace(request.Destination),
	}
	destination := net.ParseIP(result.Destination).To4()
	if destination == nil {
		return result, nil, 0, 0, 0, 0, fmt.Errorf("destination must be a valid IPv4 address")
	}
	intervalMillis := request.IntervalMillis
	if intervalMillis == 0 {
		intervalMillis = int(defaultPingInterval / time.Millisecond)
	}
	if intervalMillis < 1 {
		return result, nil, 0, 0, 0, 0, fmt.Errorf("interval must be a positive integer in milliseconds")
	}
	timeoutMillis := request.TimeoutMillis
	if timeoutMillis == 0 {
		timeoutMillis = int(defaultPingTimeout / time.Millisecond)
	}
	if timeoutMillis < 1 {
		return result, nil, 0, 0, 0, 0, fmt.Errorf("timeout must be a positive integer in milliseconds")
	}
	count := request.Count
	if count == 0 {
		count = defaultPingCount
	}
	if count < 1 || count > maxPingCount {
		return result, nil, 0, 0, 0, 0, fmt.Errorf("count must be between 1 and %d", maxPingCount)
	}
	payloadSize := request.PayloadSize
	if payloadSize < 0 || payloadSize > maxPingPayload {
		return result, nil, 0, 0, 0, 0, fmt.Errorf("payload size must be between 0 and %d bytes", maxPingPayload)
	}
	result.IntervalMillis = intervalMillis
	result.TimeoutMillis = timeoutMillis
	result.Count = count
	result.PayloadSize = payloadSize
	return result, destination, time.Duration(intervalMillis) * time.Millisecond, time.Duration(timeoutMillis) * time.Millisecond, count, payloadSize, nil
}

func buildICMPEchoRequest(identifier, sequence uint16, payloadSize int) []byte {
	packet := make([]byte, header.ICMPv4MinimumSize+payloadSize)
	icmp := header.ICMPv4(packet)
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetCode(0)
	icmp.SetIdent(identifier)
	icmp.SetSequence(sequence)
	for index := range icmp.Payload() {
		icmp.Payload()[index] = byte(index)
	}
	return packet
}

func readPingReply(ctx context.Context, conn net.Conn, identifier, sequence uint16, startedAt time.Time, timeout time.Duration) PingProbe {
	probe := PingProbe{Sequence: int(sequence)}
	deadline := startedAt.Add(timeout)
	packet := make([]byte, header.ICMPv4MinimumSize+maxPingPayload)
	for {
		if ctx.Err() != nil {
			probe.Status = "cancelled"
			return probe
		}
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(packet)
		if err != nil {
			if ctx.Err() != nil {
				probe.Status = "cancelled"
				return probe
			}
			if isPingTimeout(err) {
				probe.Status = "timeout"
				return probe
			}
			probe.Status = "error"
			probe.Error = err.Error()
			return probe
		}
		if n < header.ICMPv4MinimumSize {
			continue
		}
		icmp := header.ICMPv4(packet[:n])
		if icmp.Type() != header.ICMPv4EchoReply || icmp.Code() != 0 || icmp.Ident() != identifier || icmp.Sequence() != sequence {
			continue
		}
		probe.Status = "reply"
		probe.Bytes = n
		probe.RTTMillis = float64(time.Since(startedAt)) / float64(time.Millisecond)
		return probe
	}
}

func isPingTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func waitForNextPing(ctx context.Context, next time.Time) bool {
	delay := time.Until(next)
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func summarizePingResult(result *PingAdoptedIPAddressResult) {
	if result.Sent > 0 {
		result.LossPercent = float64(result.Sent-result.Received) * 100 / float64(result.Sent)
	}
	if result.Received == 0 {
		return
	}
	first := true
	var total float64
	for _, probe := range result.Probes {
		if probe.Status != "reply" {
			continue
		}
		if first || probe.RTTMillis < result.MinRTTMillis {
			result.MinRTTMillis = probe.RTTMillis
		}
		if first || probe.RTTMillis > result.MaxRTTMillis {
			result.MaxRTTMillis = probe.RTTMillis
		}
		first = false
		total += probe.RTTMillis
	}
	result.AvgRTTMillis = total / float64(result.Received)
}
