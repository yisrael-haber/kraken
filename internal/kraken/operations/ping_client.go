package operations

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	defaultPingIntervalMillis = 1000
	defaultPingTimeoutMillis  = 1000
	defaultPingCount          = 4
	maxPingCount              = 1000
	maxPingPayload            = 65507
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
	PingAdoptedIPAddressRequest
	Sent         int         `json:"sent"`
	Received     int         `json:"received"`
	LossPercent  float64     `json:"lossPercent"`
	MinRTTMillis float64     `json:"minRttMillis,omitempty"`
	AvgRTTMillis float64     `json:"avgRttMillis,omitempty"`
	MaxRTTMillis float64     `json:"maxRttMillis,omitempty"`
	Probes       []PingProbe `json:"probes,omitempty"`
}

type PingProbe struct {
	Sequence  int     `json:"sequence"`
	Status    string  `json:"status"`
	RTTMillis float64 `json:"rttMillis,omitempty"`
	Bytes     int     `json:"bytes,omitempty"`
	Error     string  `json:"error,omitempty"`
}

type PingDialer func(net.IP) (net.Conn, error)

func PingWithDialer(request PingAdoptedIPAddressRequest, dial PingDialer) (result PingAdoptedIPAddressResult, err error) {
	destination, err := normalizePingRequest(&request)
	result.PingAdoptedIPAddressRequest = request
	if err != nil {
		return result, err
	}

	conn, err := dial(destination)
	if err != nil {
		return result, err
	}
	defer func() {
		err = errors.Join(err, conn.Close())
	}()

	result.Probes = make([]PingProbe, 0, result.Count)
	requestPacket := make([]byte, header.ICMPv4MinimumSize+result.PayloadSize)
	requestICMP := header.ICMPv4(requestPacket)
	requestICMP.SetType(header.ICMPv4Echo)
	replyPacket := make([]byte, len(requestPacket))
	interval := time.Duration(result.IntervalMillis) * time.Millisecond
	timeout := time.Duration(result.TimeoutMillis) * time.Millisecond
	var totalRTT float64
	for sequence := 1; sequence <= result.Count; sequence++ {
		startedAt := time.Now()
		probe := PingProbe{Sequence: sequence}
		result.Sent++
		requestICMP.SetSequence(uint16(sequence))
		if err := conn.SetDeadline(startedAt.Add(timeout)); err != nil {
			return result, err
		}
		if _, err := conn.Write(requestPacket); err != nil {
			probe.Status = "error"
			probe.Error = err.Error()
		} else {
			probe = readPingReply(conn, replyPacket, uint16(sequence), startedAt)
			if probe.Status == "reply" {
				result.Received++
				totalRTT += probe.RTTMillis
				if result.Received == 1 || probe.RTTMillis < result.MinRTTMillis {
					result.MinRTTMillis = probe.RTTMillis
				}
				if probe.RTTMillis > result.MaxRTTMillis {
					result.MaxRTTMillis = probe.RTTMillis
				}
			}
		}
		result.Probes = append(result.Probes, probe)

		if sequence < result.Count {
			time.Sleep(time.Until(startedAt.Add(interval)))
		}
	}

	result.LossPercent = float64(result.Sent-result.Received) * 100 / float64(result.Sent)
	if result.Received != 0 {
		result.AvgRTTMillis = totalRTT / float64(result.Received)
	}
	return result, nil
}

func normalizePingRequest(request *PingAdoptedIPAddressRequest) (net.IP, error) {
	request.SourceIP = strings.TrimSpace(request.SourceIP)
	request.Destination = strings.TrimSpace(request.Destination)
	destination := net.ParseIP(request.Destination).To4()
	if destination == nil {
		return nil, fmt.Errorf("destination must be a valid IPv4 address")
	}
	if request.IntervalMillis == 0 {
		request.IntervalMillis = defaultPingIntervalMillis
	}
	if request.IntervalMillis < 1 {
		return nil, fmt.Errorf("interval must be a positive integer in milliseconds")
	}
	if request.TimeoutMillis == 0 {
		request.TimeoutMillis = defaultPingTimeoutMillis
	}
	if request.TimeoutMillis < 1 {
		return nil, fmt.Errorf("timeout must be a positive integer in milliseconds")
	}
	if request.Count == 0 {
		request.Count = defaultPingCount
	}
	if request.Count < 1 || request.Count > maxPingCount {
		return nil, fmt.Errorf("count must be between 1 and %d", maxPingCount)
	}
	if request.PayloadSize < 0 || request.PayloadSize > maxPingPayload {
		return nil, fmt.Errorf("payload size must be between 0 and %d bytes", maxPingPayload)
	}
	return destination, nil
}

func readPingReply(conn net.Conn, packet []byte, sequence uint16, startedAt time.Time) PingProbe {
	probe := PingProbe{Sequence: int(sequence)}
	for {
		n, err := conn.Read(packet)
		if err != nil {
			if isPingTimeout(err) {
				probe.Status = "timeout"
				return probe
			}
			probe.Status = "error"
			probe.Error = err.Error()
			return probe
		}
		icmp := header.ICMPv4(packet[:n])
		if icmp.Code() != 0 || icmp.Sequence() != sequence {
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
