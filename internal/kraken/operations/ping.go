package operations

import (
	"fmt"
	"net"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
)

type PingAdoptedIPAddressRequest struct {
	SourceIP   string `json:"sourceIP"`
	TargetIP   string `json:"targetIP"`
	Count      int    `json:"count,omitempty"`
	PayloadHex string `json:"payloadHex,omitempty"`
}

type PingAdoptedIPAddressReply struct {
	Sequence  int     `json:"sequence"`
	Success   bool    `json:"success"`
	RTTMillis float64 `json:"rttMillis,omitempty"`
}

type PingAdoptedIPAddressResult struct {
	SourceIP string                      `json:"sourceIP"`
	TargetIP string                      `json:"targetIP"`
	Sent     int                         `json:"sent"`
	Received int                         `json:"received"`
	Replies  []PingAdoptedIPAddressReply `json:"replies"`
}

func Ping(source *adoption.Identity, targetIP net.IP, count int, payload []byte) (PingAdoptedIPAddressResult, error) {
	targetIP = targetIP.To4()
	if targetIP == nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("a valid IPv4 target is required")
	}
	if count <= 0 {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("ping count must be positive")
	}
	if source == nil || source.IP.To4() == nil {
		return PingAdoptedIPAddressResult{}, fmt.Errorf("a valid IPv4 source is required")
	}

	result := PingAdoptedIPAddressResult{
		SourceIP: source.IP.String(),
		TargetIP: targetIP.String(),
		Replies:  make([]PingAdoptedIPAddressReply, 0, count),
	}
	_ = payload
	return result, fmt.Errorf("ICMP ping is not implemented")
}
