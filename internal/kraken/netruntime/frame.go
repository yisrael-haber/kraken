package netruntime

import (
	"fmt"
	"net"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type InboundFrameInfo struct {
	SourceIP  net.IP
	TargetIP  net.IP
	SourceMAC net.HardwareAddr
}

func IsMinimumEthernetFrame(frame []byte) bool {
	return len(frame) >= header.EthernetMinimumSize
}

func IsIPv4Frame(frame []byte) bool {
	return IsMinimumEthernetFrame(frame) && header.Ethernet(frame).Type() == header.IPv4ProtocolNumber
}

func IsBroadcastEthernetFrame(frame []byte) bool {
	return IsMinimumEthernetFrame(frame) && header.Ethernet(frame).DestinationAddress() == header.EthernetBroadcastAddress
}

func ClassifyInboundFrame(frame []byte) (InboundFrameInfo, bool) {
	if !IsMinimumEthernetFrame(frame) {
		return InboundFrameInfo{}, false
	}

	ethernet := header.Ethernet(frame)
	payload := frame[header.EthernetMinimumSize:]

	switch ethernet.Type() {
	case header.ARPProtocolNumber:
		if len(payload) < header.ARPSize {
			return InboundFrameInfo{}, false
		}
		arp := header.ARP(payload)
		if !arp.IsValid() {
			return InboundFrameInfo{}, false
		}

		sourceIP := common.NormalizeIPv4(arp.ProtocolAddressSender())
		targetIP := common.NormalizeIPv4(arp.ProtocolAddressTarget())
		if sourceIP == nil || targetIP == nil {
			return InboundFrameInfo{}, false
		}
		info := InboundFrameInfo{
			SourceIP:  sourceIP,
			TargetIP:  targetIP,
			SourceMAC: arp.HardwareAddressSender(),
		}
		return info, len(info.SourceMAC) != 0

	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(payload)
		if !ipv4.IsValid(len(payload)) {
			return InboundFrameInfo{}, false
		}

		sourceAddr := ipv4.SourceAddress().As4()
		targetAddr := ipv4.DestinationAddress().As4()
		info := InboundFrameInfo{
			SourceIP:  sourceAddr[:],
			TargetIP:  targetAddr[:],
			SourceMAC: frame[6:12],
		}
		return info, len(info.SourceMAC) != 0
	}

	return InboundFrameInfo{}, false
}

func RoutedIPv4Destination(frame []byte) (net.IP, error) {
	_, destinationIP, err := routedIPv4Header(frame)
	return destinationIP, err
}

func RouteNextHop(routes []net.IPNet, defaultGateway, destinationIP net.IP) (net.IP, error) {
	destinationIP = common.NormalizeIPv4(destinationIP)
	if destinationIP == nil {
		return nil, fmt.Errorf("a routed IPv4 destination is required")
	}

	for _, route := range routes {
		if route.Contains(destinationIP) {
			return common.CloneIPv4(destinationIP), nil
		}
	}

	defaultGateway = common.NormalizeIPv4(defaultGateway)
	if defaultGateway == nil {
		return nil, fmt.Errorf("no next hop is available for %s", destinationIP.String())
	}

	return defaultGateway, nil
}

func RewriteForwardedIPv4Frame(frame []byte, sourceMAC, destinationMAC net.HardwareAddr) error {
	ipv4Header, _, err := routedIPv4Header(frame)
	if err != nil {
		return err
	}
	if len(sourceMAC) == 0 || len(destinationMAC) == 0 {
		return fmt.Errorf("forwarded frame requires source and destination MAC addresses")
	}

	if ipv4Header.TTL() <= 1 {
		return fmt.Errorf("forwarded frame TTL expired")
	}

	copy(frame[:6], destinationMAC)
	copy(frame[6:12], sourceMAC)
	ipv4Header.SetTTL(ipv4Header.TTL() - 1)
	ipv4Header.SetChecksum(0)
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())
	return nil
}

func routedIPv4Header(frame []byte) (header.IPv4, net.IP, error) {
	if len(frame) < header.EthernetMinimumSize {
		return nil, nil, fmt.Errorf("routed frame is too short")
	}

	eth := header.Ethernet(frame)
	if eth.Type() != header.IPv4ProtocolNumber {
		return nil, nil, fmt.Errorf("routing requires an IPv4 frame")
	}

	payload := frame[header.EthernetMinimumSize:]
	ipv4Header := header.IPv4(payload)
	if !ipv4Header.IsValid(len(payload)) {
		return nil, nil, fmt.Errorf("routed frame contains an invalid IPv4 packet")
	}

	destinationAddr := ipv4Header.DestinationAddress().As4()
	destinationIP := net.IPv4(destinationAddr[0], destinationAddr[1], destinationAddr[2], destinationAddr[3]).To4()
	return ipv4Header, destinationIP, nil
}
