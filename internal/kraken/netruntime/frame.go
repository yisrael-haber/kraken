package netruntime

import (
	"net"

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

		sourceIP := net.IP(arp.ProtocolAddressSender()).To4()
		targetIP := net.IP(arp.ProtocolAddressTarget()).To4()
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
