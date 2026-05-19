package netruntime

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	adoptedNetstackNICID = tcpip.NICID(1)
)

func buildNetstackRoutes(ip net.IP, subnetMask net.IPMask, defaultGateway net.IP) []tcpip.Route {
	items := make([]tcpip.Route, 0, 2)
	if subnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4Slice(ip.Mask(subnetMask)),
		tcpip.MaskFromBytes(subnetMask),
	); err == nil {
		items = append(items, tcpip.Route{
			Destination: subnet,
			NIC:         adoptedNetstackNICID,
		})
	}

	gateway := defaultGateway.To4()
	if gateway != nil {
		items = append(items, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			Gateway:     tcpip.AddrFrom4Slice(gateway),
			NIC:         adoptedNetstackNICID,
		})
	} else {
		items = append(items, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         adoptedNetstackNICID,
		})
	}

	return items
}
