package netruntime

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	adoptedNetstackNICID      = tcpip.NICID(1)
	adoptedNetstackDefaultMTU = 1500
)

func adoptedNetstackMTU(override uint32) uint32 {
	if override >= 68 {
		return override
	}
	if override != 0 {
		return 68
	}
	return adoptedNetstackDefaultMTU
}

func buildNetstackRoutes(routes []net.IPNet, defaultGateway net.IP) []tcpip.Route {
	items := make([]tcpip.Route, 0, len(routes)+1)
	for _, route := range routes {
		ip := route.IP.To4()
		if ip == nil || len(route.Mask) != net.IPv4len {
			continue
		}
		subnet, err := tcpip.NewSubnet(
			tcpip.AddrFrom4Slice(ip.Mask(route.Mask)),
			tcpip.MaskFromBytes(route.Mask),
		)
		if err != nil {
			continue
		}
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
	} else if len(items) == 0 {
		items = append(items, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         adoptedNetstackNICID,
		})
	}

	return items
}
