package operations

import "net"

func engineKey(ip net.IP) string {
	normalized := ip.To4()
	if normalized == nil {
		return ""
	}
	return normalized.String()
}
