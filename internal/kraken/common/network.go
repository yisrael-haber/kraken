package common

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

var labelRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]([a-zA-Z0-9 _.-]*[a-zA-Z0-9_.-])?$`)

func ValidLabel(value string) bool {
	return labelRegex.MatchString(value)
}

func NormalizeAdoptionIP(value string) (net.IP, error) {
	if addr, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil && addr.Is4() {
		return net.IP(addr.AsSlice()), nil
	}
	return nil, fmt.Errorf("a valid IPv4 address is required")
}

func NormalizeDefaultGateway(value string, adoptedIP net.IP) (net.IP, error) {
	if value = strings.TrimSpace(value); value == "" {
		return nil, nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("a valid IPv4 address is required")
	}
	gateway := net.IP(addr.AsSlice())
	if gateway.Equal(net.IPv4zero) || gateway.Equal(adoptedIP) {
		return nil, fmt.Errorf("defaultGateway must be a valid IPv4 address different from IP and 0.0.0.0")
	}
	return gateway, nil
}

func NormalizeSubnetPrefix(prefix int) (int, error) {
	if prefix == 0 {
		return 24, nil
	}
	if prefix < 1 || prefix > 32 {
		return 0, fmt.Errorf("subnetPrefix must be between 1 and 32")
	}
	return prefix, nil
}
