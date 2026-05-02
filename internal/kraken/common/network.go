package common

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

var labelRegex = regexp.MustCompile(`^\s*([a-zA-Z0-9_.-][a-zA-Z0-9 _.-]*?)\s*$`)

func NormalizeAdoptionLabel(value string) (string, error) {
	match := labelRegex.FindStringSubmatch(value)
	if match == nil {
		return "", fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}
	return match[1], nil
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
