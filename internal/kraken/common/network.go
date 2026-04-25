package common

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

var labelRegex = regexp.MustCompile(`^[a-zA-Z0-9 _.-]+$`)

func NormalizeAdoptionLabel(value string) (string, error) {
	label := strings.TrimSpace(value)
	if label == "" {
		return "", fmt.Errorf("label is required")
	}

	if !labelRegex.MatchString(label) {
		return "", fmt.Errorf("label may only contain letters, numbers, spaces, dots, underscores, and hyphens")
	}

	return label, nil
}

func NormalizeAdoptionIP(value string) (net.IP, error) {
	return parseIPv4Text(strings.TrimSpace(value))
}

func parseIPv4Text(value string) (net.IP, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("a valid IPv4 address is required")
	}
	return net.IP(addr.AsSlice()), nil
}

func NormalizeDefaultGateway(value string, adoptedIP net.IP) (net.IP, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	gateway, err := parseIPv4Text(value)
	if err != nil {
		return nil, fmt.Errorf("defaultGateway: %w", err)
	}

	if gateway.Equal(net.IPv4zero) {
		return nil, fmt.Errorf("defaultGateway must not be 0.0.0.0")
	}
	if gateway.Equal(adoptedIP) {
		return nil, fmt.Errorf("defaultGateway must differ from IP")
	}

	return gateway, nil
}

func NormalizeIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	if ip = ip.To4(); ip == nil {
		return nil
	}

	return ip
}

func CloneIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	return slices.Clone(ip.To4())
}

func CloneHardwareAddr(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) == 0 {
		return nil
	}

	return slices.Clone(mac)
}

func IPString(ip net.IP) string {
	if ip == nil {
		return ""
	}

	return ip.String()
}
