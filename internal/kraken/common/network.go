package common

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

func NormalizeAdoptionLabel(value string) (string, error) {
	label := strings.TrimSpace(value)
	if label == "" {
		return "", fmt.Errorf("label is required")
	}

	for _, char := range label {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == ' ' || char == '-' || char == '_' || char == '.':
		default:
			return "", fmt.Errorf("label may only contain letters, numbers, spaces, dots, underscores, and hyphens")
		}
	}

	if strings.HasSuffix(label, ".") || strings.HasSuffix(label, " ") {
		return "", fmt.Errorf("label may not end with a dot or space")
	}

	return label, nil
}

func NormalizeAdoptionIP(value string) (net.IP, error) {
	ip := NormalizeIPv4(net.ParseIP(strings.TrimSpace(value)))
	if ip == nil {
		return nil, fmt.Errorf("a valid IPv4 address is required")
	}

	return ip, nil
}

func NormalizeDefaultGateway(value string, adoptedIP net.IP) (net.IP, error) {
	gateway, err := normalizeOptionalAdoptionIP(value)
	if err != nil {
		return nil, fmt.Errorf("defaultGateway: %w", err)
	}
	if gateway == nil {
		return nil, nil
	}
	if gateway.Equal(net.IPv4zero) {
		return nil, fmt.Errorf("defaultGateway must not be 0.0.0.0")
	}
	if NormalizeIPv4(adoptedIP) != nil && gateway.Equal(adoptedIP) {
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

func normalizeOptionalAdoptionIP(value string) (net.IP, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}

	return NormalizeAdoptionIP(trimmed)
}
