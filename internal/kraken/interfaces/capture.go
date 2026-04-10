package interfaces

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/gopacket/pcap"
)

func loadCaptureDevices() (map[string]captureDevice, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcap enumeration failed: %w", err)
	}

	items := make(map[string]captureDevice, len(devices))
	for _, device := range devices {
		name := strings.TrimSpace(device.Name)
		if name == "" {
			continue
		}

		description := strings.TrimSpace(device.Description)
		items[name] = captureDevice{
			Description:           description,
			matchAddressIPs:       captureAddressIPs(device.Addresses),
			normalizedDescription: normalizeCaptureMatchText(description),
		}
	}

	return items, nil
}

func CaptureDeviceNameForInterface(iface net.Interface) (string, error) {
	captureDevices, err := loadCaptureDevices()
	if err != nil {
		return "", fmt.Errorf("pcap device enumeration failed: %w", err)
	}

	if _, ok := captureDevices[iface.Name]; ok {
		return iface.Name, nil
	}

	addresses, err := interfaceIPs(iface)
	if err != nil {
		return "", fmt.Errorf("read interface addresses for %s: %w", iface.Name, err)
	}

	if captureDeviceName, _, ok := matchedCaptureDevice(iface.Name, addresses, captureDevices); ok {
		return captureDeviceName, nil
	}

	return "", fmt.Errorf("no pcap device matched interface %q", iface.Name)
}

func captureAddressIPs(addrs []pcap.InterfaceAddress) []string {
	items := make([]string, 0, len(addrs))

	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}

		text := strings.TrimSpace(addr.IP.String())
		if text == "" {
			continue
		}

		items = append(items, text)
	}

	sort.Strings(items)
	return compactStrings(items)
}

func matchedCaptureDevice(interfaceName string, systemAddresses []string, devices map[string]captureDevice) (string, captureDevice, bool) {
	if device, ok := devices[interfaceName]; ok {
		return interfaceName, device, true
	}

	if len(systemAddresses) != 0 {
		for deviceName, device := range devices {
			if len(device.matchAddressIPs) == 0 {
				continue
			}
			if sharesCaptureAddress(systemAddresses, device.matchAddressIPs) {
				return deviceName, device, true
			}
		}
	}

	normalizedInterfaceName := normalizeCaptureMatchText(interfaceName)
	if normalizedInterfaceName == "" {
		return "", captureDevice{}, false
	}

	for deviceName, device := range devices {
		normalizedDescription := normalizedMatchDescription(device)
		if normalizedDescription == "" {
			continue
		}
		if normalizedDescription == normalizedInterfaceName ||
			strings.Contains(normalizedDescription, normalizedInterfaceName) ||
			strings.Contains(normalizedInterfaceName, normalizedDescription) {
			return deviceName, device, true
		}
	}

	return "", captureDevice{}, false
}

func normalizedMatchDescription(device captureDevice) string {
	if device.normalizedDescription != "" {
		return device.normalizedDescription
	}

	return normalizeCaptureMatchText(device.Description)
}

func sharesCaptureAddress(left, right []string) bool {
	leftIndex := 0
	rightIndex := 0

	for leftIndex < len(left) && rightIndex < len(right) {
		switch {
		case left[leftIndex] == right[rightIndex]:
			return true
		case left[leftIndex] < right[rightIndex]:
			leftIndex++
		default:
			rightIndex++
		}
	}

	return false
}

func normalizeCaptureMatchText(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(value))

	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}

	return builder.String()
}
