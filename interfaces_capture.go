package main

import (
	"fmt"
	"net"
	"slices"
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

		items[name] = captureDevice{
			Description: strings.TrimSpace(device.Description),
			Flags:       device.Flags,
			Addresses:   addressInfosFromPcap(device.Addresses),
		}
	}

	return items, nil
}

func pcapDeviceNameForInterface(iface net.Interface) (string, error) {
	captureDevices, err := loadCaptureDevices()
	if err != nil {
		return "", fmt.Errorf("pcap device enumeration failed: %w", err)
	}

	addresses, err := interfaceAddresses(iface)
	if err != nil {
		return "", fmt.Errorf("read interface addresses for %s: %w", iface.Name, err)
	}

	if captureDeviceName, _, ok := matchedCaptureDevice(iface.Name, addresses, captureDevices); ok {
		return captureDeviceName, nil
	}

	return "", fmt.Errorf("no pcap device matched interface %q", iface.Name)
}

func addressInfosFromPcap(addrs []pcap.InterfaceAddress) []InterfaceAddress {
	items := make([]InterfaceAddress, 0, len(addrs))

	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}

		items = append(items, InterfaceAddress{
			Family:    ipFamily(addr.IP),
			Address:   buildDisplayAddress(addr.IP, addr.Netmask),
			IP:        addr.IP.String(),
			Netmask:   maskString(addr.Netmask),
			Broadcast: ipString(addr.Broadaddr),
			Peer:      ipString(addr.P2P),
		})
	}

	sortInterfaceAddresses(items)

	return items
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}

	return ip.String()
}

func matchedCaptureDevice(interfaceName string, systemAddresses []InterfaceAddress, devices map[string]captureDevice) (string, captureDevice, bool) {
	if device, ok := devices[interfaceName]; ok {
		return interfaceName, device, true
	}

	systemIPs := captureAddressIPs(systemAddresses)
	if len(systemIPs) != 0 {
		for deviceName, device := range devices {
			deviceIPs := captureAddressIPs(device.Addresses)
			if len(deviceIPs) == 0 {
				continue
			}
			if sharesCaptureAddress(systemIPs, deviceIPs) {
				return deviceName, device, true
			}
		}
	}

	normalizedInterfaceName := normalizeCaptureMatchText(interfaceName)
	if normalizedInterfaceName == "" {
		return "", captureDevice{}, false
	}

	for deviceName, device := range devices {
		normalizedDescription := normalizeCaptureMatchText(device.Description)
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

func captureAddressIPs(addresses []InterfaceAddress) []string {
	items := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if strings.TrimSpace(address.IP) == "" {
			continue
		}
		items = append(items, address.IP)
	}

	slices.Sort(items)
	return slices.Compact(items)
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
