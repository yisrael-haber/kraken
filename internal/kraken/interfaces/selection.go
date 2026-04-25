package interfaces

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/gopacket/pcap"
)

type Selection struct {
	Options []InterfaceOption `json:"options"`
	Warning string            `json:"warning,omitempty"`
}

type InterfaceOption struct {
	Name     string `json:"name"`
	CanAdopt bool   `json:"canAdopt"`
}

var findAllDevs = pcap.FindAllDevs
var interfaceByName = net.InterfaceByName

func List() (Selection, error) {
	devices, err := findAllDevs()
	if err != nil {
		return Selection{Warning: fmt.Sprintf("pcap enumeration failed: %v", err)}, nil
	}

	options := make([]InterfaceOption, 0, len(devices))
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		name := interfaceOptionName(device)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		_, canAdopt := systemInterfaceForDevice(device)
		options = append(options, InterfaceOption{Name: name, CanAdopt: canAdopt})
	}

	sort.Slice(options, func(i, j int) bool {
		if options[i].CanAdopt != options[j].CanAdopt {
			return options[i].CanAdopt
		}
		return options[i].Name < options[j].Name
	})

	return Selection{Options: options}, nil
}

func CaptureDeviceNameForInterface(iface net.Interface) (string, error) {
	devices, err := findAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap device enumeration failed: %w", err)
	}

	if device, ok := captureDeviceForInterface(iface, devices); ok {
		return device.Name, nil
	}

	return "", fmt.Errorf("no pcap device matched interface %q", iface.Name)
}

func captureDeviceForInterface(iface net.Interface, devices []pcap.Interface) (pcap.Interface, bool) {
	for _, device := range devices {
		if strings.TrimSpace(device.Name) == iface.Name {
			return device, true
		}
	}
	for _, device := range devices {
		if systemName, ok := systemInterfaceForDevice(device); ok && systemName == iface.Name {
			return device, true
		}
	}

	addresses := interfaceAddresses(iface)
	if len(addresses) == 0 {
		return pcap.Interface{}, false
	}
	for _, device := range devices {
		if deviceSharesAddress(device, addresses) {
			return device, true
		}
	}

	return pcap.Interface{}, false
}

func interfaceOptionName(device pcap.Interface) string {
	if name, ok := systemInterfaceForDevice(device); ok {
		return name
	}
	return strings.TrimSpace(device.Name)
}

func systemInterfaceForDevice(device pcap.Interface) (string, bool) {
	for _, name := range []string{device.Name, device.Description} {
		iface, err := net.InterfaceByName(strings.TrimSpace(name))
		if err == nil && iface.Flags&net.FlagLoopback == 0 {
			return iface.Name, true
		}
	}
	return "", false
}

func interfaceAddresses(iface net.Interface) []net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		switch value := addr.(type) {
		case *net.IPNet:
			ips = append(ips, value.IP)
		case *net.IPAddr:
			ips = append(ips, value.IP)
		}
	}
	return ips
}

func deviceSharesAddress(device pcap.Interface, ips []net.IP) bool {
	for _, address := range device.Addresses {
		for _, ip := range ips {
			if address.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
