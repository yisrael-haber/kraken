package interfaces

import (
	"fmt"
	"net"
	"sort"

	"github.com/google/gopacket/pcap"
)

type Selection struct {
	Options []string `json:"options"`
	Warning string   `json:"warning,omitempty"`
}

func List() Selection {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return Selection{Warning: fmt.Sprintf("pcap enumeration failed: %v", err)}
	}

	options := make([]string, 0, len(devices))
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		name, ok := systemInterfaceForDevice(device)
		if !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		options = append(options, name)
	}

	sort.Strings(options)

	return Selection{Options: options}
}

func systemInterfaceForDevice(device pcap.Interface) (string, bool) {
	if name, ok := systemInterfaceName(device.Name); ok {
		return name, true
	}
	return systemInterfaceName(device.Description)
}

func systemInterfaceName(name string) (string, bool) {
	iface, err := net.InterfaceByName(name)
	if err == nil && iface.Flags&net.FlagLoopback == 0 {
		return iface.Name, true
	}
	return "", false
}
