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
	Name string `json:"name"`
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
		name, ok := systemInterfaceForDevice(device)
		if !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		options = append(options, InterfaceOption{Name: name})
	}

	sort.Slice(options, func(i, j int) bool {
		return options[i].Name < options[j].Name
	})

	return Selection{Options: options}, nil
}

func systemInterfaceForDevice(device pcap.Interface) (string, bool) {
	if name, ok := systemInterfaceName(device.Name); ok {
		return name, true
	}
	return systemInterfaceName(device.Description)
}

func systemInterfaceName(name string) (string, bool) {
	iface, err := interfaceByName(strings.TrimSpace(name))
	if err == nil && iface.Flags&net.FlagLoopback == 0 {
		return iface.Name, true
	}
	return "", false
}
