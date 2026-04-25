package interfaces

import (
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

type selectionCandidate struct {
	option         InterfaceOption
	description    string
	captureVisible bool
	captureOnly    bool
	isUp           bool
	isRunning      bool
	isLoopback     bool
	isPointToPoint bool
	hasAddresses   bool
}

func List() (Selection, error) {
	selection := Selection{}
	captureDevices, captureErr := loadCaptureDevices()
	if captureErr != nil {
		selection.Warning = captureErr.Error()
		captureDevices = map[string]pcap.Interface{}
	}

	systemInterfaces, err := net.Interfaces()
	if err != nil {
		return selection, err
	}

	seenCaptureDevices := make(map[string]struct{}, len(systemInterfaces))
	candidates := make([]selectionCandidate, 0, len(systemInterfaces)+len(captureDevices))

	for _, systemInterface := range systemInterfaces {
		systemIPs, addrErr := interfaceIPs(systemInterface)
		if addrErr != nil {
			systemIPs = nil
		}

		candidate := selectionCandidate{
			option: InterfaceOption{
				Name: systemInterface.Name,
			},
			isUp:           systemInterface.Flags&net.FlagUp != 0,
			isRunning:      systemInterface.Flags&net.FlagRunning != 0,
			isLoopback:     systemInterface.Flags&net.FlagLoopback != 0,
			isPointToPoint: systemInterface.Flags&net.FlagPointToPoint != 0,
			hasAddresses:   len(systemIPs) != 0,
		}

		if captureDeviceName, device, ok := matchedCaptureDevice(systemInterface.Name, systemIPs, captureDevices); ok {
			candidate.description = strings.TrimSpace(device.Description)
			candidate.captureVisible = true
			candidate.hasAddresses = candidate.hasAddresses || len(captureAddressIPs(device.Addresses)) != 0
			seenCaptureDevices[captureDeviceName] = struct{}{}
		}

		candidate.option.CanAdopt = supportsAdoption(candidate)
		candidates = append(candidates, candidate)
	}

	for name, device := range captureDevices {
		if _, ok := seenCaptureDevices[name]; ok {
			continue
		}

		candidate := selectionCandidate{
			option: InterfaceOption{
				Name: name,
			},
			description:    strings.TrimSpace(device.Description),
			captureVisible: true,
			captureOnly:    true,
			hasAddresses:   len(captureAddressIPs(device.Addresses)) != 0,
		}
		candidate.option.CanAdopt = supportsAdoption(candidate)
		candidates = append(candidates, candidate)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidateLess(candidates[i], candidates[j])
	})

	selection.Options = make([]InterfaceOption, len(candidates))
	for i, candidate := range candidates {
		selection.Options[i] = candidate.option
	}

	return selection, nil
}

func supportsAdoption(candidate selectionCandidate) bool {
	return !candidate.captureOnly && !candidate.isLoopback && candidate.captureVisible
}

func interfaceIPs(iface net.Interface) ([]string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	return addressIPsFromNet(addrs), nil
}

func addressIPsFromNet(addrs []net.Addr) []string {
	items := make([]string, 0, len(addrs))

	for _, addr := range addrs {
		switch value := addr.(type) {
		case *net.IPNet:
			items = appendIP(items, value.IP)
		case *net.IPAddr:
			items = appendIP(items, value.IP)
		}
	}

	sort.Strings(items)
	return compactStrings(items)
}

func appendIP(items []string, ip net.IP) []string {
	if ip == nil {
		return items
	}

	text := strings.TrimSpace(ip.String())
	if text == "" {
		return items
	}

	return append(items, text)
}

func compactStrings(items []string) []string {
	if len(items) < 2 {
		return items
	}

	compacted := items[:1]
	for _, item := range items[1:] {
		if item != compacted[len(compacted)-1] {
			compacted = append(compacted, item)
		}
	}

	return compacted
}

func candidateLess(left, right selectionCandidate) bool {
	leftVirtual := isLikelyVirtualInterface(left)
	rightVirtual := isLikelyVirtualInterface(right)

	switch {
	case left.isUp != right.isUp:
		return left.isUp
	case left.isRunning != right.isRunning:
		return left.isRunning
	case left.captureOnly != right.captureOnly:
		return !left.captureOnly
	case left.isLoopback != right.isLoopback:
		return !left.isLoopback
	case leftVirtual != rightVirtual:
		return !leftVirtual
	case left.hasAddresses != right.hasAddresses:
		return left.hasAddresses
	case left.captureVisible != right.captureVisible:
		return left.captureVisible
	default:
		return left.option.Name < right.option.Name
	}
}

func isLikelyVirtualInterface(candidate selectionCandidate) bool {
	name := strings.ToLower(candidate.option.Name)
	description := strings.ToLower(candidate.description)

	if candidate.isPointToPoint {
		return true
	}

	virtualHints := []string{
		"br-",
		"bridge",
		"cali",
		"cni",
		"docker",
		"dummy",
		"flannel",
		"hyper-v",
		"ifb",
		"lxc",
		"lxd",
		"macvlan",
		"macvtap",
		"podman",
		"tailscale",
		"tap",
		"tun",
		"vbox",
		"veth",
		"vethernet",
		"virbr",
		"virtual",
		"vmnet",
		"vxlan",
		"wg",
		"zerotier",
		"zt",
	}

	for _, hint := range virtualHints {
		if strings.Contains(name, hint) || strings.Contains(description, hint) {
			return true
		}
	}

	return false
}
