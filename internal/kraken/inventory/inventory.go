package inventory

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	captureFlagLoopback                = 0x00000001
	captureFlagUp                      = 0x00000002
	captureFlagRunning                 = 0x00000004
	captureFlagWireless                = 0x00000008
	captureFlagConnectionStatus        = 0x00000030
	captureFlagConnectionStatusUnknown = 0x00000000
	captureFlagConnectionConnected     = 0x00000010
	captureFlagConnectionDisconnected  = 0x00000020
	captureFlagConnectionNotApplicable = 0x00000030
)

type InterfaceSnapshot struct {
	Interfaces     []NetworkInterface `json:"interfaces"`
	CaptureWarning string             `json:"captureWarning,omitempty"`
}

type NetworkInterface struct {
	Name              string             `json:"name"`
	Description       string             `json:"description,omitempty"`
	Index             int                `json:"index,omitempty"`
	MTU               int                `json:"mtu,omitempty"`
	HardwareAddr      string             `json:"hardwareAddr,omitempty"`
	OSFlags           []string           `json:"osFlags,omitempty"`
	CaptureFlags      []string           `json:"captureFlags,omitempty"`
	RawCaptureFlags   uint32             `json:"rawCaptureFlags,omitempty"`
	CaptureVisible    bool               `json:"captureVisible"`
	CaptureOnly       bool               `json:"captureOnly"`
	CanAdopt          bool               `json:"canAdopt"`
	AdoptionIssue     string             `json:"adoptionIssue,omitempty"`
	IsUp              bool               `json:"isUp"`
	IsRunning         bool               `json:"isRunning"`
	IsLoopback        bool               `json:"isLoopback"`
	IsPointToPoint    bool               `json:"isPointToPoint"`
	SupportsMulticast bool               `json:"supportsMulticast"`
	SystemAddresses   []InterfaceAddress `json:"systemAddresses,omitempty"`
	CaptureAddresses  []InterfaceAddress `json:"captureAddresses,omitempty"`
}

type InterfaceAddress struct {
	Family    string `json:"family"`
	Address   string `json:"address"`
	IP        string `json:"ip,omitempty"`
	Netmask   string `json:"netmask,omitempty"`
	Broadcast string `json:"broadcast,omitempty"`
	Peer      string `json:"peer,omitempty"`
}

type captureDevice struct {
	Description string
	Flags       uint32
	Addresses   []InterfaceAddress
}

func List() (InterfaceSnapshot, error) {
	snapshot := InterfaceSnapshot{}
	captureDevices, captureErr := loadCaptureDevices()
	if captureErr != nil {
		snapshot.CaptureWarning = captureErr.Error()
		captureDevices = map[string]captureDevice{}
	}

	systemInterfaces, err := net.Interfaces()
	if err != nil {
		return snapshot, err
	}

	seenCaptureDevices := make(map[string]struct{}, len(systemInterfaces))
	interfaces := make([]NetworkInterface, 0, len(systemInterfaces)+len(captureDevices))

	for _, systemInterface := range systemInterfaces {
		info := NetworkInterface{
			Name:              systemInterface.Name,
			Index:             systemInterface.Index,
			MTU:               systemInterface.MTU,
			HardwareAddr:      systemInterface.HardwareAddr.String(),
			OSFlags:           expandNetFlags(systemInterface.Flags),
			IsUp:              systemInterface.Flags&net.FlagUp != 0,
			IsRunning:         systemInterface.Flags&net.FlagRunning != 0,
			IsLoopback:        systemInterface.Flags&net.FlagLoopback != 0,
			IsPointToPoint:    systemInterface.Flags&net.FlagPointToPoint != 0,
			SupportsMulticast: systemInterface.Flags&net.FlagMulticast != 0,
		}

		if addresses, addrErr := interfaceAddresses(systemInterface); addrErr == nil {
			info.SystemAddresses = addresses
		}

		if captureDeviceName, device, ok := matchedCaptureDevice(systemInterface.Name, info.SystemAddresses, captureDevices); ok {
			info.Description = strings.TrimSpace(device.Description)
			info.CaptureFlags = expandCaptureFlags(device.Flags)
			info.RawCaptureFlags = device.Flags
			info.CaptureVisible = true
			info.CaptureAddresses = device.Addresses
			seenCaptureDevices[captureDeviceName] = struct{}{}
		}

		info.CanAdopt, info.AdoptionIssue = adoptionSupport(info)
		interfaces = append(interfaces, info)
	}

	for name, device := range captureDevices {
		if _, ok := seenCaptureDevices[name]; ok {
			continue
		}

		info := NetworkInterface{
			Name:             name,
			Description:      strings.TrimSpace(device.Description),
			CaptureFlags:     expandCaptureFlags(device.Flags),
			RawCaptureFlags:  device.Flags,
			CaptureVisible:   true,
			CaptureOnly:      true,
			CaptureAddresses: device.Addresses,
		}
		info.CanAdopt, info.AdoptionIssue = adoptionSupport(info)
		interfaces = append(interfaces, info)
	}

	sort.Slice(interfaces, func(i, j int) bool {
		return interfaceLess(interfaces[i], interfaces[j])
	})

	snapshot.Interfaces = interfaces

	return snapshot, nil
}

func adoptionSupport(item NetworkInterface) (bool, string) {
	switch {
	case item.CaptureOnly:
		return false, "capture-only device"
	case item.IsLoopback:
		return false, "loopback is not supported"
	case !item.CaptureVisible:
		return false, "no pcap device matched"
	default:
		return true, ""
	}
}

func interfaceAddresses(iface net.Interface) ([]InterfaceAddress, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	return addressInfosFromNet(addrs), nil
}

func addressInfosFromNet(addrs []net.Addr) []InterfaceAddress {
	items := make([]InterfaceAddress, 0, len(addrs))

	for _, addr := range addrs {
		switch value := addr.(type) {
		case *net.IPNet:
			ip := value.IP
			item := InterfaceAddress{
				Family:  ipFamily(ip),
				Address: value.String(),
				IP:      ip.String(),
				Netmask: maskString(value.Mask),
			}
			items = append(items, item)
		case *net.IPAddr:
			items = append(items, InterfaceAddress{
				Family:  ipFamily(value.IP),
				Address: value.String(),
				IP:      value.IP.String(),
			})
		default:
			items = append(items, InterfaceAddress{
				Address: addr.String(),
			})
		}
	}

	sortInterfaceAddresses(items)

	return items
}

func sortInterfaceAddresses(items []InterfaceAddress) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]

		if left.Family != right.Family {
			return left.Family < right.Family
		}

		return left.Address < right.Address
	})
}

func expandNetFlags(flags net.Flags) []string {
	var items []string

	if flags&net.FlagUp != 0 {
		items = append(items, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		items = append(items, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		items = append(items, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		items = append(items, "point-to-point")
	}
	if flags&net.FlagMulticast != 0 {
		items = append(items, "multicast")
	}
	if flags&net.FlagRunning != 0 {
		items = append(items, "running")
	}

	return items
}

func expandCaptureFlags(flags uint32) []string {
	var items []string

	if flags&captureFlagUp != 0 {
		items = append(items, "pcap-up")
	}
	if flags&captureFlagRunning != 0 {
		items = append(items, "pcap-running")
	}
	if flags&captureFlagLoopback != 0 {
		items = append(items, "pcap-loopback")
	}
	if flags&captureFlagWireless != 0 {
		items = append(items, "wireless")
	}

	switch flags & captureFlagConnectionStatus {
	case captureFlagConnectionConnected:
		items = append(items, "connected")
	case captureFlagConnectionDisconnected:
		items = append(items, "disconnected")
	case captureFlagConnectionNotApplicable:
		items = append(items, "connection-n/a")
	case captureFlagConnectionStatusUnknown:
		items = append(items, "connection-unknown")
	}

	return items
}

func ipFamily(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "IPv4"
	}

	return "IPv6"
}

func maskString(mask net.IPMask) string {
	if len(mask) == 0 {
		return ""
	}

	return net.IP(mask).String()
}

func buildDisplayAddress(ip net.IP, mask net.IPMask) string {
	if ip == nil {
		return ""
	}

	if ones, bits := mask.Size(); bits > 0 {
		return fmt.Sprintf("%s/%d", ip.String(), ones)
	}

	return ip.String()
}

func interfaceLess(left, right NetworkInterface) bool {
	leftHasAddresses := len(left.SystemAddresses) > 0 || len(left.CaptureAddresses) > 0
	rightHasAddresses := len(right.SystemAddresses) > 0 || len(right.CaptureAddresses) > 0
	leftVirtual := isLikelyVirtualInterface(left)
	rightVirtual := isLikelyVirtualInterface(right)

	switch {
	case left.IsUp != right.IsUp:
		return left.IsUp
	case left.IsRunning != right.IsRunning:
		return left.IsRunning
	case left.CaptureOnly != right.CaptureOnly:
		return !left.CaptureOnly
	case left.IsLoopback != right.IsLoopback:
		return !left.IsLoopback
	case leftVirtual != rightVirtual:
		return !leftVirtual
	case leftHasAddresses != rightHasAddresses:
		return leftHasAddresses
	case left.CaptureVisible != right.CaptureVisible:
		return left.CaptureVisible
	default:
		return left.Name < right.Name
	}
}

func isLikelyVirtualInterface(item NetworkInterface) bool {
	name := strings.ToLower(item.Name)
	description := strings.ToLower(item.Description)

	if item.IsPointToPoint {
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
