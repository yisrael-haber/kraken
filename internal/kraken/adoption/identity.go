package adoption

import (
	"fmt"
	"net"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type entry struct {
	label                 string
	ip                    net.IP
	iface                 net.Interface
	mac                   net.HardwareAddr
	defaultGateway        net.IP
	mtu                   uint32
	transportScriptName   string
	applicationScriptName string
}

func ResolveInterface(name string) (net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return net.Interface{}, fmt.Errorf("interface %q not found: %w", name, err)
	}

	if iface.Flags&net.FlagLoopback != 0 {
		return net.Interface{}, fmt.Errorf("interface %q is loopback and cannot be used for ARP adoption", name)
	}

	return *iface, nil
}

func ResolveMAC(iface net.Interface, macText string) (net.HardwareAddr, error) {
	if strings.TrimSpace(macText) != "" {
		mac, err := net.ParseMAC(strings.TrimSpace(macText))
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address %q: %w", macText, err)
		}
		return mac, nil
	}

	if len(iface.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface %q does not expose a hardware address; MAC must be provided explicitly", iface.Name)
	}

	return iface.HardwareAddr, nil
}

func NormalizeScriptName(scriptName string) string {
	return strings.TrimSpace(scriptName)
}

func resolveIdentity(labelText, interfaceName, ipText, macText, defaultGatewayText string, mtuValue int) (string, net.Interface, net.IP, net.HardwareAddr, net.IP, uint32, error) {
	label, err := common.NormalizeAdoptionLabel(labelText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	if strings.TrimSpace(interfaceName) == "" {
		return "", net.Interface{}, nil, nil, nil, 0, fmt.Errorf("interfaceName is required")
	}

	iface, err := ResolveInterface(strings.TrimSpace(interfaceName))
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	ip, err := common.NormalizeAdoptionIP(ipText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	mac, err := ResolveMAC(iface, macText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	defaultGateway, err := common.NormalizeDefaultGateway(defaultGatewayText, ip)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	mtu, err := normalizeIdentityMTU(iface, mtuValue)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	return label, iface, ip, mac, defaultGateway, mtu, nil
}

func newEntryWithGatewayAndScripts(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32, transportScriptName string, applicationScriptName string) entry {
	return entry{
		label:                 label,
		ip:                    common.CloneIPv4(ip),
		iface:                 iface,
		mac:                   common.CloneHardwareAddr(mac),
		defaultGateway:        common.CloneIPv4(defaultGateway),
		mtu:                   mtu,
		transportScriptName:   NormalizeScriptName(transportScriptName),
		applicationScriptName: NormalizeScriptName(applicationScriptName),
	}
}

func (item entry) IP() net.IP {
	return item.ip
}

func (item entry) Label() string {
	return item.label
}

func (item entry) Interface() net.Interface {
	return item.iface
}

func (item entry) MAC() net.HardwareAddr {
	return item.mac
}

func (item entry) DefaultGateway() net.IP {
	return item.defaultGateway
}

func (item entry) MTU() uint32 {
	return item.mtu
}

func (item entry) TransportScriptName() string {
	return item.transportScriptName
}

func (item entry) ApplicationScriptName() string {
	return item.applicationScriptName
}

func (item entry) snapshot() AdoptedIPAddress {
	return AdoptedIPAddress{
		Label:          item.label,
		IP:             item.ip.String(),
		InterfaceName:  item.iface.Name,
		MAC:            item.mac.String(),
		DefaultGateway: common.IPString(item.defaultGateway),
		MTU:            int(item.mtu),
	}
}

func (item entry) detailsSnapshot() AdoptedIPAddressDetails {
	return AdoptedIPAddressDetails{
		Label:                 item.label,
		IP:                    item.ip.String(),
		InterfaceName:         item.iface.Name,
		MAC:                   item.mac.String(),
		DefaultGateway:        common.IPString(item.defaultGateway),
		MTU:                   int(item.mtu),
		TransportScriptName:   NormalizeScriptName(item.transportScriptName),
		ApplicationScriptName: NormalizeScriptName(item.applicationScriptName),
	}
}

func detailsWithListener(item entry, listener Listener) AdoptedIPAddressDetails {
	details := item.detailsSnapshot()
	if listener == nil {
		return details
	}

	details.ARPCacheEntries = listener.ARPCacheSnapshot()
	status := listener.StatusSnapshot(item.ip)
	details.Capture = status.Capture
	details.Metrics = status.Metrics
	details.ScriptError = status.ScriptError
	details.Recording = listener.RecordingSnapshot(item.ip)
	details.Services = listener.ServiceSnapshot(item.ip)
	return details
}
