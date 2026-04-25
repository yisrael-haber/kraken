package adoption

import (
	"net"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type Identity struct {
	Label                 string
	IP                    net.IP
	Interface             net.Interface
	MAC                   net.HardwareAddr
	DefaultGateway        net.IP
	MTU                   uint32
	TransportScriptName   string
	ApplicationScriptName string
}

func ResolveInterface(name string) (net.Interface, error) {
	iface, err := net.InterfaceByName(strings.TrimSpace(name))
	if err != nil {
		return net.Interface{}, err
	}
	return *iface, nil
}

func ResolveMAC(iface net.Interface, macText string) (net.HardwareAddr, error) {
	return net.ParseMAC(strings.TrimSpace(macText))
}

func NormalizeScriptName(scriptName string) string {
	return strings.TrimSpace(scriptName)
}

func resolveIdentity(labelText, interfaceName, ipText, macText, defaultGatewayText string, mtuValue int) (string, net.Interface, net.IP, net.HardwareAddr, net.IP, uint32, error) {
	label, err := common.NormalizeAdoptionLabel(labelText)
	if err != nil {
		return "", net.Interface{}, nil, nil, nil, 0, err
	}

	iface, err := ResolveInterface(interfaceName)

	if err != nil || (iface.Flags&net.FlagLoopback != 0) {
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

func newIdentityWithGatewayAndScripts(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32, transportScriptName string, applicationScriptName string) Identity {
	return Identity{
		Label:                 label,
		IP:                    common.CloneIPv4(ip),
		Interface:             iface,
		MAC:                   common.CloneHardwareAddr(mac),
		DefaultGateway:        common.CloneIPv4(defaultGateway),
		MTU:                   mtu,
		TransportScriptName:   NormalizeScriptName(transportScriptName),
		ApplicationScriptName: NormalizeScriptName(applicationScriptName),
	}
}

func (item Identity) snapshot() AdoptedIPAddress {
	return AdoptedIPAddress{
		Label:          item.Label,
		IP:             item.IP.String(),
		InterfaceName:  item.Interface.Name,
		MAC:            item.MAC.String(),
		DefaultGateway: common.IPString(item.DefaultGateway),
		MTU:            int(item.MTU),
	}
}

func (item Identity) detailsSnapshot() AdoptedIPAddressDetails {
	return AdoptedIPAddressDetails{
		Label:                 item.Label,
		IP:                    item.IP.String(),
		InterfaceName:         item.Interface.Name,
		MAC:                   item.MAC.String(),
		DefaultGateway:        common.IPString(item.DefaultGateway),
		MTU:                   int(item.MTU),
		TransportScriptName:   item.TransportScriptName,
		ApplicationScriptName: item.ApplicationScriptName,
	}
}

func detailsWithListener(item Identity, listener Listener) AdoptedIPAddressDetails {
	details := item.detailsSnapshot()
	if listener == nil {
		return details
	}

	details.ARPCacheEntries = listener.ARPCacheSnapshot()
	status := listener.StatusSnapshot(item.IP)
	details.Capture = status.Capture
	details.ScriptError = status.ScriptError
	details.Recording = listener.RecordingSnapshot(item.IP)
	details.Services = listener.ServiceSnapshot(item.IP)
	return details
}
