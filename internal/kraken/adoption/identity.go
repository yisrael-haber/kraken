package adoption

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const defaultIdentityMTU = 1500

func normalizeIdentity(identity *Identity) error {
	var err error
	identity.Label, err = common.NormalizeAdoptionLabel(identity.Label)
	if err != nil {
		return err
	}

	ifacePtr, err := net.InterfaceByName(strings.TrimSpace(identity.InterfaceName))
	if err != nil {
		return err
	}
	iface := *ifacePtr
	if iface.Flags&net.FlagLoopback != 0 {
		return errors.New("loopback interface cannot be adopted")
	}

	ip := identity.IP.To4()
	if ip == nil {
		return errors.New("a valid IPv4 address is required")
	}

	if len(identity.MAC) == 0 {
		return errors.New("a valid MAC address is required")
	}

	identity.DefaultGateway, err = common.NormalizeDefaultGateway(ipString(identity.DefaultGateway), ip)
	if err != nil {
		return err
	}

	identity.MTU, err = normalizeIdentityMTU(iface, int(identity.MTU))
	if err != nil {
		return err
	}

	identity.IP = ip
	identity.InterfaceName = iface.Name
	identity.Interface = iface
	return nil
}

func newIdentityWithGatewayAndScripts(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32, transportScriptName string, applicationScriptName string) Identity {
	return Identity{
		Label:                 label,
		IP:                    ip.To4(),
		InterfaceName:         iface.Name,
		Interface:             iface,
		MAC:                   HardwareAddr(mac),
		DefaultGateway:        defaultGateway.To4(),
		MTU:                   mtu,
		TransportScriptName:   transportScriptName,
		ApplicationScriptName: applicationScriptName,
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func normalizeIdentityMTU(iface net.Interface, mtu int) (uint32, error) {
	if mtu == 0 {
		mtu = iface.MTU
	}
	if mtu == 0 {
		mtu = defaultIdentityMTU
	}
	if mtu < 68 || mtu > 65535 {
		return 0, fmt.Errorf("mtu must be between 68 and 65535")
	}
	return uint32(mtu), nil
}
