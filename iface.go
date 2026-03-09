package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

// parsePayload parses a data string into bytes.
// Strings prefixed with "0x" are decoded as hex; everything else is used as-is.
func parsePayload(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		b, err := hex.DecodeString(s[2:])
		if err != nil {
			return nil, fmt.Errorf("invalid hex payload: %w", err)
		}
		return b, nil
	}
	return []byte(s), nil
}

func getActiveInterfaces() ([]net.Interface, error) {
	const requiredFlags = net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning

	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var active []net.Interface
	for _, iface := range all {
		if iface.Flags&requiredFlags != requiredFlags {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		active = append(active, iface)
	}
	return active, nil
}

func ifaceIPv4(iface net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", iface.Name)
}

// pcapDeviceName returns the device name pcap.OpenLive expects for the given
// interface. On Linux this matches iface.Name directly; on Windows Npcap uses
// "\Device\NPF_{GUID}" names that bear no relation to the friendly name, so we
// match by IP address instead.
func pcapDeviceName(iface net.Interface) (string, error) {
	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return "", err
	}
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("listing pcap devices: %w", err)
	}
	for _, dev := range devs {
		if dev.Name == iface.Name {
			return dev.Name, nil // fast path: Linux
		}
		for _, addr := range dev.Addresses {
			if addr.IP.Equal(srcIP) {
				return dev.Name, nil // Windows: matched by IP
			}
		}
	}
	return "", fmt.Errorf("no pcap device found for interface %s (%s)", iface.Name, srcIP)
}

func resolveIface(name string) (net.Interface, error) {
	if name != "" {
		found, err := net.InterfaceByName(name)
		if err != nil {
			return net.Interface{}, fmt.Errorf("interface %q not found: %w", name, err)
		}
		return *found, nil
	}
	interfaces, err := getActiveInterfaces()
	if err != nil || len(interfaces) == 0 {
		return net.Interface{}, fmt.Errorf("no active interfaces found")
	}
	return interfaces[0], nil
}

func cmdDevices(args []string) error {
	interfaces, err := getActiveInterfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		fmt.Println(iface.Name)
	}
	return nil
}
