package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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

func sendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func printPacket(pkt gopacket.Packet) {
	var srcMAC, dstMAC string
	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		e := eth.(*layers.Ethernet)
		srcMAC, dstMAC = e.SrcMAC.String(), e.DstMAC.String()
	}

	var srcIP, dstIP, proto string
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
		proto = ip.Protocol.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
		proto = ip.NextHeader.String()
	}

	var srcPort, dstPort string
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		srcPort, dstPort = t.SrcPort.String(), t.DstPort.String()
	} else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		srcPort, dstPort = u.SrcPort.String(), u.DstPort.String()
	}

	fmt.Printf("[%s] %s -> %s", proto, srcIP, dstIP)
	if srcPort != "" {
		fmt.Printf("  ports: %s -> %s", srcPort, dstPort)
	}
	if srcMAC != "" {
		fmt.Printf("  MAC: %s -> %s", srcMAC, dstMAC)
	}
	fmt.Println()
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

func cmdARP(args []string) error {
	fs := flag.NewFlagSet("arp", flag.ExitOnError)
	ifaceName := fs.String("i", "", "interface to use (default: first active)")
	target := fs.String("t", "", "target IP address (required)")
	srcIPStr := fs.String("src-ip", "", "source IP to use (default: interface IP)")
	srcMACStr := fs.String("src-mac", "", "source MAC to use (default: interface MAC)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: moto arp -t <target-ip> [-i interface] [-src-ip ip] [-src-mac mac]")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if len(*target) == 0 {
		fs.Usage()
		return fmt.Errorf("target IP required")
	}

	dstIP := net.ParseIP(*target)
	if dstIP == nil {
		return fmt.Errorf("invalid IP: %s", *target)
	}

	iface, err := resolveIface(*ifaceName)
	if err != nil {
		return err
	}

	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return err
	}
	if *srcIPStr != "" {
		parsed := net.ParseIP(*srcIPStr)
		if parsed == nil {
			return fmt.Errorf("invalid source IP: %s", *srcIPStr)
		}
		srcIP = parsed
	}

	srcMAC := iface.HardwareAddr
	if *srcMACStr != "" {
		parsed, err := net.ParseMAC(*srcMACStr)
		if err != nil {
			return fmt.Errorf("invalid source MAC: %s", *srcMACStr)
		}
		srcMAC = parsed
	}

	devName, err := pcapDeviceName(iface)
	if err != nil {
		return err
	}
	handle, err := pcap.OpenLive(devName, 65535, true, 30*time.Second)
	if err != nil {
		return err
	}
	defer handle.Close()

	fmt.Printf("sending ARP request for %s on %s\n", dstIP, iface.Name)
	return sendARPRequest(handle, srcMAC, srcIP, dstIP)
}

func cmdCapture(args []string) error {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	ifaceName := fs.String("i", "", "interface to capture on (default: first active)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: moto capture [-i interface]")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	iface, err := resolveIface(*ifaceName)
	if err != nil {
		return err
	}
	devName, err := pcapDeviceName(iface)
	if err != nil {
		return err
	}
	fmt.Printf("capturing on %s\n", iface.Name)

	handle, err := pcap.OpenLive(devName, 65535, true, 30*time.Second)
	if err != nil {
		return err
	}
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		printPacket(pkt)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		runShell()
		return
	}

	subcommands := map[string]func([]string) error{
		"devices": cmdDevices,
		"arp":     cmdARP,
		"capture": cmdCapture,
	}

	cmd, ok := subcommands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		os.Exit(1)
	}

	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
