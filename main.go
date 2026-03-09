package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// EthParams holds overridable Ethernet layer fields.
// Zero/nil values mean "use the command default".
type EthParams struct {
	Src net.HardwareAddr
	Dst net.HardwareAddr
}

// IPv4Params holds overridable IPv4 layer fields.
// Zero values mean "use the command default".
type IPv4Params struct {
	Src        net.IP
	TTL        uint8
	TOS        uint8
	ID         uint16
	Flags      layers.IPv4Flag
	FragOffset uint16
}

// ICMPv4Params holds overridable ICMPv4 layer fields.
type ICMPv4Params struct {
	TypeCode layers.ICMPv4TypeCode
	ID       uint16
	Seq      uint16
	Data     []byte
	// explicit flags so zero-value ID/Seq/TypeCode are distinguishable from unset
	HasTypeCode bool
	HasID       bool
	HasSeq      bool
}

// ARPParams holds overridable ARP layer fields.
type ARPParams struct {
	Op     uint16
	SrcMAC net.HardwareAddr
	SrcIP  net.IP
	DstMAC net.HardwareAddr
	DstIP  net.IP
}

// ── Layer builders ───────────────────────────────────────────────────────────

func buildEthLayer(p EthParams, defaultSrc, defaultDst net.HardwareAddr, etherType layers.EthernetType) layers.Ethernet {
	src := defaultSrc
	if p.Src != nil {
		src = p.Src
	}
	dst := defaultDst
	if p.Dst != nil {
		dst = p.Dst
	}
	return layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: etherType}
}

func buildARPLayer(p ARPParams, defaultSrcMAC net.HardwareAddr, defaultSrcIP, defaultDstIP net.IP) layers.ARP {
	op := uint16(layers.ARPRequest)
	if p.Op != 0 {
		op = p.Op
	}
	srcMAC := defaultSrcMAC
	if p.SrcMAC != nil {
		srcMAC = p.SrcMAC
	}
	srcIP := defaultSrcIP
	if p.SrcIP != nil {
		srcIP = p.SrcIP
	}
	dstMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	if p.DstMAC != nil {
		dstMAC = p.DstMAC
	}
	dstIP := defaultDstIP
	if p.DstIP != nil {
		dstIP = p.DstIP
	}
	return layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
}

func buildIPv4Layer(p IPv4Params, defaultSrcIP, dstIP net.IP, proto layers.IPProtocol) layers.IPv4 {
	srcIP := defaultSrcIP
	if p.Src != nil {
		srcIP = p.Src
	}
	ttl := uint8(64)
	if p.TTL != 0 {
		ttl = p.TTL
	}
	return layers.IPv4{
		Version:    4,
		TTL:        ttl,
		TOS:        p.TOS,
		Id:         p.ID,
		Flags:      p.Flags,
		FragOffset: p.FragOffset,
		Protocol:   proto,
		SrcIP:      srcIP,
		DstIP:      dstIP.To4(),
	}
}

func buildICMPv4Layer(p ICMPv4Params) layers.ICMPv4 {
	typeCode := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	if p.HasTypeCode {
		typeCode = p.TypeCode
	}
	id := uint16(1)
	if p.HasID {
		id = p.ID
	}
	seq := uint16(1)
	if p.HasSeq {
		seq = p.Seq
	}
	return layers.ICMPv4{TypeCode: typeCode, Id: id, Seq: seq}
}

// ── Send functions ───────────────────────────────────────────────────────────

func doARP(iface net.Interface, defaultDstIP net.IP, eth EthParams, arp ARPParams) error {
	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return err
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

	ethLayer := buildEthLayer(eth, iface.HardwareAddr, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, layers.EthernetTypeARP)
	arpLayer := buildARPLayer(arp, iface.HardwareAddr, srcIP, defaultDstIP)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &ethLayer, &arpLayer); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func doPing(iface net.Interface, defaultDstIP net.IP, eth EthParams, ip4 IPv4Params, icmp ICMPv4Params) error {
	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return err
	}

	var dstMAC net.HardwareAddr
	if eth.Dst != nil {
		dstMAC = eth.Dst
	} else {
		resolved, err := resolveMAC(iface, defaultDstIP)
		if err != nil {
			return fmt.Errorf("resolving MAC for %s: %w", defaultDstIP, err)
		}
		dstMAC = resolved
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

	ethLayer := buildEthLayer(eth, iface.HardwareAddr, dstMAC, layers.EthernetTypeIPv4)
	ip4Layer := buildIPv4Layer(ip4, srcIP, defaultDstIP, layers.IPProtocolICMPv4)
	icmpLayer := buildICMPv4Layer(icmp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &ethLayer, &ip4Layer, &icmpLayer, gopacket.Payload(icmp.Data)); err != nil {
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

	var eth EthParams
	var arp ARPParams

	if *srcIPStr != "" {
		parsed := net.ParseIP(*srcIPStr)
		if parsed == nil {
			return fmt.Errorf("invalid source IP: %s", *srcIPStr)
		}
		arp.SrcIP = parsed
	}

	if *srcMACStr != "" {
		parsed, err := net.ParseMAC(*srcMACStr)
		if err != nil {
			return fmt.Errorf("invalid source MAC: %s", *srcMACStr)
		}
		eth.Src = parsed
		arp.SrcMAC = parsed
	}

	fmt.Printf("sending ARP request for %s on %s\n", dstIP, iface.Name)
	if err := doARP(iface, dstIP, eth, arp); err != nil {
		if *srcMACStr != "" {
			return fmt.Errorf("%w\n(MAC spoofing is often blocked by the NIC driver — the packet was not sent)", err)
		}
		return err
	}
	return nil
}

func cmdPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	ifaceName := fs.String("i", "", "interface to use (default: first active)")
	target := fs.String("t", "", "target IP address (required)")
	srcIPStr := fs.String("src-ip", "", "source IP to use (default: interface IP)")
	srcMACStr := fs.String("src-mac", "", "source MAC to use (default: interface MAC)")
	dstMACStr := fs.String("dst-mac", "", "destination MAC (default: broadcast)")
	idFlag := fs.Int("id", 1, "ICMP identifier")
	seqFlag := fs.Int("seq", 1, "ICMP sequence number")
	dataStr := fs.String("data", "", `payload bytes: raw string or hex with 0x prefix (e.g. -data "hello" or -data 0xdeadbeef)`)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: moto ping -t <target-ip> [-i interface] [-src-ip ip] [-src-mac mac] [-dst-mac mac] [-id n] [-seq n] [-data bytes]")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *target == "" {
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

	var eth EthParams
	var ip4 IPv4Params
	var icmp ICMPv4Params

	if *srcIPStr != "" {
		parsed := net.ParseIP(*srcIPStr)
		if parsed == nil {
			return fmt.Errorf("invalid source IP: %s", *srcIPStr)
		}
		ip4.Src = parsed
	}

	if *srcMACStr != "" {
		parsed, err := net.ParseMAC(*srcMACStr)
		if err != nil {
			return fmt.Errorf("invalid source MAC: %s", *srcMACStr)
		}
		eth.Src = parsed
	}

	if *dstMACStr != "" {
		parsed, err := net.ParseMAC(*dstMACStr)
		if err != nil {
			return fmt.Errorf("invalid destination MAC: %s", *dstMACStr)
		}
		eth.Dst = parsed
	}

	icmp.ID = uint16(*idFlag)
	icmp.HasID = true
	icmp.Seq = uint16(*seqFlag)
	icmp.HasSeq = true

	payload, err := parsePayload(*dataStr)
	if err != nil {
		return err
	}
	icmp.Data = payload

	fmt.Printf("sending ICMP echo request to %s on %s\n", dstIP, iface.Name)
	if err := doPing(iface, dstIP, eth, ip4, icmp); err != nil {
		if *srcMACStr != "" {
			return fmt.Errorf("%w\n(MAC spoofing is often blocked by the NIC driver — the packet was not sent)", err)
		}
		return err
	}
	return nil
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
		"ping":    cmdPing,
		"capture": cmdCapture,
		"script":  cmdScript,
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
