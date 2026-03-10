package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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

func doCapture(iface net.Interface) error {
	devName, err := pcapDeviceName(iface)
	if err != nil {
		return err
	}
	handle, err := pcap.OpenLive(devName, 65535, true, 30*time.Second)
	if err != nil {
		return err
	}
	defer handle.Close()

	defragger := ip4defrag.NewIPv4Defragmenter()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for rawPkt := range src.Packets() {
		pkt, err := defragPacket(defragger, rawPkt)
		if err != nil || pkt == nil {
			continue
		}
		printPacket(pkt)
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
	fmt.Printf("capturing on %s\n", iface.Name)
	return doCapture(iface)
}
