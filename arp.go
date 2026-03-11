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

func cmdARP(args []string) error {
	fs := flag.NewFlagSet("arp", flag.ExitOnError)
	ifaceName := fs.String("i", "", "interface to use (default: first active)")
	target := fs.String("t", "", "target IP address (required)")
	srcIPStr := fs.String("src-ip", "", "source IP to use (default: interface IP)")
	srcMACStr := fs.String("src-mac", "", "source MAC to use (default: interface MAC)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: kraken arp -t <target-ip> [-i interface] [-src-ip ip] [-src-mac mac]")
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
