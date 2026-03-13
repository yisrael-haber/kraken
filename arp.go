package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ── ARP cache ─────────────────────────────────────────────────────────────────

const (
	arpCacheTTL      = 5 * time.Minute
	arpResolveTimeout = 3 * time.Second
)

type arpEntry struct {
	mac     net.HardwareAddr
	updated time.Time
}

type arpCache struct {
	mu      sync.RWMutex
	entries map[string]arpEntry
}

var globalARPCache = &arpCache{
	entries: make(map[string]arpEntry),
}

func (c *arpCache) lookup(ip net.IP) (net.HardwareAddr, bool) {
	c.mu.RLock()
	e, ok := c.entries[ip.String()]
	c.mu.RUnlock()
	if !ok || time.Since(e.updated) > arpCacheTTL {
		return nil, false
	}
	return e.mac, true
}

func (c *arpCache) set(ip net.IP, mac net.HardwareAddr) {
	c.mu.Lock()
	c.entries[ip.String()] = arpEntry{mac: mac, updated: time.Now()}
	c.mu.Unlock()
}

func (c *arpCache) delete(ip net.IP) {
	c.mu.Lock()
	delete(c.entries, ip.String())
	c.mu.Unlock()
}

func (c *arpCache) snapshot() map[string]arpEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]arpEntry, len(c.entries))
	for k, v := range c.entries {
		out[k] = v
	}
	return out
}

func (c *arpCache) clear() {
	c.mu.Lock()
	c.entries = make(map[string]arpEntry)
	c.mu.Unlock()
}

// arpRequest sends an ARP request from srcMAC/srcIP asking for dstIP and
// waits up to arpResolveTimeout for a reply. Does not update the cache.
func arpRequest(devName string, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("BPF filter: %w", err)
	}

	ethLayer := buildEthLayer(EthParams{}, srcMAC, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, layers.EthernetTypeARP)
	arpLayer := buildARPLayer(ARPParams{}, srcMAC, srcIP, dstIP)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &ethLayer, &arpLayer); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	type result struct {
		mac net.HardwareAddr
		err error
	}
	ch := make(chan result, 1)
	go func() {
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			pkt, err := src.NextPacket()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if err == io.EOF || err != nil {
				ch <- result{err: fmt.Errorf("ARP receive: %w", err)}
				return
			}
			arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
			if !ok || arp.Operation != uint16(layers.ARPReply) {
				continue
			}
			if !net.IP(arp.SourceProtAddress).Equal(dstIP.To4()) {
				continue
			}
			mac := make(net.HardwareAddr, len(arp.SourceHwAddress))
			copy(mac, arp.SourceHwAddress)
			ch <- result{mac: mac}
		}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		return res.mac, nil
	case <-time.After(arpResolveTimeout):
		handle.Close()
		return nil, fmt.Errorf("ARP timeout: no reply from %s", dstIP)
	}
}

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
