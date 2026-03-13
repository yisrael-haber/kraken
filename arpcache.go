package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)


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

// snapshot returns a copy of all entries for display.
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

// arpRequest sends an ARP request from srcMAC/srcIP asking for dstIP on devName
// and waits up to arpResolveTimeout for a reply. It does not update the cache.
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
		// Closing the handle causes the goroutine's NextPacket to return an
		// error, letting it exit. The buffered channel prevents a goroutine leak.
		handle.Close()
		return nil, fmt.Errorf("ARP timeout: no reply from %s", dstIP)
	}
}

// resolveMAC returns the MAC address for dstIP, using the interface's own
// IP/MAC as the ARP sender. Checks the cache first; caches and returns on hit.
func resolveMAC(iface net.Interface, dstIP net.IP) (net.HardwareAddr, error) {
	if mac, ok := globalARPCache.lookup(dstIP); ok {
		return mac, nil
	}
	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return nil, err
	}
	devName, err := pcapDeviceName(iface)
	if err != nil {
		return nil, err
	}
	mac, err := arpRequest(devName, iface.HardwareAddr, srcIP, dstIP)
	if err != nil {
		return nil, err
	}
	globalARPCache.set(dstIP, mac)
	return mac, nil
}
