package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ipHandlers maps IP protocols to their adoption response handlers.
// Add an entry here to handle additional protocols for adopted addresses.
var ipHandlers = map[layers.IPProtocol]func(*ifaceListener, *layers.Ethernet, *layers.IPv4, gopacket.Packet, adoptEntry){
	layers.IPProtocolICMPv4: handleICMPv4,
	layers.IPProtocolTCP:    handleTCP,
}

func handleTCP(_ *ifaceListener, eth *layers.Ethernet, ip4 *layers.IPv4, pkt gopacket.Packet, entry adoptEntry) {
	// Keep the ARP cache warm so runOutbound can always reach the sender.
	globalARPCache.set(ip4.SrcIP, net.HardwareAddr(eth.SrcMAC))
	if entry.netstack == nil {
		return
	}
	entry.netstack.injectInbound(pkt)
}

func handleICMPv4(r *ifaceListener, eth *layers.Ethernet, ip4 *layers.IPv4, pkt gopacket.Packet, entry adoptEntry) {
	icmpPkt, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok || icmpPkt.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
		return
	}
	r.sendICMPReply(eth, ip4, icmpPkt, entry)
}

// ── Adoption table ────────────────────────────────────────────────────────────

type adoptEntry struct {
	ip       net.IP
	mac      net.HardwareAddr
	iface    net.Interface
	netstack *adoptedNetstack
}

type ifaceListener struct {
	iface  net.Interface
	handle *pcap.Handle
	stop   chan struct{}
}

type adoptionTable struct {
	mu        sync.Mutex
	entries   map[string]adoptEntry    // key: ip.String()
	listeners map[string]*ifaceListener // key: iface.Name
}

var globalAdoptions = &adoptionTable{
	entries:   make(map[string]adoptEntry),
	listeners: make(map[string]*ifaceListener),
}

// add adopts ip→mac on iface, starting a listener for the interface if needed.
// capturePath, if non-empty, is passed to the netstack for per-packet pcap recording.
func (t *adoptionTable) add(ip net.IP, mac net.HardwareAddr, iface net.Interface, capturePath string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	ipStr := ip.String()

	// If already adopted on a different interface, clean up the old listener.
	if old, exists := t.entries[ipStr]; exists && old.iface.Name != iface.Name {
		delete(t.entries, ipStr)
		t.maybeStopListener(old.iface.Name)
	}

	t.entries[ipStr] = adoptEntry{ip: ip, mac: mac, iface: iface}

	if _, exists := t.listeners[iface.Name]; !exists {
		if err := t.startListener(iface); err != nil {
			delete(t.entries, ipStr)
			return err
		}
	}

	ns, err := newAdoptedNetstack(ip, mac, iface, t.listeners[iface.Name].handle, capturePath)
	if err != nil {
		fmt.Printf("warning: netstack init failed for %s: %v\n", ip, err)
	} else {
		entry := t.entries[ipStr]
		entry.netstack = ns
		t.entries[ipStr] = entry
	}
	return nil
}

// remove drops the adoption for ip, stopping the interface listener if no IPs remain.
// Returns false if ip was not adopted.
func (t *adoptionTable) remove(ip net.IP) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.entries[ip.String()]
	if !exists {
		return false
	}
	if entry.netstack != nil {
		entry.netstack.stop()
	}
	delete(t.entries, ip.String())
	t.maybeStopListener(entry.iface.Name)
	return true
}

func (t *adoptionTable) lookupByIP(ip net.IP) (adoptEntry, bool) {
	t.mu.Lock()
	e, ok := t.entries[ip.String()]
	t.mu.Unlock()
	return e, ok
}

func (t *adoptionTable) snapshot() map[string]adoptEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]adoptEntry, len(t.entries))
	for k, v := range t.entries {
		out[k] = v
	}
	return out
}

// maybeStopListener signals the listener for ifaceName to exit if no entries reference it.
// Must be called with t.mu held.
func (t *adoptionTable) maybeStopListener(ifaceName string) {
	for _, e := range t.entries {
		if e.iface.Name == ifaceName {
			return
		}
	}
	if resp, ok := t.listeners[ifaceName]; ok {
		close(resp.stop)
		delete(t.listeners, ifaceName)
	}
}

// startListener opens a pcap handle on iface and launches the responder goroutine.
// Must be called with t.mu held.
func (t *adoptionTable) startListener(iface net.Interface) error {
	devName, err := pcapDeviceName(iface)
	if err != nil {
		return fmt.Errorf("pcap device for %s: %w", iface.Name, err)
	}
	// Short read timeout so the goroutine can check its stop channel periodically.
	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	if err != nil {
		return err
	}
	// Capture ARP and all IPv4 traffic; IP matching against adopted addresses is
	// done in Go so the filter stays constant as IPs are added/removed.
	if err := handle.SetBPFFilter("arp or ip"); err != nil {
		handle.Close()
		return fmt.Errorf("BPF filter: %w", err)
	}
	resp := &ifaceListener{
		iface:  iface,
		handle: handle,
		stop:   make(chan struct{}),
	}
	t.listeners[iface.Name] = resp
	go resp.run(t)
	return nil
}

// ── Responder goroutine ───────────────────────────────────────────────────────

// run owns the pcap handle and dispatches incoming packets to the appropriate
// handler for as long as the adoption is active.
func (r *ifaceListener) run(table *adoptionTable) {
	defer r.handle.Close()
	defragger := ip4defrag.NewIPv4Defragmenter()
	src := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	for {
		select {
		case <-r.stop:
			return
		default:
		}

		rawPkt, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF || err != nil {
			return
		}

		// ARP request → send ARP reply if the target IP is adopted.
		if arpPkt, ok := rawPkt.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
			if arpPkt.Operation == uint16(layers.ARPRequest) {
				if entry, found := table.lookupByIP(net.IP(arpPkt.DstProtAddress)); found {
					r.sendARPReply(arpPkt, entry)
				}
			}
			continue
		}

		// IPv4: defragment, then dispatch to the registered handler.
		pkt, err := defragPacket(defragger, rawPkt)
		if err != nil || pkt == nil {
			continue
		}
		ip4Pkt, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		entry, found := table.lookupByIP(ip4Pkt.DstIP)
		if !found {
			continue
		}
		handler, ok := ipHandlers[ip4Pkt.Protocol]
		if !ok {
			continue
		}
		ethPkt, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			continue
		}
		handler(r, ethPkt, ip4Pkt, pkt, entry)
	}
}

// ── Reply senders ─────────────────────────────────────────────────────────────

func (r *ifaceListener) sendARPReply(req *layers.ARP, entry adoptEntry) {
	requesterMAC := net.HardwareAddr(req.SourceHwAddress)
	requesterIP := net.IP(req.SourceProtAddress)
	// Learn the requester's MAC so runOutbound can reach them without a
	// separate ARP probe.
	globalARPCache.set(requesterIP, requesterMAC)

	ethLayer := buildEthLayer(EthParams{}, entry.mac, requesterMAC, layers.EthernetTypeARP)
	arpLayer := buildARPLayer(
		ARPParams{Op: uint16(layers.ARPReply), SrcMAC: entry.mac, SrcIP: entry.ip, DstMAC: requesterMAC, DstIP: requesterIP},
		entry.mac, entry.ip, requesterIP,
	)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &ethLayer, &arpLayer); err != nil {
		return
	}
	_ = r.handle.WritePacketData(buf.Bytes())
}

func (r *ifaceListener) sendICMPReply(eth *layers.Ethernet, ip4 *layers.IPv4, icmp *layers.ICMPv4, entry adoptEntry) {
	ethLayer := buildEthLayer(EthParams{}, entry.mac, net.HardwareAddr(eth.SrcMAC), layers.EthernetTypeIPv4)
	ip4Layer := buildIPv4Layer(IPv4Params{}, entry.ip, ip4.SrcIP, layers.IPProtocolICMPv4)
	icmpLayer := buildICMPv4Layer(ICMPv4Params{
		TypeCode:    layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		ID:          icmp.Id,
		Seq:         icmp.Seq,
		HasTypeCode: true,
		HasID:       true,
		HasSeq:      true,
	})

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &ethLayer, &ip4Layer, &icmpLayer, gopacket.Payload(icmp.Payload)); err != nil {
		return
	}
	_ = r.handle.WritePacketData(buf.Bytes())
}
