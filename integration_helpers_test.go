//go:build integration

package main

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
)

const (
	// adoptedIP is a link-local address chosen to be absent from any real host
	// on the test network.  169.254.x.x is never globally routed and DHCP
	// clients only use it as a last resort, so collisions are extremely unlikely.
	testAdoptedIPStr  = "169.254.99.1"
	testAdoptedIPStr2 = "169.254.99.2"
)

// adoptedMAC is the synthetic MAC we tell the adoption table to use.
var adoptedMAC = net.HardwareAddr{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
var adoptedMAC2 = net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}

// requireRoot skips the test unless the process is running as root (UID 0).
// All integration tests call this at the top because pcap requires root.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("integration test requires root (pcap)")
	}
}

// firstEthernetIface returns the first active, non-loopback interface that
// has an Ethernet MAC and an IPv4 address, or skips the test.
func firstEthernetIface(t *testing.T) net.Interface {
	t.Helper()
	ifaces, err := getActiveInterfaces()
	require.NoError(t, err, "getActiveInterfaces")
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 0 {
			continue // loopback or tunnel
		}
		if _, err := ifaceIPv4(iface); err != nil {
			continue
		}
		return iface
	}
	t.Skip("no suitable Ethernet interface found")
	panic("unreachable")
}

// openCapture opens a promiscuous pcap handle on iface with bpfFilter applied.
func openCapture(t *testing.T, iface net.Interface, bpfFilter string) *pcap.Handle {
	t.Helper()
	devName, err := pcapDeviceName(iface)
	require.NoError(t, err)
	h, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	require.NoError(t, err)
	require.NoError(t, h.SetBPFFilter(bpfFilter))
	t.Cleanup(h.Close)
	return h
}

// nextPacketTimeout reads from src until it finds a packet accepted by accept,
// or until timeout elapses.  Returns nil on timeout.
func nextPacketTimeout(src *gopacket.PacketSource, timeout time.Duration, accept func(gopacket.Packet) bool) gopacket.Packet {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pkt, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return nil
		}
		if accept(pkt) {
			return pkt
		}
	}
	return nil
}

// sendPacket serialises layers and writes the resulting bytes to handle.
func sendPacket(t *testing.T, handle *pcap.Handle, ls ...gopacket.SerializableLayer) {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ls...,
	))
	require.NoError(t, handle.WritePacketData(buf.Bytes()))
}

// adoptIP registers ip/mac/iface in globalAdoptions and waits briefly for the
// listener goroutine to start.  It un-adopts at test cleanup.
func adoptIP(t *testing.T, ip net.IP, mac net.HardwareAddr, iface net.Interface) {
	t.Helper()
	require.NoError(t, globalAdoptions.add(ip, mac, iface, ""))
	time.Sleep(50 * time.Millisecond) // let the listener goroutine start
	t.Cleanup(func() { globalAdoptions.remove(ip) })
}

// buildEcho builds an ICMP echo-request packet from srcIP/srcMAC to dstIP/dstMAC.
func buildEchoRequest(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id, seq uint16) []byte {
	t.Helper()
	eth := buildEthLayer(EthParams{}, srcMAC, dstMAC, layers.EthernetTypeIPv4)
	ip4 := buildIPv4Layer(IPv4Params{}, srcIP.To4(), dstIP.To4(), layers.IPProtocolICMPv4)
	icmp := buildICMPv4Layer(ICMPv4Params{ID: id, Seq: seq, HasID: true, HasSeq: true})
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&eth, &ip4, &icmp,
	))
	return buf.Bytes()
}
