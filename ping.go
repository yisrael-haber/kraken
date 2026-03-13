package main

import (
	"errors"
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

const pingReplyTimeout = 3 * time.Second

var (
	zeroMAC    = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	loopbackIP = net.IP{127, 0, 0, 1}
)

// netRoute holds the routing decision for a given destination.
type netRoute struct {
	iface  net.Interface
	srcMAC net.HardwareAddr
	dstMAC net.HardwareAddr
	local  bool
}

func (r *netRoute) openHandle() (*pcap.Handle, error) {
	var devName string
	if r.local {
		devName = "lo"
	} else {
		var err error
		devName, err = pcapDeviceName(r.iface)
		if err != nil {
			return nil, err
		}
	}
	return pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
}

// isLocalIP reports whether ip is a loopback address or assigned to a local interface.
func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ifaceIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ifaceIP = v.IP
			case *net.IPAddr:
				ifaceIP = v.IP
			}
			if ifaceIP != nil && ifaceIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// resolveRoute returns routing info for reaching dstIP. Local destinations use
// loopback; remote destinations resolve the MAC via ARP on iface.
func resolveRoute(iface net.Interface, dstIP net.IP) (*netRoute, error) {
	if isLocalIP(dstIP) {
		loIface, err := net.InterfaceByName("lo")
		if err != nil {
			return nil, fmt.Errorf("loopback interface not available: %w", err)
		}
		return &netRoute{
			iface:  *loIface,
			srcMAC: append(net.HardwareAddr{}, zeroMAC...),
			dstMAC: append(net.HardwareAddr{}, zeroMAC...),
			local:  true,
		}, nil
	}
	dstMAC, err := resolveMAC(iface, dstIP)
	if err != nil {
		return nil, err
	}
	return &netRoute{
		iface:  iface,
		srcMAC: append(net.HardwareAddr{}, iface.HardwareAddr...),
		dstMAC: dstMAC,
	}, nil
}

var errPingTimeout = errors.New("ping timeout")

func formatRTT(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.3f µs", float64(d.Nanoseconds())/1000)
	}
	return fmt.Sprintf("%.3f ms", float64(d.Nanoseconds())/1e6)
}

func doPing(iface net.Interface, defaultDstIP net.IP, eth EthParams, ip4 IPv4Params, icmp ICMPv4Params) (time.Duration, error) {
	route, err := resolveRoute(iface, defaultDstIP)
	if err != nil {
		return 0, fmt.Errorf("resolving route for %s: %w", defaultDstIP, err)
	}

	// Source IP: loopback for local destinations, interface IP for remote.
	var srcIP net.IP
	if route.local {
		srcIP = loopbackIP
	} else {
		srcIP, err = ifaceIPv4(iface)
		if err != nil {
			return 0, err
		}
	}

	// Destination MAC: explicit user override takes priority over route default.
	dstMAC := route.dstMAC
	if eth.Dst != nil {
		dstMAC = eth.Dst
	}

	handle, err := route.openHandle()
	if err != nil {
		return 0, err
	}
	if err := handle.SetBPFFilter("icmp or (ip[6:2] & 0x3fff != 0)"); err != nil {
		handle.Close()
		return 0, fmt.Errorf("BPF filter: %w", err)
	}

	ethLayer := buildEthLayer(eth, route.srcMAC, dstMAC, layers.EthernetTypeIPv4)
	ip4Layer := buildIPv4Layer(ip4, srcIP, defaultDstIP, layers.IPProtocolICMPv4)
	icmpLayer := buildICMPv4Layer(icmp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &ethLayer, &ip4Layer, &icmpLayer, gopacket.Payload(icmp.Data)); err != nil {
		handle.Close()
		return 0, err
	}

	sentAt := time.Now()
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		handle.Close()
		return 0, err
	}

	sentID := icmpLayer.Id
	sentSeq := icmpLayer.Seq
	dstIP4 := defaultDstIP.To4()

	type result struct {
		rtt time.Duration
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defragger := ip4defrag.NewIPv4Defragmenter()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			rawPkt, err := src.NextPacket()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if err != nil {
				ch <- result{err: err}
				return
			}
			pkt, err := defragPacket(defragger, rawPkt)
			if err != nil || pkt == nil {
				continue
			}
			ip4Pkt, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || !ip4Pkt.SrcIP.Equal(dstIP4) {
				continue
			}
			icmpPkt, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if !ok || icmpPkt.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
				continue
			}
			if icmpPkt.Id != sentID || icmpPkt.Seq != sentSeq {
				continue
			}
			ch <- result{rtt: time.Since(sentAt)}
			return
		}
	}()

	select {
	case res := <-ch:
		handle.Close()
		if res.err != nil {
			return 0, res.err
		}
		return res.rtt, nil
	case <-time.After(pingReplyTimeout):
		handle.Close()
		return 0, errPingTimeout
	}
}

// runPing sends count ICMP echo requests and prints per-reply RTT and a summary.
// If icmp.HasSeq is false, the sequence number is auto-incremented per packet.
func runPing(iface net.Interface, dstIP net.IP, count int, eth EthParams, ip4 IPv4Params, icmp ICMPv4Params) error {
	fmt.Printf("PING %s on %s\n", dstIP, iface.Name)
	var received int
	for i := 1; i <= count; i++ {
		loopICMP := icmp
		if !loopICMP.HasSeq {
			loopICMP.Seq = uint16(i)
			loopICMP.HasSeq = true
		}
		rtt, err := doPing(iface, dstIP, eth, ip4, loopICMP)
		if errors.Is(err, errPingTimeout) {
			fmt.Printf("Request timeout for icmp_seq=%d\n", loopICMP.Seq)
		} else if err != nil {
			return err
		} else {
			received++
			fmt.Printf("reply from %s: icmp_seq=%d time=%s\n", dstIP, loopICMP.Seq, formatRTT(rtt))
		}
	}
	loss := (count - received) * 100 / count
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss\n", count, received, loss)
	return nil
}

func cmdPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	ifaceName := fs.String("i", "", "interface to use (default: first active)")
	target := fs.String("t", "", "target IP address (required)")
	srcIPStr := fs.String("src-ip", "", "source IP to use (default: interface IP)")
	srcMACStr := fs.String("src-mac", "", "source MAC to use (default: interface MAC)")
	dstMACStr := fs.String("dst-mac", "", "destination MAC (default: resolved via ARP)")
	idFlag := fs.Int("id", 1, "ICMP identifier")
	seqFlag := fs.Int("seq", 0, "ICMP sequence number (default: auto-increment from 1)")
	nFlag := fs.Int("n", 20, "number of echo requests to send")
	dataStr := fs.String("data", "", `payload bytes: raw string or hex with 0x prefix (e.g. -data "hello" or -data 0xdeadbeef)`)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: kraken ping -t <target-ip> [-i interface] [-n count] [-src-ip ip] [-src-mac mac] [-dst-mac mac] [-id n] [-seq n] [-data bytes]")
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

	payload, err := parsePayload(*dataStr)
	if err != nil {
		return err
	}
	icmp.Data = payload

	if *seqFlag != 0 {
		icmp.Seq = uint16(*seqFlag)
		icmp.HasSeq = true
	}

	if err := runPing(iface, dstIP, *nFlag, eth, ip4, icmp); err != nil {
		if *srcMACStr != "" {
			return fmt.Errorf("%w\n(MAC spoofing is often blocked by the NIC driver — the packet was not sent)", err)
		}
		return err
	}
	return nil
}
