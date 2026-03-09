package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const pingReplyTimeout = 3 * time.Second

var errPingTimeout = errors.New("ping timeout")

func formatRTT(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.3f µs", float64(d.Nanoseconds())/1000)
	}
	return fmt.Sprintf("%.3f ms", float64(d.Nanoseconds())/1e6)
}

func doPing(iface net.Interface, defaultDstIP net.IP, eth EthParams, ip4 IPv4Params, icmp ICMPv4Params) (time.Duration, error) {
	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return 0, err
	}

	var dstMAC net.HardwareAddr
	if eth.Dst != nil {
		dstMAC = eth.Dst
	} else {
		resolved, err := resolveMAC(iface, defaultDstIP)
		if err != nil {
			return 0, fmt.Errorf("resolving MAC for %s: %w", defaultDstIP, err)
		}
		dstMAC = resolved
	}

	devName, err := pcapDeviceName(iface)
	if err != nil {
		return 0, err
	}
	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	if err != nil {
		return 0, err
	}
	if err := handle.SetBPFFilter("icmp"); err != nil {
		handle.Close()
		return 0, fmt.Errorf("BPF filter: %w", err)
	}

	ethLayer := buildEthLayer(eth, iface.HardwareAddr, dstMAC, layers.EthernetTypeIPv4)
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
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			pkt, err := src.NextPacket()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if err != nil {
				ch <- result{err: err}
				return
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
		fmt.Fprintln(os.Stderr, "usage: moto ping -t <target-ip> [-i interface] [-n count] [-src-ip ip] [-src-mac mac] [-dst-mac mac] [-id n] [-seq n] [-data bytes]")
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

	fmt.Printf("PING %s on %s\n", dstIP, iface.Name)
	var received int
	for i := 1; i <= *nFlag; i++ {
		loopICMP := icmp
		if *seqFlag != 0 {
			loopICMP.Seq = uint16(*seqFlag)
		} else {
			loopICMP.Seq = uint16(i)
		}
		loopICMP.HasSeq = true

		rtt, err := doPing(iface, dstIP, eth, ip4, loopICMP)
		if errors.Is(err, errPingTimeout) {
			fmt.Printf("Request timeout for icmp_seq=%d\n", loopICMP.Seq)
		} else if err != nil {
			if *srcMACStr != "" {
				return fmt.Errorf("%w\n(MAC spoofing is often blocked by the NIC driver — the packet was not sent)", err)
			}
			return err
		} else {
			received++
			fmt.Printf("reply from %s: icmp_seq=%d time=%s\n", dstIP, loopICMP.Seq, formatRTT(rtt))
		}
	}
	loss := (*nFlag - received) * 100 / *nFlag
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss\n", *nFlag, received, loss)
	return nil
}
