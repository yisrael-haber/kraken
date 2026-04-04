package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const pingReplyTimeout = 3 * time.Second

func formatRTT(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.3f µs", float64(d.Nanoseconds())/1000)
	}
	return fmt.Sprintf("%.3f ms", float64(d.Nanoseconds())/1e6)
}

// pcapDumper writes packets to a pcapng file.
// NgWriter uses an internal bufio.Writer, so Flush is called after each packet
// to ensure data reaches the OS before the next packet arrives.
type pcapDumper struct {
	mu     sync.Mutex
	f      *os.File
	writer *pcapgo.NgWriter
}

func newPcapDumper(path string, linkType layers.LinkType) (*pcapDumper, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w, err := pcapgo.NewNgWriter(f, linkType)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &pcapDumper{f: f, writer: w}, nil
}

// write appends a raw IPv4 packet to the pcapng file and flushes immediately.
func (d *pcapDumper) write(ipBytes []byte) {
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(ipBytes),
		Length:        len(ipBytes),
	}
	d.mu.Lock()
	_ = d.writer.WritePacket(ci, ipBytes)
	_ = d.writer.Flush()
	d.mu.Unlock()
}

func (d *pcapDumper) close() {
	d.mu.Lock()
	_ = d.writer.Flush()
	d.f.Close()
	d.mu.Unlock()
}

// adoptedNetstack is a per-adopted-IP userspace TCP/IP stack backed by gVisor.
// Inbound TCP frames arrive via injectInbound (called from the pcap capture
// loop in adopt.go). Outbound frames produced by the stack are read in
// runOutbound and written back to the wire via the shared pcap handle.
// The handle is the same one used by the ifaceListener; pcap separates
// read and write paths internally so concurrent use is safe.
type adoptedNetstack struct {
	ip    net.IP
	mac   net.HardwareAddr
	iface net.Interface
	handle *pcap.Handle

	s      *stack.Stack
	ep     *channel.Endpoint
	cancel context.CancelFunc

	mu           sync.RWMutex
	handlers     map[uint16]func(net.Conn)
	pingHandlers map[uint16]chan pingReply
	mod          packetMod

	dumper     *pcapDumper // nil if no capture requested
	ownsDumper bool        // true if this netstack created the dumper and must close it
}

// pingReply carries an ICMP echo reply received from the network.
type pingReply struct {
	seq        uint16
	receivedAt time.Time
}

func newAdoptedNetstack(ip net.IP, mac net.HardwareAddr, iface net.Interface, handle *pcap.Handle, capturePath string) (*adoptedNetstack, error) {
	ep := channel.New(256, 1500, tcpip.LinkAddress(mac))

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	const nicID = tcpip.NICID(1)
	if tcpipErr := s.CreateNIC(nicID, ep); tcpipErr != nil {
		return nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	ip4 := ip.To4()
	addr := tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
	if tcpipErr := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); tcpipErr != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %v", tcpipErr)
	}

	// Default route: send all outbound traffic through this NIC.
	// The actual Ethernet dst is resolved from the ARP cache in runOutbound.
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	ctx, cancel := context.WithCancel(context.Background())

	var dumper *pcapDumper
	if capturePath != "" {
		var err error
		dumper, err = newPcapDumper(capturePath, layers.LinkTypeRaw)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("open capture file: %w", err)
		}
		fmt.Printf("[capture] writing to %s\n", capturePath)
	}

	ns := &adoptedNetstack{
		ip:           ip,
		mac:          mac,
		iface:        iface,
		handle:       handle,
		s:            s,
		ep:           ep,
		cancel:       cancel,
		handlers:     make(map[uint16]func(net.Conn)),
		pingHandlers: make(map[uint16]chan pingReply),
		dumper:       dumper,
		ownsDumper:   dumper != nil,
	}

	// The TCP forwarder intercepts incoming SYNs and dispatches to handlers.
	fwd := tcp.NewForwarder(s, 0, 256, ns.handleForwarderRequest)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	go ns.runOutbound(ctx)
	return ns, nil
}

// handleForwarderRequest is called by the TCP forwarder for each new SYN.
// If a handler is registered for the destination port, the connection is
// completed and handed off; otherwise a RST is sent.
func (ns *adoptedNetstack) handleForwarderRequest(r *tcp.ForwarderRequest) {
	port := uint16(r.ID().LocalPort)

	ns.mu.RLock()
	handler, ok := ns.handlers[port]
	ns.mu.RUnlock()

	if !ok {
		r.Complete(true) // RST — no handler for this port
		return
	}

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	go handler(conn)
}

// injectInbound feeds a captured IPv4 packet into the gVisor stack.
// It is called from the adopt.go dispatch loop with the reassembled packet.
func (ns *adoptedNetstack) injectInbound(pkt gopacket.Packet) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ipBytes := append(ipLayer.LayerContents(), ipLayer.LayerPayload()...)

	// Record in connection log and capture file before injecting.
	globalConnLog.UpdateInbound(ns.ip, ipBytes)
	if ns.dumper != nil {
		ns.dumper.write(ipBytes)
	}

	buf := buffer.MakeWithData(ipBytes)
	pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
	defer pktBuf.DecRef()
	ns.ep.InjectInbound(ipv4.ProtocolNumber, pktBuf)
}

// resolveMAC returns the Ethernet address for dstIP. The ARP request is sent
// from the adopted IP/MAC so the remote host learns the correct mapping.
func (ns *adoptedNetstack) resolveMAC(dstIP net.IP) (net.HardwareAddr, error) {
	if mac, ok := globalARPCache.lookup(dstIP); ok {
		return mac, nil
	}
	devName, err := pcapDeviceName(ns.iface)
	if err != nil {
		return nil, err
	}
	mac, err := arpRequest(devName, ns.mac, ns.ip, dstIP)
	if err != nil {
		return nil, err
	}
	globalARPCache.set(dstIP, mac)
	return mac, nil
}

// runOutbound drains the stack's outbound queue, wraps each IP packet in an
// Ethernet frame, and writes it to the wire. If the destination MAC is not
// cached, a real ARP request is sent from the adopted IP before the frame
// goes out. This is where L3 header modifications can be applied before the
// frame leaves — the stack never touches the NIC directly.
func (ns *adoptedNetstack) runOutbound(ctx context.Context) {
	for {
		pkt := ns.ep.ReadContext(ctx)
		if pkt == nil {
			return // context cancelled — stop was called
		}

		view := pkt.ToView()
		ipBytes := make([]byte, view.Size())
		copy(ipBytes, view.AsSlice())
		view.Release()
		pkt.DecRef()

		if len(ipBytes) < 20 {
			continue
		}

		// Apply header overrides (L3/L4) before logging or sending.
		ns.mu.RLock()
		mod := ns.mod
		ns.mu.RUnlock()
		ipBytes = applyPacketMod(ipBytes, mod)

		// Record in connection log and capture file before sending to wire.
		globalConnLog.UpdateOutbound(ns.ip, ipBytes)
		if ns.dumper != nil {
			ns.dumper.write(ipBytes)
		}

		dstIP := net.IP(ipBytes[16:20])

		// L2: use EthDst override if set (skips ARP), otherwise ARP-resolve.
		var dstMAC net.HardwareAddr
		if mod.EthDst != nil {
			dstMAC = mod.EthDst
		} else {
			var err error
			dstMAC, err = ns.resolveMAC(dstIP)
			if err != nil {
				fmt.Printf("[netstack] ARP failed for %s: %v\n", dstIP, err)
				continue
			}
		}

		srcMAC := ns.mac
		if mod.EthSrc != nil {
			srcMAC = mod.EthSrc
		}

		buf := gopacket.NewSerializeBuffer()
		eth := layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, gopacket.Payload(ipBytes)); err != nil {
			continue
		}
		_ = ns.handle.WritePacketData(buf.Bytes())
	}
}

// listen registers handler as the TCP connection handler for port on this
// adopted IP. Incoming connections to that port are handed to handler as a
// net.Conn running in a new goroutine. Registering a second handler for the
// same port replaces the first.
func (ns *adoptedNetstack) listen(port uint16, handler func(net.Conn)) {
	ns.mu.Lock()
	ns.handlers[port] = handler
	ns.mu.Unlock()
}

// dial opens an outbound TCP connection from the adopted IP to remoteIP:port.
// The source address is the adopted IP; the source port is chosen by the stack.
// The returned conn is a standard net.Conn backed by the gVisor TCP stack.
// Outbound packets leave via runOutbound exactly like server-side traffic, so
// IP header fields are accessible for modification before they hit the wire.
func (ns *adoptedNetstack) dial(ctx context.Context, remoteIP net.IP, port uint16) (net.Conn, error) {
	ip4 := remoteIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("dial: IPv4 address required")
	}
	addr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}),
		Port: port,
	}
	return gonet.DialContextTCP(ctx, ns.s, addr, ipv4.ProtocolNumber)
}

// deliverICMPReply is called from the adopt.go dispatch loop when an ICMP
// echo reply arrives addressed to this adopted IP. It routes the reply to
// whichever ping() call is waiting on that ICMP identifier.
func (ns *adoptedNetstack) deliverICMPReply(id, seq uint16) {
	ns.mu.RLock()
	ch, ok := ns.pingHandlers[id]
	ns.mu.RUnlock()
	if ok {
		select {
		case ch <- pingReply{seq: seq, receivedAt: time.Now()}:
		default:
		}
	}
}

// ping sends count ICMP echo requests to dstIP from the adopted IP and prints
// per-reply RTT and a packet-loss summary. Requests go out via raw pcap so
// the adopted MAC appears as source; replies arrive via deliverICMPReply.
func (ns *adoptedNetstack) ping(ctx context.Context, dstIP net.IP, count int, icmpID uint16) error {
	ip4 := dstIP.To4()
	if ip4 == nil {
		return fmt.Errorf("ping: IPv4 address required")
	}

	dstMAC, err := ns.resolveMAC(dstIP)
	if err != nil {
		return fmt.Errorf("ping: ARP failed for %s: %w", dstIP, err)
	}

	replyCh := make(chan pingReply, 8)
	ns.mu.Lock()
	ns.pingHandlers[icmpID] = replyCh
	ns.mu.Unlock()
	defer func() {
		ns.mu.Lock()
		delete(ns.pingHandlers, icmpID)
		ns.mu.Unlock()
	}()

	fmt.Printf("PING %s from %s\n", dstIP, ns.ip)
	var received int
	for seq := 1; seq <= count; seq++ {
		ethLayer := buildEthLayer(EthParams{}, ns.mac, dstMAC, layers.EthernetTypeIPv4)
		ip4Layer := buildIPv4Layer(IPv4Params{}, ns.ip, dstIP, layers.IPProtocolICMPv4)
		icmpLayer := buildICMPv4Layer(ICMPv4Params{
			TypeCode:    layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			ID:          icmpID,
			Seq:         uint16(seq),
			HasTypeCode: true, HasID: true, HasSeq: true,
		})

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, &ethLayer, &ip4Layer, &icmpLayer); err != nil {
			return err
		}
		sentAt := time.Now()
		if err := ns.handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}

		deadline := time.NewTimer(pingReplyTimeout)
	wait:
		for {
			select {
			case reply := <-replyCh:
				if reply.seq == uint16(seq) {
					received++
					fmt.Printf("reply from %s: icmp_seq=%d time=%s\n", dstIP, seq, formatRTT(reply.receivedAt.Sub(sentAt)))
					deadline.Stop()
					break wait
				}
				// Late reply for an earlier seq — discard.
			case <-deadline.C:
				fmt.Printf("Request timeout for icmp_seq=%d\n", seq)
				break wait
			case <-ctx.Done():
				deadline.Stop()
				return ctx.Err()
			}
		}
	}

	loss := (count - received) * 100 / count
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss\n", count, received, loss)
	return nil
}

// setMod replaces the outbound packet modifier. An empty packetMod clears
// all overrides. Safe to call concurrently.
func (ns *adoptedNetstack) setMod(mod packetMod) {
	ns.mu.Lock()
	ns.mod = mod
	ns.mu.Unlock()
}

// injectInboundRaw feeds a raw IPv4 byte slice directly into the gVisor stack.
// Unlike injectInbound it skips connection logging and pcap capture, making it
// suitable for swap sessions whose dummy IPs must not appear in the conn log.
func (ns *adoptedNetstack) injectInboundRaw(ipBytes []byte) {
	buf := buffer.MakeWithData(ipBytes)
	pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
	defer pktBuf.DecRef()
	ns.ep.InjectInbound(ipv4.ProtocolNumber, pktBuf)
}

// setDumper attaches an externally-owned pcapDumper to this netstack.
// The caller is responsible for closing it; stop() will not.
func (ns *adoptedNetstack) setDumper(d *pcapDumper) {
	ns.mu.Lock()
	ns.dumper = d
	ns.ownsDumper = false
	ns.mu.Unlock()
}

// stop shuts down the stack and its outbound goroutine.
func (ns *adoptedNetstack) stop() {
	ns.cancel()
	ns.s.Close()
	if ns.ownsDumper && ns.dumper != nil {
		ns.dumper.close()
	}
}
