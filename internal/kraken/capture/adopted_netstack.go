package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	adoptedNetstackNICID         = tcpip.NICID(1)
	adoptedNetstackOutboundDepth = 256
	adoptedNetstackDefaultMTU    = 1500
)

type adoptedNetstackConfig struct {
	ifaceName      string
	ip             net.IP
	mac            net.HardwareAddr
	defaultGateway net.IP
	routes         []net.IPNet
}

type adoptedNetstack struct {
	config adoptedNetstackConfig

	stack    *stack.Stack
	channel  *channel.Endpoint
	observer *inboundPacketObserver

	cancel context.CancelFunc
	done   chan struct{}
}

type inboundPacketObserver struct {
	targetIP compactIPv4
	record   func(activityLogRecord)
}

type compactIPv4 struct {
	addr  [net.IPv4len]byte
	valid bool
}

type compactMAC struct {
	addr  [6]byte
	valid bool
}

type activityLogRecord struct {
	identity  adoption.Identity
	direction string
	protocol  string
	event     string
	status    string
	details   string
	peerIP    compactIPv4
	peerMAC   compactMAC
	icmpID    uint16
	icmpSeq   uint16
	rtt       time.Duration
}

func (observer *inboundPacketObserver) HandlePacket(_ tcpip.NICID, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if observer == nil || observer.record == nil || pkt == nil || pkt.PktType == tcpip.PacketOutgoing {
		return
	}

	record, ok := classifyInboundPacket(pkt, observer.targetIP)
	if !ok {
		return
	}

	observer.record(record)
}

func newAdoptedNetstack(config adoptedNetstackConfig, outbound func(*stack.PacketBuffer) error, observeInbound func(activityLogRecord)) (*adoptedNetstack, error) {
	if common.NormalizeIPv4(config.ip) == nil {
		return nil, fmt.Errorf("netstack requires a valid IPv4 address")
	}
	if len(config.mac) == 0 {
		return nil, fmt.Errorf("netstack requires a hardware address")
	}
	if outbound == nil {
		return nil, fmt.Errorf("netstack requires an outbound handler")
	}

	linkEP := channel.New(adoptedNetstackOutboundDepth, adoptedNetstackMTU(config.ifaceName), tcpip.LinkAddress(config.mac))
	stackEP := ethernet.New(linkEP)
	netstack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			arp.NewProtocol,
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			icmp.NewProtocol4,
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		RawFactory:               raw.EndpointFactory{},
		AllowPacketEndpointWrite: true,
	})

	if err := netstack.CreateNICWithOptions(adoptedNetstackNICID, stackEP, stack.NICOptions{
		Name:               config.ifaceName,
		DeliverLinkPackets: true,
	}); err != nil {
		return nil, fmt.Errorf("create netstack NIC: %s", err)
	}

	localAddr := tcpip.AddrFrom4Slice(config.ip.To4())
	if err := netstack.AddProtocolAddress(adoptedNetstackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: localAddr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("assign adopted IPv4 address: %s", err)
	}

	routes, err := buildNetstackRoutes(config.routes, config.defaultGateway)
	if err != nil {
		return nil, err
	}
	netstack.SetRouteTable(routes)

	ctx, cancel := context.WithCancel(context.Background())
	item := &adoptedNetstack{
		config:  cloneAdoptedNetstackConfig(config),
		stack:   netstack,
		channel: linkEP,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	if observeInbound != nil {
		item.observer = &inboundPacketObserver{
			targetIP: compactIPv4FromIP(config.ip),
			record:   observeInbound,
		}
		if err := netstack.RegisterPacketEndpoint(adoptedNetstackNICID, header.EthernetProtocolAll, item.observer); err != nil {
			netstack.Close()
			netstack.Wait()
			cancel()
			return nil, fmt.Errorf("register packet observer: %s", err)
		}
	}
	go item.runOutbound(ctx, outbound)

	return item, nil
}

func adoptedNetstackMTU(ifaceName string) uint32 {
	if iface, err := net.InterfaceByName(ifaceName); err == nil && iface.MTU > 0 {
		return uint32(iface.MTU)
	}
	return adoptedNetstackDefaultMTU
}

func cloneAdoptedNetstackConfig(config adoptedNetstackConfig) adoptedNetstackConfig {
	clonedRoutes := make([]net.IPNet, 0, len(config.routes))
	for _, route := range config.routes {
		clonedRoutes = append(clonedRoutes, net.IPNet{
			IP:   common.CloneIPv4(route.IP),
			Mask: append(net.IPMask(nil), route.Mask...),
		})
	}

	return adoptedNetstackConfig{
		ifaceName:      config.ifaceName,
		ip:             common.CloneIPv4(config.ip),
		mac:            common.CloneHardwareAddr(config.mac),
		defaultGateway: common.CloneIPv4(config.defaultGateway),
		routes:         clonedRoutes,
	}
}

func compactIPv4FromIP(ip net.IP) compactIPv4 {
	ipv4 := common.NormalizeIPv4(ip)
	if ipv4 == nil {
		return compactIPv4{}
	}

	var addr [net.IPv4len]byte
	copy(addr[:], ipv4)
	return compactIPv4{
		addr:  addr,
		valid: true,
	}
}

func compactIPv4FromSlice(raw []byte) compactIPv4 {
	if len(raw) < net.IPv4len {
		return compactIPv4{}
	}

	var addr [net.IPv4len]byte
	copy(addr[:], raw[:net.IPv4len])
	return compactIPv4{
		addr:  addr,
		valid: true,
	}
}

func compactIPv4FromAddress(addr tcpip.Address) compactIPv4 {
	if addr.BitLen() != net.IPv4len*8 {
		return compactIPv4{}
	}

	return compactIPv4FromSlice(addr.AsSlice())
}

func (ip compactIPv4) IP() net.IP {
	if !ip.valid {
		return nil
	}

	return net.IPv4(ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]).To4()
}

func compactMACFromSlice(raw []byte) compactMAC {
	if len(raw) < 6 {
		return compactMAC{}
	}

	var addr [6]byte
	copy(addr[:], raw[:6])
	return compactMAC{
		addr:  addr,
		valid: true,
	}
}

func (mac compactMAC) HardwareAddr() net.HardwareAddr {
	if !mac.valid {
		return nil
	}

	addr := make(net.HardwareAddr, len(mac.addr))
	copy(addr, mac.addr[:])
	return addr
}

func (netstack *adoptedNetstack) matches(identity adoption.Identity, routes []net.IPNet) bool {
	if netstack == nil || identity == nil {
		return false
	}

	if netstack.config.ifaceName != identity.Interface().Name {
		return false
	}
	if !bytes.Equal(common.NormalizeIPv4(netstack.config.ip), common.NormalizeIPv4(identity.IP())) {
		return false
	}
	if !bytes.Equal(netstack.config.mac, identity.MAC()) {
		return false
	}
	if !bytes.Equal(common.NormalizeIPv4(netstack.config.defaultGateway), common.NormalizeIPv4(identity.DefaultGateway())) {
		return false
	}
	if len(netstack.config.routes) != len(routes) {
		return false
	}
	for index := range routes {
		if !netstack.config.routes[index].IP.Equal(routes[index].IP) {
			return false
		}
		if !bytes.Equal(netstack.config.routes[index].Mask, routes[index].Mask) {
			return false
		}
	}

	return true
}

func (netstack *adoptedNetstack) close() {
	if netstack == nil {
		return
	}

	if netstack.observer != nil {
		netstack.stack.UnregisterPacketEndpoint(adoptedNetstackNICID, header.EthernetProtocolAll, netstack.observer)
	}
	netstack.cancel()
	netstack.channel.Close()
	<-netstack.done
	netstack.stack.Close()
	netstack.stack.Wait()
}

func (netstack *adoptedNetstack) arpCacheSnapshot() []adoption.ARPCacheItem {
	if netstack == nil {
		return nil
	}

	entries, err := netstack.stack.Neighbors(adoptedNetstackNICID, ipv4.ProtocolNumber)
	if err != nil {
		return nil
	}

	items := make([]adoption.ARPCacheItem, 0, len(entries))
	for _, entry := range entries {
		if entry.Addr.BitLen() != net.IPv4len*8 || entry.LinkAddr == "" {
			continue
		}

		addr := entry.Addr.As4()

		items = append(items, adoption.ARPCacheItem{
			IP:        net.IP(addr[:]).String(),
			MAC:       net.HardwareAddr(entry.LinkAddr).String(),
			UpdatedAt: "",
		})
	}

	return items
}

type netstackPingReply struct {
	id       uint16
	sequence uint16
	success  bool
	rtt      time.Duration
}

func (netstack *adoptedNetstack) ping(targetIP net.IP, count int, payload []byte, timeout time.Duration) ([]netstackPingReply, error) {
	targetIP = common.NormalizeIPv4(targetIP)
	if netstack == nil || targetIP == nil {
		return nil, fmt.Errorf("a valid IPv4 target is required")
	}
	if count <= 0 {
		return nil, fmt.Errorf("ping count must be positive")
	}

	endpoint, wq, pingID, err := netstack.newPingEndpoint(targetIP)
	if err != nil {
		return nil, err
	}
	defer endpoint.Close()

	replies := make([]netstackPingReply, 0, count)
	for sequence := 1; sequence <= count; sequence++ {
		reply := netstackPingReply{
			id:       pingID,
			sequence: uint16(sequence),
		}

		if err := writeICMPEchoRequest(endpoint, reply.sequence, payload); err != nil {
			return replies, err
		}

		sentAt := time.Now()
		rtt, ok, err := waitForICMPEchoReply(endpoint, wq, reply.sequence, sentAt, timeout)
		if err != nil {
			replies = append(replies, reply)
			return replies, err
		}
		reply.success = ok
		reply.rtt = rtt
		replies = append(replies, reply)
	}

	return replies, nil
}

func (netstack *adoptedNetstack) newPingEndpoint(targetIP net.IP) (tcpip.Endpoint, *waiter.Queue, uint16, error) {
	var wq waiter.Queue

	endpoint, err := netstack.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("create ICMP endpoint: %s", err)
	}

	localAddress := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(netstack.config.ip.To4()),
	}
	if err := endpoint.Bind(localAddress); err != nil {
		endpoint.Close()
		return nil, nil, 0, fmt.Errorf("bind ICMP endpoint: %s", err)
	}

	remoteAddress := tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(targetIP.To4()),
	}
	if err := endpoint.Connect(remoteAddress); err != nil {
		endpoint.Close()
		return nil, nil, 0, fmt.Errorf("connect ICMP endpoint: %s", err)
	}

	boundAddress, err := endpoint.GetLocalAddress()
	if err != nil {
		endpoint.Close()
		return nil, nil, 0, fmt.Errorf("get ICMP endpoint address: %s", err)
	}

	return endpoint, &wq, boundAddress.Port, nil
}

func (netstack *adoptedNetstack) injectFrame(frame []byte) {
	if netstack == nil || len(frame) == 0 {
		return
	}

	clonedFrame := append([]byte(nil), frame...)
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(clonedFrame),
	})
	defer packet.DecRef()

	netstack.channel.InjectInbound(0, packet)
}

func (netstack *adoptedNetstack) runOutbound(ctx context.Context, outbound func(*stack.PacketBuffer) error) {
	defer close(netstack.done)

	for {
		packet := netstack.channel.ReadContext(ctx)
		if packet == nil {
			return
		}

		if err := outbound(packet); err != nil {
			packet.DecRef()
			continue
		}
		packet.DecRef()
	}
}

func buildNetstackRoutes(routes []net.IPNet, defaultGateway net.IP) ([]tcpip.Route, error) {
	items := make([]tcpip.Route, 0, len(routes)+1)
	for _, route := range routes {
		subnet, ok := ipNetToTCPIPSubnet(route)
		if !ok {
			continue
		}
		items = append(items, tcpip.Route{
			Destination: subnet,
			NIC:         adoptedNetstackNICID,
		})
	}

	gateway := common.NormalizeIPv4(defaultGateway)
	if gateway != nil {
		items = append(items, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			Gateway:     tcpip.AddrFrom4Slice(gateway.To4()),
			NIC:         adoptedNetstackNICID,
		})
	} else if len(items) == 0 {
		items = append(items, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         adoptedNetstackNICID,
		})
	}

	return items, nil
}

func ipNetToTCPIPSubnet(route net.IPNet) (tcpip.Subnet, bool) {
	ip := common.NormalizeIPv4(route.IP)
	if ip == nil || len(route.Mask) != net.IPv4len {
		return tcpip.Subnet{}, false
	}

	subnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4Slice(ip.Mask(route.Mask)),
		tcpip.MaskFromBytes(route.Mask),
	)
	if err != nil {
		return tcpip.Subnet{}, false
	}

	return subnet, true
}

type outboundFrameInfo struct {
	protocol  string
	targetIP  net.IP
	targetMAC net.HardwareAddr
	event     string
	icmpID    uint16
	icmpSeq   uint16
}

func classifyInboundPacket(packet *stack.PacketBuffer, targetIP compactIPv4) (activityLogRecord, bool) {
	if packet == nil || !targetIP.valid {
		return activityLogRecord{}, false
	}

	switch packet.NetworkProtocolNumber {
	case arp.ProtocolNumber:
		network := packet.NetworkHeader().Slice()
		if len(network) < header.ARPSize {
			return activityLogRecord{}, false
		}

		arpPacket := header.ARP(network)
		if !arpPacket.IsValid() {
			return activityLogRecord{}, false
		}

		peerIP := compactIPv4FromSlice(arpPacket.ProtocolAddressSender())
		packetTarget := compactIPv4FromSlice(arpPacket.ProtocolAddressTarget())
		if !packetTarget.valid || packetTarget != targetIP {
			return activityLogRecord{}, false
		}

		record := activityLogRecord{
			direction: "inbound",
			protocol:  "arp",
			peerIP:    peerIP,
			peerMAC:   compactMACFromSlice(arpPacket.HardwareAddressSender()),
		}
		switch arpPacket.Op() {
		case header.ARPRequest:
			record.event = "recv-request"
		case header.ARPReply:
			record.event = "recv-reply"
		default:
			return activityLogRecord{}, false
		}
		return record, true

	case ipv4.ProtocolNumber:
		network := packet.NetworkHeader().Slice()
		if len(network) == 0 {
			return activityLogRecord{}, false
		}

		ipv4Packet := header.IPv4(network)
		if !ipv4Packet.IsValid(len(network)) {
			return activityLogRecord{}, false
		}
		if packet.TransportProtocolNumber != header.ICMPv4ProtocolNumber {
			return activityLogRecord{}, false
		}

		packetTarget := compactIPv4FromAddress(ipv4Packet.DestinationAddress())
		if !packetTarget.valid || packetTarget != targetIP {
			return activityLogRecord{}, false
		}

		transport := packet.TransportHeader().Slice()
		if len(transport) < header.ICMPv4MinimumSize {
			transport = ipv4Packet.Payload()
			if len(transport) < header.ICMPv4MinimumSize {
				return activityLogRecord{}, false
			}
		}

		icmpPacket := header.ICMPv4(transport)
		if icmpPacket.Type() != header.ICMPv4Echo {
			return activityLogRecord{}, false
		}

		return activityLogRecord{
			direction: "inbound",
			protocol:  "icmpv4",
			event:     "recv-echo-request",
			status:    "received",
			peerIP:    compactIPv4FromAddress(ipv4Packet.SourceAddress()),
			icmpID:    icmpPacket.Ident(),
			icmpSeq:   icmpPacket.Sequence(),
		}, true
	}

	return activityLogRecord{}, false
}

func classifyOutboundPacketBuffer(packet *stack.PacketBuffer) activityLogRecord {
	record := activityLogRecord{
		direction: "outbound",
	}
	if packet == nil {
		return record
	}

	if link := packet.LinkHeader().Slice(); len(link) >= header.EthernetMinimumSize {
		record.peerMAC = compactMACFromSlice([]byte(header.Ethernet(link).DestinationAddress()))
	}

	switch packet.NetworkProtocolNumber {
	case arp.ProtocolNumber:
		network := packet.NetworkHeader().Slice()
		if len(network) < header.ARPSize {
			return record
		}

		arpPacket := header.ARP(network)
		if !arpPacket.IsValid() {
			return record
		}

		record.protocol = "arp"
		record.peerIP = compactIPv4FromSlice(arpPacket.ProtocolAddressTarget())
		if !record.peerMAC.valid {
			record.peerMAC = compactMACFromSlice(arpPacket.HardwareAddressTarget())
		}
		switch arpPacket.Op() {
		case header.ARPRequest:
			record.event = "send-request"
		case header.ARPReply:
			record.event = "send-reply"
		}

	case ipv4.ProtocolNumber:
		network := packet.NetworkHeader().Slice()
		if len(network) == 0 {
			return record
		}

		ipv4Packet := header.IPv4(network)
		if !ipv4Packet.IsValid(len(network)) {
			return record
		}

		record.protocol = "ipv4"
		record.peerIP = compactIPv4FromAddress(ipv4Packet.DestinationAddress())
		if packet.TransportProtocolNumber != header.ICMPv4ProtocolNumber {
			return record
		}

		transport := packet.TransportHeader().Slice()
		if len(transport) < header.ICMPv4MinimumSize {
			transport = ipv4Packet.Payload()
			if len(transport) < header.ICMPv4MinimumSize {
				return record
			}
		}

		icmpPacket := header.ICMPv4(transport)
		record.protocol = "icmpv4"
		record.icmpID = icmpPacket.Ident()
		record.icmpSeq = icmpPacket.Sequence()
		switch icmpPacket.Type() {
		case header.ICMPv4Echo:
			record.event = "send-echo-request"
		case header.ICMPv4EchoReply:
			record.event = "send-echo-reply"
		}
	}

	return record
}

func appendPacketBufferTo(dst []byte, packet *stack.PacketBuffer) []byte {
	if packet == nil {
		return dst[:0]
	}

	total := len(dst) + packet.Size()
	if cap(dst) < total {
		expanded := make([]byte, len(dst), total)
		copy(expanded, dst)
		dst = expanded
	}

	position := len(dst)
	dst = dst[:total]
	views, offset := packet.AsViewList()
	for view := views.Front(); view != nil; view = view.Next() {
		raw := view.AsSlice()
		if offset >= len(raw) {
			offset -= len(raw)
			continue
		}
		raw = raw[offset:]
		offset = 0
		position += copy(dst[position:], raw)
	}

	return dst[:position]
}

func activityRecordFromOutboundInfo(identity adoption.Identity, info outboundFrameInfo, status, details string) activityLogRecord {
	return activityLogRecord{
		identity:  identity,
		direction: "outbound",
		protocol:  info.protocol,
		event:     info.event,
		status:    status,
		details:   details,
		peerIP:    compactIPv4FromIP(info.targetIP),
		peerMAC:   compactMACFromSlice(info.targetMAC),
		icmpID:    info.icmpID,
		icmpSeq:   info.icmpSeq,
	}
}

var errPingReadTimeout = errors.New("timed out waiting for ICMP reply")

func writeICMPEchoRequest(endpoint tcpip.Endpoint, sequence uint16, payload []byte) error {
	message := make([]byte, header.ICMPv4MinimumSize+len(payload))
	icmpMessage := header.ICMPv4(message)
	icmpMessage.SetType(header.ICMPv4Echo)
	icmpMessage.SetCode(header.ICMPv4UnusedCode)
	icmpMessage.SetSequence(sequence)
	copy(icmpMessage.Payload(), payload)

	if _, err := endpoint.Write(bytes.NewReader(message), tcpip.WriteOptions{}); err != nil {
		return fmt.Errorf("write ICMP echo request: %s", err)
	}

	return nil
}

func waitForICMPEchoReply(endpoint tcpip.Endpoint, wq *waiter.Queue, sequence uint16, sentAt time.Time, timeout time.Duration) (time.Duration, bool, error) {
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 2048)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, false, nil
		}

		count, err := readEndpointWithTimeout(endpoint, wq, buffer, remaining)
		if err != nil {
			if errors.Is(err, errPingReadTimeout) {
				return 0, false, nil
			}
			return 0, false, err
		}
		if count < header.ICMPv4MinimumSize {
			continue
		}

		icmpMessage := header.ICMPv4(buffer[:count])
		if icmpMessage.Type() != header.ICMPv4EchoReply || icmpMessage.Sequence() != sequence {
			continue
		}

		return time.Since(sentAt), true, nil
	}
}

func readEndpointWithTimeout(endpoint tcpip.Endpoint, wq *waiter.Queue, dst []byte, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		return 0, errPingReadTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	options := tcpip.ReadOptions{}
	reader := func() (int, tcpip.Error) {
		writer := tcpip.SliceWriter(dst)
		result, err := endpoint.Read(&writer, options)
		if err != nil {
			return 0, err
		}
		return result.Count, nil
	}

	count, err := reader()
	if _, wouldBlock := err.(*tcpip.ErrWouldBlock); wouldBlock {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)

		for {
			count, err = reader()
			if _, wouldBlock := err.(*tcpip.ErrWouldBlock); !wouldBlock {
				break
			}

			select {
			case <-timer.C:
				return 0, errPingReadTimeout
			case <-notifyCh:
			}
		}
	}

	if _, closed := err.(*tcpip.ErrClosedForReceive); closed {
		return 0, io.EOF
	}
	if err != nil {
		return 0, errors.New(err.String())
	}

	return count, nil
}

func parseScriptablePacket(frame []byte) (*packetpkg.OutboundPacket, error) {
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)

	ethernetLayer, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if ethernetLayer == nil {
		return nil, fmt.Errorf("missing ethernet header")
	}

	outbound := &packetpkg.OutboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       common.CloneHardwareAddr(ethernetLayer.SrcMAC),
			DstMAC:       common.CloneHardwareAddr(ethernetLayer.DstMAC),
			EthernetType: ethernetLayer.EthernetType,
			Length:       ethernetLayer.Length,
		},
	}

	if arpLayer, _ := packet.Layer(layers.LayerTypeARP).(*layers.ARP); arpLayer != nil {
		outbound.ARP = &layers.ARP{
			AddrType:          arpLayer.AddrType,
			Protocol:          arpLayer.Protocol,
			HwAddressSize:     arpLayer.HwAddressSize,
			ProtAddressSize:   arpLayer.ProtAddressSize,
			Operation:         arpLayer.Operation,
			SourceHwAddress:   append([]byte(nil), arpLayer.SourceHwAddress...),
			SourceProtAddress: append([]byte(nil), arpLayer.SourceProtAddress...),
			DstHwAddress:      append([]byte(nil), arpLayer.DstHwAddress...),
			DstProtAddress:    append([]byte(nil), arpLayer.DstProtAddress...),
		}
		return outbound, nil
	}

	ipv4Layer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipv4Layer == nil {
		return nil, fmt.Errorf("missing IPv4 header")
	}

	outbound.IPv4 = &layers.IPv4{
		Version:    ipv4Layer.Version,
		IHL:        ipv4Layer.IHL,
		TOS:        ipv4Layer.TOS,
		Length:     ipv4Layer.Length,
		Id:         ipv4Layer.Id,
		Flags:      ipv4Layer.Flags,
		FragOffset: ipv4Layer.FragOffset,
		TTL:        ipv4Layer.TTL,
		Protocol:   ipv4Layer.Protocol,
		Checksum:   ipv4Layer.Checksum,
		SrcIP:      common.CloneIPv4(ipv4Layer.SrcIP),
		DstIP:      common.CloneIPv4(ipv4Layer.DstIP),
		Options:    append([]layers.IPv4Option(nil), ipv4Layer.Options...),
		Padding:    append([]byte(nil), ipv4Layer.Padding...),
	}

	if icmpLayer, _ := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); icmpLayer != nil {
		outbound.ICMPv4 = &layers.ICMPv4{
			TypeCode: icmpLayer.TypeCode,
			Checksum: icmpLayer.Checksum,
			Id:       icmpLayer.Id,
			Seq:      icmpLayer.Seq,
		}
		outbound.Payload = append([]byte(nil), icmpLayer.Payload...)
		return outbound, nil
	}

	if app := packet.ApplicationLayer(); app != nil {
		outbound.Payload = append([]byte(nil), app.Payload()...)
		return outbound, nil
	}

	if len(ipv4Layer.Payload) != 0 {
		outbound.Payload = append([]byte(nil), ipv4Layer.Payload...)
	}

	return outbound, nil
}

func (listener *pcapAdoptionListener) handleNetstackOutbound(sourceIP net.IP, packet *stack.PacketBuffer) error {
	sourceIP = common.NormalizeIPv4(sourceIP)
	if sourceIP == nil || packet == nil {
		return nil
	}

	identity, exists := listener.lookup(sourceIP)
	if !exists {
		return nil
	}

	record := classifyOutboundPacketBuffer(packet)
	record.identity = identity

	buffer := listener.takeSerializeScratch(packet.Size())
	frame := appendPacketBufferTo(buffer[:0], packet)
	defer listener.releaseSerializeScratch(frame[:0])

	script := buildBoundPacketScript(identity)
	if script.ctx.ScriptName == "" {
		if err := listener.writePacket(frame); err != nil {
			record.status = "error"
			record.details = err.Error()
			listener.enqueueActivity(record)
			return err
		}
		record.status = "sent"
		listener.enqueueActivity(record)
		return nil
	}

	outbound, err := parseScriptablePacket(frame)
	if err != nil {
		record.status = "error"
		record.details = err.Error()
		listener.enqueueActivity(record)
		return err
	}
	if err := listener.applyBoundScript(outbound, script.ctx); err != nil {
		record.status = "error"
		record.details = err.Error()
		listener.enqueueActivity(record)
		return err
	}
	if err := listener.writePreparedPacket(outbound); err != nil {
		record.status = "error"
		record.details = err.Error()
		listener.enqueueActivity(record)
		return err
	}

	finalInfo := classifyOutboundPacket(outbound)
	listener.enqueueActivity(activityRecordFromOutboundInfo(identity, finalInfo, "sent", ""))
	return nil
}

func classifyOutboundPacket(packet *packetpkg.OutboundPacket) outboundFrameInfo {
	if packet == nil {
		return outboundFrameInfo{}
	}

	info := outboundFrameInfo{}

	if packet.Ethernet != nil {
		info.targetMAC = common.CloneHardwareAddr(packet.Ethernet.DstMAC)
	}
	if packet.ARP != nil {
		info.protocol = "arp"
		info.targetIP = common.NormalizeIPv4(net.IP(packet.ARP.DstProtAddress))
		switch packet.ARP.Operation {
		case uint16(layers.ARPRequest):
			info.event = "send-request"
		case uint16(layers.ARPReply):
			info.event = "send-reply"
		}
		return info
	}
	if packet.IPv4 != nil {
		info.protocol = "ipv4"
		info.targetIP = common.NormalizeIPv4(packet.IPv4.DstIP)
	}
	if packet.ICMPv4 != nil {
		info.protocol = "icmpv4"
		info.icmpID = packet.ICMPv4.Id
		info.icmpSeq = packet.ICMPv4.Seq
		switch packet.ICMPv4.TypeCode.Type() {
		case layers.ICMPv4TypeEchoRequest:
			info.event = "send-echo-request"
		case layers.ICMPv4TypeEchoReply:
			info.event = "send-echo-reply"
		}
	}

	return info
}
