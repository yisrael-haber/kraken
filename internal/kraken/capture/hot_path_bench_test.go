package capture

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type benchmarkForwardingListener struct {
	forwardingProbeListener
}

func (listener *benchmarkForwardingListener) InjectFrame([]byte) error {
	listener.injected++
	return nil
}

func (listener *benchmarkForwardingListener) RouteFrame(adoption.Identity, routingpkg.StoredRoute, []byte) error {
	listener.routed++
	return nil
}

func BenchmarkClassifyInboundFrameARP(b *testing.B) {
	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildARPRequestPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		_, _ = classifyInboundFrame(frame)
	}
}

func BenchmarkClassifyInboundFrameICMP(b *testing.B) {
	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		_, _ = classifyInboundFrame(frame)
	}
}

func BenchmarkAppendPacketBufferTo(b *testing.B) {
	packet := benchmarkContiguousTCPPacket(8080, 50505, []byte("hello"))
	defer packet.DecRef()

	b.Run("pooled", func(b *testing.B) {
		frame := make([]byte, 0, packet.Size())
		b.ReportAllocs()
		b.SetBytes(int64(packet.Size()))
		for i := 0; i < b.N; i++ {
			frame = appendPacketBufferTo(frame[:0], packet)
		}
	})

	b.Run("grow", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(packet.Size()))
		for i := 0; i < b.N; i++ {
			frame := appendPacketBufferTo(nil, packet)
			if len(frame) != packet.Size() {
				b.Fatalf("expected frame size %d, got %d", packet.Size(), len(frame))
			}
		}
	})
}

func BenchmarkPacketBufferSlice(b *testing.B) {
	packet := benchmarkContiguousRawPacket([]byte("hello"))
	defer packet.DecRef()

	b.ReportAllocs()
	b.SetBytes(int64(packet.Size()))
	for i := 0; i < b.N; i++ {
		frame, ok := packetBufferSlice(packet)
		if !ok || len(frame) != packet.Size() {
			b.Fatalf("expected contiguous packet buffer slice")
		}
	}
}

func BenchmarkIdentityForSourceAddress(b *testing.B) {
	group := &adoptedEngineGroup{
		identities: map[compactIPv4]adoption.Identity{
			compactIPv4FromIP(net.IPv4(192, 168, 56, 10)): fakeIdentity{
				label: "bench",
				ip:    net.IPv4(192, 168, 56, 10),
				mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
			},
		},
		managedHTTPPorts: make(map[uint16]int),
	}
	group.identitiesV.Store(cloneIdentitySnapshot(group.identities))
	group.managedHTTPPortsV.Store(make(map[uint16]int))
	group.peersV.Store(make(map[compactIPv4]compactMAC))
	address := tcpip.AddrFrom4Slice(net.IPv4(192, 168, 56, 10).To4())
	packet := benchmarkARPPacket(
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.IPv4(192, 168, 56, 1),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	)
	defer packet.DecRef()

	b.Run("ipv4-address", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := group.identityForSourceAddress(address, nil); !ok {
				b.Fatal("expected identity lookup to succeed")
			}
		}
	})

	b.Run("arp-header", func(b *testing.B) {
		var zeroAddress tcpip.Address
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := group.identityForSourceAddress(zeroAddress, packet); !ok {
				b.Fatal("expected ARP identity lookup to succeed")
			}
		}
	})
}

func BenchmarkIsManagedHTTPPacket(b *testing.B) {
	packet := benchmarkContiguousTCPPacket(8080, 50505, nil)
	defer packet.DecRef()

	b.Run("miss-no-managed-ports", func(b *testing.B) {
		group := &adoptedEngineGroup{managedHTTPPorts: make(map[uint16]int)}
		group.managedHTTPPortsV.Store(make(map[uint16]int))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if group.isManagedHTTPPacket(packet) {
				b.Fatal("expected no managed HTTP match")
			}
		}
	})

	b.Run("hit", func(b *testing.B) {
		group := &adoptedEngineGroup{managedHTTPPorts: map[uint16]int{8080: 1}}
		group.managedHTTPPortsV.Store(cloneManagedHTTPPortSnapshot(group.managedHTTPPorts))
		group.managedHTTPPortCount.Store(1)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !group.isManagedHTTPPacket(packet) {
				b.Fatal("expected managed HTTP match")
			}
		}
	})
}

func BenchmarkMaterializeScriptHTTPRequest(b *testing.B) {
	body := bytes.Repeat([]byte("payload="), 32)
	template := httptest.NewRequest("POST", "http://example.test/upload?q=1", nil)
	template.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	template.Header.Set("X-Test", "bench")

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		request := *template
		request.Body = io.NopCloser(bytes.NewReader(body))
		if _, err := materializeScriptHTTPRequest(&request); err != nil {
			b.Fatalf("materialize request: %v", err)
		}
	}
}

func BenchmarkRememberPeerStable(b *testing.B) {
	group, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, func(_ *adoptedEngineGroup, pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	if err != nil {
		b.Fatalf("new adopted engine group: %v", err)
	}
	defer group.close()

	ip := compactIPv4FromIP(net.IPv4(192, 168, 56, 20))
	mac := compactMACFromSlice([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		group.rememberPeer(ip, mac)
	}
}

func BenchmarkDispatchInboundFrameICMP(b *testing.B) {
	outbound := 0
	group, identity := benchmarkInboundGroup(b, &outbound)
	defer group.close()

	listener := &pcapAdoptionListener{
		ipGroups: map[compactIPv4]*adoptedEngineGroup{compactIPv4FromIP(identity.ip): group},
	}
	listener.ipGroupsV.Store(cloneEngineGroupMap(listener.ipGroups))
	listener.groupsV.Store([]*adoptedEngineGroup{group})

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.ip,
		identity.mac,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))
	group.rememberPeer(
		compactIPv4FromIP(net.IPv4(192, 168, 56, 20)),
		compactMACFromSlice([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}),
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		listener.dispatchInboundFrame(frame)
	}
	if outbound == 0 {
		b.Fatal("expected inbound ICMP to trigger outbound work")
	}
}

func BenchmarkDispatchInboundFrameForwardedDirect(b *testing.B) {
	target := &benchmarkForwardingListener{}
	listener := &pcapAdoptionListener{
		forward: func(destinationIP net.IP) (adoption.ForwardingDecision, bool) {
			return adoption.ForwardingDecision{
				Listener: target,
				Identity: fakeIdentity{ip: destinationIP},
			}, true
		},
	}
	listener.ipGroupsV.Store(map[compactIPv4]*adoptedEngineGroup{})
	listener.groupsV.Store([]*adoptedEngineGroup(nil))

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		listener.dispatchInboundFrame(frame)
	}
	if target.injected == 0 {
		b.Fatal("expected direct forwarding work")
	}
}

func BenchmarkDispatchInboundFrameForwardedRoute(b *testing.B) {
	target := &benchmarkForwardingListener{}
	route := routingpkg.StoredRoute{
		Label:           "lab-segment",
		DestinationCIDR: "10.0.0.0/24",
		ViaAdoptedIP:    "192.168.56.10",
	}
	listener := &pcapAdoptionListener{
		forward: func(destinationIP net.IP) (adoption.ForwardingDecision, bool) {
			return adoption.ForwardingDecision{
				Listener: target,
				Identity: fakeIdentity{ip: net.IPv4(192, 168, 56, 10)},
				Route:    route,
				Routed:   true,
			}, destinationIP != nil
		},
	}
	listener.ipGroupsV.Store(map[compactIPv4]*adoptedEngineGroup{})
	listener.groupsV.Store([]*adoptedEngineGroup(nil))

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		listener.dispatchInboundFrame(frame)
	}
	if target.routed == 0 {
		b.Fatal("expected routed forwarding work")
	}
}

func BenchmarkInjectFrameICMP(b *testing.B) {
	outbound := 0
	group, identity := benchmarkInboundGroup(b, &outbound)
	defer group.close()

	frame := serializeBenchmarkOutboundPacket(b, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.ip,
		identity.mac,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))
	peerIP := compactIPv4FromIP(net.IPv4(192, 168, 56, 20))
	peerMAC := compactMACFromSlice([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x20})

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		group.rememberPeer(peerIP, peerMAC)
		group.injectFrame(frame)
	}
	if outbound == 0 {
		b.Fatal("expected inbound ICMP to trigger outbound work")
	}
}

func BenchmarkApplyScriptHTTPRequest(b *testing.B) {
	body := bytes.Repeat([]byte("rewritten"), 16)
	scriptRequest := scriptpkg.HTTPRequest{
		Method:  "POST",
		Target:  "/rewrite?q=2",
		Version: "HTTP/1.1",
		Host:    "example.test",
		Headers: []scriptpkg.HTTPHeader{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Content-Length", Value: "144"},
			{Name: "X-Test", Value: "bench"},
		},
		Body: body,
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	template := httptest.NewRequest("GET", "http://example.test/", nil)
	for i := 0; i < b.N; i++ {
		request := *template
		if err := applyScriptHTTPRequest(&request, scriptRequest); err != nil {
			b.Fatalf("apply request: %v", err)
		}
	}
}

func BenchmarkHTTPServiceHandlerResponseOnly(b *testing.B) {
	binding := benchmarkHTTPServiceScriptBinding(b, `def on_response(request, response, ctx):
    return None
`)
	managed := newManagedTCPService(tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, nil, nil)
	handler := newHTTPServiceHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.Copy(io.Discard, request.Body)
		_, _ = writer.Write([]byte("ok"))
	}), fakeIdentity{
		label: "web",
		ip:    net.IPv4(192, 168, 56, 10),
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, binding, managed, nil)
	body := bytes.Repeat([]byte("payload="), 32)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		request := httptest.NewRequest(http.MethodPost, "http://example.test/upload?q=1", io.NopCloser(bytes.NewReader(body)))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Code != http.StatusOK {
			b.Fatalf("expected status 200, got %d", writer.Code)
		}
	}
}

func BenchmarkScriptHeadersFromHTTPHeader(b *testing.B) {
	header := http.Header{
		"Content-Type":   {"text/plain"},
		"Content-Length": {"256"},
		"X-Test":         {"alpha", "beta"},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		headers := scriptHeadersFromHTTPHeader(header)
		if len(headers) != 4 {
			b.Fatalf("expected 4 script headers, got %d", len(headers))
		}
	}
}

func BenchmarkHTTPHeaderFromScriptHeaders(b *testing.B) {
	headers := []scriptpkg.HTTPHeader{
		{Name: "Content-Type", Value: "text/plain"},
		{Name: "Content-Length", Value: "256"},
		{Name: "X-Test", Value: "alpha"},
		{Name: "X-Test", Value: "beta"},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		header := httpHeaderFromScriptHeaders(headers)
		if len(header["X-Test"]) != 2 {
			b.Fatalf("expected 2 X-Test values, got %d", len(header["X-Test"]))
		}
	}
}

func benchmarkContiguousTCPPacket(sourcePort, targetPort uint16, payload []byte) *stack.PacketBuffer {
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	packet.TransportProtocolNumber = tcp.ProtocolNumber
	packet.NetworkProtocolNumber = ipv4.ProtocolNumber
	packet.EgressRoute.LocalAddress = tcpip.AddrFrom4Slice(net.IPv4(192, 168, 56, 10).To4())

	tcpHeader := header.TCP(packet.TransportHeader().Push(header.TCPMinimumSize))
	tcpHeader.Encode(&header.TCPFields{
		SrcPort:    sourcePort,
		DstPort:    targetPort,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		WindowSize: 64240,
	})

	ipHeader := header.IPv4(packet.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.TCPMinimumSize + len(payload)),
		TTL:         64,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 56, 10).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 56, 20).To4()),
	})

	return packet
}

func benchmarkContiguousRawPacket(payload []byte) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
}

func benchmarkARPPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr) *stack.PacketBuffer {
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ARPSize,
	})
	packet.NetworkProtocolNumber = arp.ProtocolNumber
	arpPacket := header.ARP(packet.NetworkHeader().Push(header.ARPSize))
	arpPacket.SetIPv4OverEthernet()
	arpPacket.SetOp(header.ARPReply)
	copy(arpPacket.HardwareAddressSender(), sourceMAC)
	copy(arpPacket.ProtocolAddressSender(), sourceIP.To4())
	copy(arpPacket.HardwareAddressTarget(), targetMAC)
	copy(arpPacket.ProtocolAddressTarget(), targetIP.To4())
	return packet
}

func benchmarkInboundGroup(b *testing.B, outbound *int) (*adoptedEngineGroup, fakeIdentity) {
	b.Helper()

	group, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		routes: []net.IPNet{{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		}},
	}, func(_ *adoptedEngineGroup, pkts stack.PacketBufferList) (int, tcpip.Error) {
		if outbound != nil {
			*outbound += pkts.Len()
		}
		return pkts.Len(), nil
	})
	if err != nil {
		b.Fatalf("new adopted engine group: %v", err)
	}

	identity := fakeIdentity{
		label: "bench",
		ip:    net.IPv4(192, 168, 56, 10),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := group.addIdentity(identity); err != nil {
		group.close()
		b.Fatalf("add identity: %v", err)
	}

	return group, identity
}

func serializeBenchmarkOutboundPacket(b *testing.B, packet *packetpkg.OutboundPacket) []byte {
	b.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := packet.SerializeValidatedInto(buffer); err != nil {
		b.Fatalf("serialize outbound packet: %v", err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func benchmarkHTTPServiceScriptBinding(b *testing.B, source string) *httpServiceScriptBinding {
	b.Helper()

	store := scriptpkg.NewStoreAtDir(b.TempDir())
	saved, err := store.Save(scriptpkg.SaveStoredScriptRequest{
		Name:    "http-service-bench",
		Surface: scriptpkg.SurfaceHTTPService,
		Source:  source,
	})
	if err != nil {
		b.Fatalf("save HTTP service script: %v", err)
	}

	storedScript, err := store.Lookup(scriptpkg.StoredScriptRef{
		Name:    saved.Name,
		Surface: scriptpkg.SurfaceHTTPService,
	})
	if err != nil {
		b.Fatalf("lookup HTTP service script: %v", err)
	}

	hasRequest, hasResponse, err := scriptpkg.HTTPServiceHooks(storedScript)
	if err != nil {
		b.Fatalf("inspect HTTP service hooks: %v", err)
	}

	return &httpServiceScriptBinding{
		script:      storedScript,
		hasRequest:  hasRequest,
		hasResponse: hasResponse,
	}
}
