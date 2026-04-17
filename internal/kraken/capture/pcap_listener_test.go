package capture

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type fakeIdentity struct {
	label          string
	ip             net.IP
	iface          net.Interface
	mac            net.HardwareAddr
	defaultGateway net.IP
	scriptName     string
}

func (identity fakeIdentity) Label() string { return identity.label }

func (identity fakeIdentity) IP() net.IP { return identity.ip }

func (identity fakeIdentity) Interface() net.Interface { return identity.iface }

func (identity fakeIdentity) MAC() net.HardwareAddr { return identity.mac }

func (identity fakeIdentity) DefaultGateway() net.IP { return identity.defaultGateway }

func (identity fakeIdentity) ScriptName() string { return identity.scriptName }

func (identity fakeIdentity) RecordARP(string, string, net.IP, net.HardwareAddr, string) {}

func (identity fakeIdentity) RecordICMP(string, string, net.IP, uint16, uint16, time.Duration, string, string) {
}

func TestPcapAdoptionListenerHealthy(t *testing.T) {
	t.Run("reports run error before stopped state", func(t *testing.T) {
		runErr := errors.New("capture loop exited")
		listener := &pcapAdoptionListener{
			done:   make(chan struct{}),
			runErr: runErr,
		}
		close(listener.done)

		if err := listener.Healthy(); !errors.Is(err, runErr) {
			t.Fatalf("expected run error %v, got %v", runErr, err)
		}
	})

	t.Run("reports stopped listener", func(t *testing.T) {
		listener := &pcapAdoptionListener{
			done: make(chan struct{}),
		}
		close(listener.done)

		if err := listener.Healthy(); !errors.Is(err, adoption.ErrListenerStopped) {
			t.Fatalf("expected ErrListenerStopped, got %v", err)
		}
	})

	t.Run("reports healthy while running", func(t *testing.T) {
		listener := &pcapAdoptionListener{
			done: make(chan struct{}),
		}

		if err := listener.Healthy(); err != nil {
			t.Fatalf("expected listener to be healthy, got %v", err)
		}
	})
}

func TestBuildBoundPacketScriptIncludesAdoptedLabel(t *testing.T) {
	script := buildBoundPacketScript(fakeIdentity{
		label:      "Lab Host",
		ip:         net.ParseIP("192.168.56.10").To4(),
		iface:      net.Interface{Name: "eth0"},
		mac:        net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		scriptName: "ttl-clamp",
	})

	if script.Adopted.Label != "Lab Host" {
		t.Fatalf("expected adopted label to be preserved, got %q", script.Adopted.Label)
	}
}

func TestBuildBoundPacketScriptSkipsContextWithoutScript(t *testing.T) {
	script := buildBoundPacketScript(fakeIdentity{
		label: "Lab Host",
		ip:    net.ParseIP("192.168.56.10").To4(),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	})

	if script.ScriptName != "" {
		t.Fatalf("expected empty script name, got %q", script.ScriptName)
	}
	if script.Adopted.Label != "" || script.Adopted.IP != "" || script.Adopted.MAC != "" {
		t.Fatalf("expected adopted context to stay empty when no script is bound, got %+v", script.Adopted)
	}
}

func TestTargetIPv4ForFrameRecognizesAdoptedARPAndICMP(t *testing.T) {
	arpTarget, ok := targetIPv4ForFrame(serializeTestPacket(t, packetpkg.BuildARPRequestPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	)))
	if !ok {
		t.Fatal("expected ARP request to resolve a target IP")
	}
	if got := arpTarget.IP().String(); got != "192.168.56.10" {
		t.Fatalf("expected ARP target IP 192.168.56.10, got %s", got)
	}

	icmpTarget, ok := targetIPv4ForFrame(serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	)))
	if !ok {
		t.Fatal("expected ICMP echo request to resolve a target IP")
	}
	if got := icmpTarget.IP().String(); got != "192.168.56.10" {
		t.Fatalf("expected ICMP target IP 192.168.56.10, got %s", got)
	}
}

func TestClassifyFrameActivityCapturesARPAndICMPMetadata(t *testing.T) {
	arpActivity, ok := classifyFrameActivity(serializeTestPacket(t, packetpkg.BuildARPRequestPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	)))
	if !ok {
		t.Fatal("expected ARP request to classify")
	}
	if arpActivity.protocol != "arp" || arpActivity.arpOp != header.ARPRequest {
		t.Fatalf("expected ARP request metadata, got %+v", arpActivity)
	}
	if got := arpActivity.sourceIP.IP().String(); got != "192.168.56.20" {
		t.Fatalf("expected ARP source IP 192.168.56.20, got %s", got)
	}

	icmpActivity, ok := classifyFrameActivity(serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	)))
	if !ok {
		t.Fatal("expected ICMP echo request to classify")
	}
	if icmpActivity.protocol != "icmpv4" || icmpActivity.icmpType != header.ICMPv4Echo {
		t.Fatalf("expected ICMP echo request metadata, got %+v", icmpActivity)
	}
	if icmpActivity.icmpID != 7 || icmpActivity.icmpSeq != 3 {
		t.Fatalf("expected id=7 seq=3, got id=%d seq=%d", icmpActivity.icmpID, icmpActivity.icmpSeq)
	}
}

func TestFrameActivityBuildsInboundAndOutboundRecords(t *testing.T) {
	identity := fakeIdentity{
		label: "lab",
		ip:    net.IPv4(192, 168, 56, 10),
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}

	arpActivity, ok := classifyFrameActivity(serializeTestPacket(t, packetpkg.BuildARPRequestPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	)))
	if !ok {
		t.Fatal("expected ARP request to classify")
	}

	inboundARP, ok := arpActivity.inboundRecord(identity)
	if !ok {
		t.Fatal("expected inbound ARP record")
	}
	if inboundARP.event != "recv-request" || inboundARP.peerIP.IP().String() != "192.168.56.20" {
		t.Fatalf("unexpected inbound ARP record %+v", inboundARP)
	}

	outboundARP, ok := arpActivity.outboundRecord(identity)
	if !ok {
		t.Fatal("expected outbound ARP record")
	}
	if outboundARP.event != "send-request" || outboundARP.peerIP.IP().String() != "192.168.56.10" {
		t.Fatalf("unexpected outbound ARP record %+v", outboundARP)
	}

	icmpActivity, ok := classifyFrameActivity(serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		3,
		[]byte("hello"),
	)))
	if !ok {
		t.Fatal("expected ICMP echo reply to classify")
	}

	inboundICMP, ok := icmpActivity.inboundRecord(identity)
	if !ok {
		t.Fatal("expected inbound ICMP record")
	}
	if inboundICMP.event != "recv-echo-reply" || inboundICMP.status != "received" {
		t.Fatalf("unexpected inbound ICMP record %+v", inboundICMP)
	}

	outboundICMP, ok := icmpActivity.outboundRecord(identity)
	if !ok {
		t.Fatal("expected outbound ICMP record")
	}
	if outboundICMP.event != "send-echo-reply" || outboundICMP.status != "sent" {
		t.Fatalf("unexpected outbound ICMP record %+v", outboundICMP)
	}
}

func TestBuildRecordingBPFFilterIncludesIPAndARPClauses(t *testing.T) {
	filter := buildRecordingBPFFilter(fakeIdentity{
		ip:    net.ParseIP("192.168.56.10").To4(),
		iface: net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	})

	for _, fragment := range []string{
		"(ip host 192.168.56.10)",
		"(arp and (arp src host 192.168.56.10 or arp dst host 192.168.56.10))",
	} {
		if !strings.Contains(filter, fragment) {
			t.Fatalf("expected filter %q to contain %q", filter, fragment)
		}
	}
	if strings.Contains(filter, "ether host") {
		t.Fatalf("expected shared interface MAC to avoid extra ether host clause, got %q", filter)
	}
}

func TestBuildRecordingBPFFilterIncludesCustomMACClause(t *testing.T) {
	filter := buildRecordingBPFFilter(fakeIdentity{
		ip:    net.ParseIP("192.168.56.11").To4(),
		iface: net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}},
		mac:   net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
	})

	if !strings.Contains(filter, "(ether host 02:aa:bb:cc:dd:ee)") {
		t.Fatalf("expected custom MAC clause in filter, got %q", filter)
	}
}

func TestAdoptedEngineGroupIdentityForSourceAddressHandlesARPReplies(t *testing.T) {
	sourceIP := net.IPv4(192, 168, 56, 10)
	sourceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	targetIP := net.IPv4(192, 168, 56, 1)
	targetMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	group := &adoptedEngineGroup{
		identities: map[compactIPv4]adoption.Identity{
			compactIPv4FromIP(sourceIP): fakeIdentity{
				label: "arp-source",
				ip:    sourceIP,
				mac:   sourceMAC,
			},
		},
	}

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ARPSize,
	})
	defer packet.DecRef()

	packet.NetworkProtocolNumber = arp.ProtocolNumber
	arpPacket := header.ARP(packet.NetworkHeader().Push(header.ARPSize))
	arpPacket.SetIPv4OverEthernet()
	arpPacket.SetOp(header.ARPReply)
	copy(arpPacket.HardwareAddressSender(), sourceMAC)
	copy(arpPacket.ProtocolAddressSender(), sourceIP.To4())
	copy(arpPacket.HardwareAddressTarget(), targetMAC)
	copy(arpPacket.ProtocolAddressTarget(), targetIP.To4())

	var address tcpip.Address
	identity, ok := group.identityForSourceAddress(address, packet)
	if !ok {
		t.Fatal("expected ARP reply to resolve an adopted identity")
	}
	if got := identity.IP().String(); got != sourceIP.String() {
		t.Fatalf("expected identity IP %s, got %s", sourceIP, got)
	}
}

func serializeTestPacket(t *testing.T, packet *packetpkg.OutboundPacket) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := packet.SerializeValidatedInto(buffer); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func serializeTCPFrame(t *testing.T, sourceIP, targetIP net.IP, sourceMAC, targetMAC net.HardwareAddr, sourcePort, targetPort uint16, seq uint32, syn bool) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       append(net.HardwareAddr(nil), sourceMAC...),
		DstMAC:       append(net.HardwareAddr(nil), targetMAC...),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    append(net.IP(nil), sourceIP.To4()...),
		DstIP:    append(net.IP(nil), targetIP.To4()...),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sourcePort),
		DstPort: layers.TCPPort(targetPort),
		Seq:     seq,
		SYN:     syn,
		Window:  64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatalf("set TCP checksum layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ethernet, ipv4, tcp); err != nil {
		t.Fatalf("serialize TCP frame: %v", err)
	}

	return append([]byte(nil), buffer.Bytes()...)
}

func TestEchoTCPServiceRespondsToSYN(t *testing.T) {
	outbound := make(chan []byte, 4)
	group, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		routes: []net.IPNet{{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		}},
	}, func(group *adoptedEngineGroup, pkts stack.PacketBufferList) (int, tcpip.Error) {
		for _, pkt := range pkts.AsSlice() {
			outbound <- appendPacketBufferTo(nil, pkt)
		}
		return pkts.Len(), nil
	})
	if err != nil {
		t.Fatalf("new adopted engine group: %v", err)
	}
	defer group.close()

	identity := fakeIdentity{
		label: "echo-host",
		ip:    net.IPv4(192, 168, 56, 10),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := group.addIdentity(identity); err != nil {
		t.Fatalf("add identity: %v", err)
	}

	listener := &pcapAdoptionListener{
		groups:   map[string]*adoptedEngineGroup{"test": group},
		ipGroups: map[compactIPv4]*adoptedEngineGroup{compactIPv4FromIP(identity.ip): group},
	}
	listener.groupsV.Store([]*adoptedEngineGroup{group})

	service, err := startEchoTCPService(group, identity.ip, tcpServiceSpec{
		service: adoption.TCPServiceEcho,
		port:    8080,
	})
	if err != nil {
		t.Fatalf("start echo service: %v", err)
	}
	defer service.stop()

	frame := serializeTCPFrame(
		t,
		net.IPv4(192, 168, 56, 20),
		identity.ip,
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.mac,
		50505,
		8080,
		100,
		true,
	)
	listener.dispatchInboundFrame(frame)

	select {
	case response := <-outbound:
		packet := gopacket.NewPacket(response, layers.LayerTypeEthernet, gopacket.Default)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			t.Fatalf("expected outbound TCP packet, got %v", packet.Layers())
		}
		tcpPacket := tcpLayer.(*layers.TCP)
		if !tcpPacket.SYN || !tcpPacket.ACK {
			t.Fatalf("expected SYN-ACK, got flags syn=%v ack=%v rst=%v", tcpPacket.SYN, tcpPacket.ACK, tcpPacket.RST)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound SYN-ACK")
	}
}

func TestEchoTCPServiceRespondsToSYNWithChecksumOffloadStyleFrame(t *testing.T) {
	outbound := make(chan []byte, 4)
	group, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		routes: []net.IPNet{{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		}},
	}, func(group *adoptedEngineGroup, pkts stack.PacketBufferList) (int, tcpip.Error) {
		for _, pkt := range pkts.AsSlice() {
			outbound <- appendPacketBufferTo(nil, pkt)
		}
		return pkts.Len(), nil
	})
	if err != nil {
		t.Fatalf("new adopted engine group: %v", err)
	}
	defer group.close()

	identity := fakeIdentity{
		label: "echo-host",
		ip:    net.IPv4(192, 168, 56, 10),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := group.addIdentity(identity); err != nil {
		t.Fatalf("add identity: %v", err)
	}

	listener := &pcapAdoptionListener{
		groups:   map[string]*adoptedEngineGroup{"test": group},
		ipGroups: map[compactIPv4]*adoptedEngineGroup{compactIPv4FromIP(identity.ip): group},
	}
	listener.groupsV.Store([]*adoptedEngineGroup{group})

	service, err := startEchoTCPService(group, identity.ip, tcpServiceSpec{
		service: adoption.TCPServiceEcho,
		port:    8080,
	})
	if err != nil {
		t.Fatalf("start echo service: %v", err)
	}
	defer service.stop()

	frame := serializeTCPFrame(
		t,
		net.IPv4(192, 168, 56, 20),
		identity.ip,
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.mac,
		50505,
		8080,
		100,
		true,
	)
	frame[50] = 0
	frame[51] = 0
	listener.dispatchInboundFrame(frame)

	select {
	case response := <-outbound:
		packet := gopacket.NewPacket(response, layers.LayerTypeEthernet, gopacket.Default)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			t.Fatalf("expected outbound TCP packet, got %v", packet.Layers())
		}
		tcpPacket := tcpLayer.(*layers.TCP)
		if !tcpPacket.SYN || !tcpPacket.ACK {
			t.Fatalf("expected SYN-ACK, got flags syn=%v ack=%v rst=%v", tcpPacket.SYN, tcpPacket.ACK, tcpPacket.RST)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound SYN-ACK")
	}
}
