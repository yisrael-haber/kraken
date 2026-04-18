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
	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
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

type forwardingProbeListener struct {
	injected    int
	routed      int
	lastRoute   routingpkg.StoredRoute
	lastViaIP   string
	lastFrame   []byte
	healthyErr  error
	arpEntries  []adoption.ARPCacheItem
	recording   *adoption.PacketRecordingStatus
	tcpServices []adoption.TCPServiceStatus
}

func (listener *forwardingProbeListener) Close() error { return nil }

func (listener *forwardingProbeListener) Healthy() error { return listener.healthyErr }

func (listener *forwardingProbeListener) EnsureIdentity(adoption.Identity) error { return nil }

func (listener *forwardingProbeListener) InjectFrame(frame []byte) error {
	listener.injected++
	listener.lastFrame = append([]byte(nil), frame...)
	return nil
}

func (listener *forwardingProbeListener) RouteFrame(via adoption.Identity, route routingpkg.StoredRoute, frame []byte) error {
	listener.routed++
	listener.lastRoute = route
	if via != nil {
		listener.lastViaIP = via.IP().String()
	}
	listener.lastFrame = append([]byte(nil), frame...)
	return nil
}

func (listener *forwardingProbeListener) Ping(adoption.Identity, net.IP, int, []byte) (adoption.PingAdoptedIPAddressResult, error) {
	return adoption.PingAdoptedIPAddressResult{}, nil
}

func (listener *forwardingProbeListener) ARPCacheSnapshot() []adoption.ARPCacheItem {
	return append([]adoption.ARPCacheItem(nil), listener.arpEntries...)
}

func (listener *forwardingProbeListener) StartRecording(adoption.Identity, string) (adoption.PacketRecordingStatus, error) {
	return adoption.PacketRecordingStatus{}, nil
}

func (listener *forwardingProbeListener) StopRecording(net.IP) error { return nil }

func (listener *forwardingProbeListener) RecordingSnapshot(net.IP) *adoption.PacketRecordingStatus {
	if listener.recording == nil {
		return nil
	}
	cloned := *listener.recording
	return &cloned
}

func (listener *forwardingProbeListener) StartTCPService(adoption.Identity, string, int, string, bool, string) (adoption.TCPServiceStatus, error) {
	return adoption.TCPServiceStatus{}, nil
}

func (listener *forwardingProbeListener) StopTCPService(net.IP, string) error { return nil }

func (listener *forwardingProbeListener) TCPServiceSnapshot(net.IP) []adoption.TCPServiceStatus {
	return append([]adoption.TCPServiceStatus(nil), listener.tcpServices...)
}

func (listener *forwardingProbeListener) ForgetIdentity(net.IP) {}

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

func TestPcapAdoptionListenerWritePacketWithoutHandleReportsStopped(t *testing.T) {
	listener := &pcapAdoptionListener{}

	if err := listener.writePacket([]byte{0x00}); !errors.Is(err, adoption.ErrListenerStopped) {
		t.Fatalf("expected ErrListenerStopped, got %v", err)
	}
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

func TestClassifyInboundFrameCapturesARPAndIPv4Metadata(t *testing.T) {
	arpInfo, ok := classifyInboundFrame(serializeTestPacket(t, packetpkg.BuildARPRequestPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	)))
	if !ok {
		t.Fatal("expected ARP request to classify")
	}
	if got := arpInfo.sourceIP.IP().String(); got != "192.168.56.20" {
		t.Fatalf("expected ARP source IP 192.168.56.20, got %s", got)
	}
	if got := arpInfo.targetIP.IP().String(); got != "192.168.56.10" {
		t.Fatalf("expected ARP target IP 192.168.56.10, got %s", got)
	}
	if got := arpInfo.sourceMAC.HardwareAddr().String(); got != "02:00:00:00:00:20" {
		t.Fatalf("expected ARP source MAC 02:00:00:00:00:20, got %s", got)
	}

	ipv4Info, ok := classifyInboundFrame(serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
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
		t.Fatal("expected IPv4 packet to classify")
	}
	if got := ipv4Info.sourceIP.IP().String(); got != "192.168.56.20" {
		t.Fatalf("expected IPv4 source IP 192.168.56.20, got %s", got)
	}
	if got := ipv4Info.targetIP.IP().String(); got != "192.168.56.10" {
		t.Fatalf("expected IPv4 target IP 192.168.56.10, got %s", got)
	}
	if got := ipv4Info.sourceMAC.HardwareAddr().String(); got != "02:00:00:00:00:20" {
		t.Fatalf("expected IPv4 source MAC 02:00:00:00:00:20, got %s", got)
	}
}

func TestBuildAdoptionCaptureBPFFilter(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if filter := buildAdoptionCaptureBPFFilter(nil, nil); filter != emptyAdoptionCaptureBPFFilter {
			t.Fatalf("expected empty filter %q, got %q", emptyAdoptionCaptureBPFFilter, filter)
		}
	})

	t.Run("includes adopted IP targets", func(t *testing.T) {
		filter := buildAdoptionCaptureBPFFilter([]*adoptedEngineGroup{{
			config: adoptedEngineGroupConfig{
				mac: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
			},
		}}, map[compactIPv4]*adoptedEngineGroup{
			compactIPv4FromIP(net.IPv4(192, 168, 56, 20)): nil,
			compactIPv4FromIP(net.IPv4(192, 168, 56, 10)): nil,
		})

		for _, fragment := range []string{
			"arp dst host 192.168.56.10",
			"arp dst host 192.168.56.20",
			"dst host 192.168.56.10",
			"dst host 192.168.56.20",
		} {
			if !strings.Contains(filter, fragment) {
				t.Fatalf("expected filter %q to contain %q", filter, fragment)
			}
		}
		if !strings.Contains(filter, "ether dst host 02:00:00:00:00:10") {
			t.Fatalf("expected filter %q to contain adopted MAC clause", filter)
		}
	})
}

func TestBuildAdoptionCaptureBPFFilterDeduplicatesMACs(t *testing.T) {
	filter := buildAdoptionCaptureBPFFilter([]*adoptedEngineGroup{
		{config: adoptedEngineGroupConfig{mac: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}},
		{config: adoptedEngineGroupConfig{mac: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}}},
	}, nil)

	if got := strings.Count(filter, "ether dst host 02:00:00:00:00:10"); got != 1 {
		t.Fatalf("expected one MAC clause, got %d in %q", got, filter)
	}
}

func TestPcapAdoptionListenerDispatchesDirectForwarding(t *testing.T) {
	target := &forwardingProbeListener{}
	listener := &pcapAdoptionListener{
		forward: func(destinationIP net.IP) (adoption.ForwardingDecision, bool) {
			if destinationIP.String() != "10.0.0.99" {
				t.Fatalf("expected forwarded destination IP 10.0.0.99, got %s", destinationIP)
			}
			return adoption.ForwardingDecision{
				Listener: target,
				Identity: fakeIdentity{ip: net.IPv4(10, 0, 0, 99)},
			}, true
		},
	}
	listener.groupsV.Store([]*adoptedEngineGroup(nil))
	listener.ipGroupsV.Store(map[compactIPv4]*adoptedEngineGroup{})

	frame := serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	))

	listener.dispatchInboundFrame(frame)

	if target.injected != 1 {
		t.Fatalf("expected direct forwarding to inject once, got %d", target.injected)
	}
	if target.routed != 0 {
		t.Fatalf("expected direct forwarding not to route, got %d", target.routed)
	}
}

func TestPcapAdoptionListenerDispatchPrefersLocalInjectionOverForwardLookup(t *testing.T) {
	group, err := newAdoptedEngineGroup(adoptedEngineGroupConfig{
		ifaceName: "eth0",
		mac:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		routes: []net.IPNet{{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		}},
	}, func(_ *adoptedEngineGroup, pkts stack.PacketBufferList) (int, tcpip.Error) {
		return pkts.Len(), nil
	})
	if err != nil {
		t.Fatalf("new adopted engine group: %v", err)
	}
	defer group.close()

	identity := fakeIdentity{
		label: "local-host",
		ip:    net.IPv4(192, 168, 56, 10),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}
	if err := group.addIdentity(identity); err != nil {
		t.Fatalf("add identity: %v", err)
	}

	forwardCalls := 0
	listener := &pcapAdoptionListener{
		forward: func(net.IP) (adoption.ForwardingDecision, bool) {
			forwardCalls++
			return adoption.ForwardingDecision{}, false
		},
		ipGroups: map[compactIPv4]*adoptedEngineGroup{
			compactIPv4FromIP(identity.ip): group,
		},
	}
	listener.ipGroupsV.Store(cloneEngineGroupMap(listener.ipGroups))
	listener.groupsV.Store([]*adoptedEngineGroup{group})

	frame := serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.ip,
		identity.mac,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	))

	listener.dispatchInboundFrame(frame)

	if forwardCalls != 0 {
		t.Fatalf("expected local delivery to skip forward lookup, got %d calls", forwardCalls)
	}
}

func TestPcapAdoptionListenerDispatchesRoutedForwarding(t *testing.T) {
	target := &forwardingProbeListener{}
	listener := &pcapAdoptionListener{
		forward: func(destinationIP net.IP) (adoption.ForwardingDecision, bool) {
			return adoption.ForwardingDecision{
				Listener: target,
				Identity: fakeIdentity{ip: net.IPv4(192, 168, 56, 10)},
				Route: routingpkg.StoredRoute{
					Label:           "lab-segment",
					DestinationCIDR: "10.0.0.0/24",
					ViaAdoptedIP:    "192.168.56.10",
				},
				Routed: true,
			}, destinationIP.String() == "10.0.0.99"
		},
	}
	listener.groupsV.Store([]*adoptedEngineGroup(nil))
	listener.ipGroupsV.Store(map[compactIPv4]*adoptedEngineGroup{})

	frame := serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	))

	listener.dispatchInboundFrame(frame)

	if target.routed != 1 {
		t.Fatalf("expected routed forwarding once, got %d", target.routed)
	}
	if target.lastRoute.Label != "lab-segment" {
		t.Fatalf("expected route label lab-segment, got %q", target.lastRoute.Label)
	}
	if target.lastViaIP != "192.168.56.10" {
		t.Fatalf("expected routed via 192.168.56.10, got %q", target.lastViaIP)
	}
}

func TestRouteNextHopPrefersConnectedSubnet(t *testing.T) {
	_, destinationIP, err := parseRoutedIPv4Frame(serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	)))
	if err != nil {
		t.Fatalf("parse routed frame: %v", err)
	}

	nextHop, err := routeNextHop([]net.IPNet{{
		IP:   net.IPv4(10, 0, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}}, net.IPv4(192, 168, 56, 1), destinationIP)
	if err != nil {
		t.Fatalf("route next hop: %v", err)
	}
	if got := nextHop.String(); got != "10.0.0.99" {
		t.Fatalf("expected direct next hop 10.0.0.99, got %s", got)
	}
}

func TestRouteNextHopFallsBackToGateway(t *testing.T) {
	nextHop, err := routeNextHop([]net.IPNet{{
		IP:   net.IPv4(10, 0, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}}, net.IPv4(192, 168, 56, 1), net.IPv4(172, 16, 0, 20))
	if err != nil {
		t.Fatalf("route next hop: %v", err)
	}
	if got := nextHop.String(); got != "192.168.56.1" {
		t.Fatalf("expected gateway next hop 192.168.56.1, got %s", got)
	}
}

func TestPrepareForwardedIPv4FrameRewritesEthernetAndTTL(t *testing.T) {
	frame := serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	))

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		t.Fatal("expected IPv4 layer")
	}
	originalTTL := ipv4Layer.(*layers.IPv4).TTL

	ipv4Header, _, err := parseRoutedIPv4Frame(frame)
	if err != nil {
		t.Fatalf("parse routed frame: %v", err)
	}

	if err := rewriteForwardedIPv4Frame(
		frame,
		ipv4Header,
		net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
	); err != nil {
		t.Fatalf("prepare forwarded frame: %v", err)
	}

	decoded := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	ethernet := decoded.Layer(layers.LayerTypeEthernet)
	if ethernet == nil {
		t.Fatal("expected Ethernet layer")
	}
	ethernetFrame := ethernet.(*layers.Ethernet)
	if got := ethernetFrame.SrcMAC.String(); got != "02:aa:bb:cc:dd:ee" {
		t.Fatalf("expected rewritten source MAC, got %s", got)
	}
	if got := ethernetFrame.DstMAC.String(); got != "02:11:22:33:44:55" {
		t.Fatalf("expected rewritten destination MAC, got %s", got)
	}
	forwardedIPv4 := decoded.Layer(layers.LayerTypeIPv4)
	if forwardedIPv4 == nil {
		t.Fatal("expected rewritten IPv4 layer")
	}
	if got := forwardedIPv4.(*layers.IPv4).TTL; got != originalTTL-1 {
		t.Fatalf("expected TTL %d, got %d", originalTTL-1, got)
	}
}

func TestRewriteForwardedIPv4FrameRejectsExpiredTTL(t *testing.T) {
	frame := serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	))

	ipv4Header, _, err := parseRoutedIPv4Frame(frame)
	if err != nil {
		t.Fatalf("parse routed frame: %v", err)
	}
	ipv4Header.SetTTL(1)

	err = rewriteForwardedIPv4Frame(
		frame,
		ipv4Header,
		net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
	)
	if err == nil || !strings.Contains(err.Error(), "TTL expired") {
		t.Fatalf("expected TTL expired error, got %v", err)
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
