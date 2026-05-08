package operations

import (
	"errors"
	"maps"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"gvisor.dev/gvisor/pkg/buffer"
)

type fakeIdentity = adoption.Identity

type forwardingProbeListener struct {
	injected   int
	lastFrame  []byte
	healthyErr error
	recording  *adoption.PacketRecordingStatus
	services   []adoption.ServiceStatus
}

func (listener *forwardingProbeListener) Close() error { return nil }

func (listener *forwardingProbeListener) Healthy() error { return listener.healthyErr }

func (listener *forwardingProbeListener) EnsureIdentity(*adoption.Identity) error { return nil }

func (listener *forwardingProbeListener) InjectFrame(frame buffer.Buffer) error {
	listener.injected++
	listener.lastFrame = append([]byte(nil), bufferBytes(&frame)...)
	frame.Release()
	return nil
}

func (listener *forwardingProbeListener) Ping(*adoption.Identity, net.IP, int, []byte) (adoption.PingAdoptedIPAddressResult, error) {
	return adoption.PingAdoptedIPAddressResult{}, nil
}

func (listener *forwardingProbeListener) ResolveDNS(*adoption.Identity, adoption.ResolveDNSAdoptedIPAddressRequest) (adoption.ResolveDNSAdoptedIPAddressResult, error) {
	return adoption.ResolveDNSAdoptedIPAddressResult{}, nil
}

func (listener *forwardingProbeListener) StatusSnapshot(net.IP) adoption.ListenerStatus {
	return adoption.ListenerStatus{}
}

func (listener *forwardingProbeListener) StartRecording(*adoption.Identity, string) (adoption.PacketRecordingStatus, error) {
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

func (listener *forwardingProbeListener) StartService(*adoption.Identity, string, map[string]string) (adoption.ServiceStatus, error) {
	return adoption.ServiceStatus{}, nil
}

func (listener *forwardingProbeListener) StopService(net.IP, string) error { return nil }

func (listener *forwardingProbeListener) ServiceSnapshot(net.IP) []adoption.ServiceStatus {
	return append([]adoption.ServiceStatus(nil), listener.services...)
}

func (listener *forwardingProbeListener) ForgetIdentity(net.IP) {}

func newMemoryTestListener(forward adoption.ForwardLookupFunc) *pcapAdoptionListener {
	listener := &pcapAdoptionListener{
		forward: forward,
		engines: make(map[string]*adoption.Identity),
	}
	listener.enginesV.Store(map[string]*adoption.Identity{})
	return listener
}

func (listener *pcapAdoptionListener) addTestEngine(ip net.IP, identity *adoption.Identity) {
	if listener.engines == nil {
		listener.engines = make(map[string]*adoption.Identity)
	}
	listener.engines[engineKey(ip)] = identity
	listener.enginesV.Store(maps.Clone(listener.engines))
}

func newTestEngineIdentity(t *testing.T, identity adoption.Identity, routes []net.IPNet, outbound func(*adoption.Identity, buffer.Buffer) error) *adoption.Identity {
	t.Helper()
	if identity.InterfaceName == "" {
		identity.InterfaceName = identity.Interface.Name
	}
	if err := identity.EnsureEngine(routes, outbound); err != nil {
		t.Fatalf("new identity engine: %v", err)
	}
	t.Cleanup(identity.CloseEngine)
	return &identity
}

func TestPcapAdoptionListenerHealthy(t *testing.T) {
	t.Run("reports stopped listener", func(t *testing.T) {
		listener := &pcapAdoptionListener{}

		if err := listener.Healthy(); !errors.Is(err, adoption.ErrListenerStopped) {
			t.Fatalf("expected ErrListenerStopped, got %v", err)
		}
	})
}

func TestPcapAdoptionListenerWritePacketWithoutHandleReportsStopped(t *testing.T) {
	listener := &pcapAdoptionListener{}

	if err := listener.writePacket([]byte{0x00}); !errors.Is(err, adoption.ErrListenerStopped) {
		t.Fatalf("expected ErrListenerStopped, got %v", err)
	}
}

func TestBuildBoundTransportScriptIncludesAdoptedLabel(t *testing.T) {
	script := buildBoundTransportScript(fakeIdentity{
		Label:               "Lab Host",
		IP:                  net.ParseIP("192.168.56.10").To4(),
		Interface:           net.Interface{Name: "eth0"},
		MAC:                 adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		TransportScriptName: "ttl-clamp",
	})

	if script.Adopted.Label != "Lab Host" {
		t.Fatalf("expected adopted label to be preserved, got %q", script.Adopted.Label)
	}
}

func TestBuildBoundTransportScriptSkipsContextWithoutScript(t *testing.T) {
	script := buildBoundTransportScript(fakeIdentity{
		Label:     "Lab Host",
		IP:        net.ParseIP("192.168.56.10").To4(),
		Interface: net.Interface{Name: "eth0"},
		MAC:       adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	})

	if script.ScriptName != "" {
		t.Fatalf("expected empty script name, got %q", script.ScriptName)
	}
	if script.Adopted.Label != "" || script.Adopted.IP != "" || script.Adopted.MAC != "" {
		t.Fatalf("expected adopted context to stay empty when no script is bound, got %+v", script.Adopted)
	}
}

func TestClassifyInboundFrameCapturesTargetIP(t *testing.T) {
	arpInfo, ok := classifyInboundFrame(serializeARPRequestTestPacket(t,
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	))
	if !ok {
		t.Fatal("expected ARP request to classify")
	}
	if got := arpInfo.targetIP.String(); got != "192.168.56.10" {
		t.Fatalf("expected ARP target IP 192.168.56.10, got %s", got)
	}

	ipv4Info, ok := classifyInboundFrame(serializeICMPEchoTestPacket(t,
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		7,
		3,
		[]byte("hello"),
	))
	if !ok {
		t.Fatal("expected IPv4 packet to classify")
	}
	if got := ipv4Info.targetIP.String(); got != "192.168.56.10" {
		t.Fatalf("expected IPv4 target IP 192.168.56.10, got %s", got)
	}
}

func TestBuildAdoptionCaptureBPFFilter(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if filter := buildAdoptionCaptureBPFFilter(nil); filter != inactiveAdoptionCaptureBPFFilter {
			t.Fatalf("expected inactive filter %q, got %q", inactiveAdoptionCaptureBPFFilter, filter)
		}
		if _, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, netruntime.CaptureSnapLen, inactiveAdoptionCaptureBPFFilter); err != nil {
			t.Fatalf("expected inactive filter to compile: %v", err)
		}
	})

	t.Run("includes adopted IP targets", func(t *testing.T) {
		filter := buildAdoptionCaptureBPFFilter(map[string]*adoption.Identity{
			engineKey(net.IPv4(192, 168, 56, 20)): nil,
			engineKey(net.IPv4(192, 168, 56, 10)): nil,
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
	})
}

func TestBuildAdoptionCaptureBPFFilterOmitsMACClauses(t *testing.T) {
	filter := buildAdoptionCaptureBPFFilter(map[string]*adoption.Identity{
		engineKey(net.IPv4(192, 168, 56, 10)): nil,
	})

	if strings.Contains(filter, "ether dst host") {
		t.Fatalf("expected IP-only filter, got %q", filter)
	}
}

func TestPcapAdoptionListenerDispatchesDirectForwarding(t *testing.T) {
	target := &forwardingProbeListener{}
	listener := newMemoryTestListener(
		func(destinationIP net.IP) (adoption.Listener, bool) {
			if destinationIP.String() != "10.0.0.99" {
				t.Fatalf("expected forwarded destination IP 10.0.0.99, got %s", destinationIP)
			}
			return target, true
		},
	)

	frame := serializeICMPEchoTestPacket(t,
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	)

	listener.dispatchInboundFrame(buffer.MakeWithData(frame))

	if target.injected != 1 {
		t.Fatalf("expected direct forwarding to inject once, got %d", target.injected)
	}
}

func TestPcapAdoptionListenerDispatchPrefersLocalInjectionOverForwardLookup(t *testing.T) {
	routes := []net.IPNet{{
		IP:   net.IPv4(192, 168, 56, 0),
		Mask: net.CIDRMask(24, 32),
	}}

	identity := newTestEngineIdentity(t, fakeIdentity{
		Label:     "local-host",
		IP:        net.IPv4(192, 168, 56, 10),
		Interface: net.Interface{Name: "eth0"},
		MAC:       adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, routes, func(_ *adoption.Identity, frame buffer.Buffer) error { frame.Release(); return nil })

	forwardCalls := 0
	listener := newMemoryTestListener(
		func(net.IP) (adoption.Listener, bool) {
			forwardCalls++
			return nil, false
		},
	)
	listener.addTestEngine(identity.IP, identity)

	frame := serializeICMPEchoTestPacket(t,
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		identity.IP,
		net.HardwareAddr(identity.MAC),
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	)

	listener.dispatchInboundFrame(buffer.MakeWithData(frame))

	if forwardCalls != 0 {
		t.Fatalf("expected local delivery to skip forward lookup, got %d calls", forwardCalls)
	}
}

func TestPcapAdoptionListenerDispatchesRoutedForwarding(t *testing.T) {
	target := &forwardingProbeListener{}
	listener := newMemoryTestListener(
		func(destinationIP net.IP) (adoption.Listener, bool) {
			return target, destinationIP.String() == "10.0.0.99"
		},
	)

	frame := serializeICMPEchoTestPacket(t,
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(10, 0, 0, 99),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		1,
		1,
		nil,
	)

	listener.dispatchInboundFrame(buffer.MakeWithData(frame))

	if target.injected != 1 {
		t.Fatalf("expected routed forwarding to inject once, got %d", target.injected)
	}
}

func TestBuildRecordingBPFFilterIncludesIPAndARPClauses(t *testing.T) {
	ifaceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	filter := buildRecordingBPFFilter(fakeIdentity{
		IP:  net.ParseIP("192.168.56.10").To4(),
		MAC: adoption.HardwareAddr(ifaceMAC),
	}, ifaceMAC)

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
		IP:  net.ParseIP("192.168.56.11").To4(),
		MAC: adoption.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
	}, net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10})

	if !strings.Contains(filter, "(ether host 02:aa:bb:cc:dd:ee)") {
		t.Fatalf("expected custom MAC clause in filter, got %q", filter)
	}
}

func serializeARPRequestTestPacket(t *testing.T, sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) []byte {
	t.Helper()

	packet, err := scriptpkg.NewMutableARPRequestPacket(sourceIP, sourceMAC, targetIP)
	return serializeMutableTestPacket(t, packet, err)
}

func serializeICMPEchoTestPacket(t *testing.T, sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) []byte {
	t.Helper()

	packet, err := scriptpkg.NewMutableICMPEchoPacket(sourceIP, sourceMAC, targetIP, targetMAC, typeCode, id, sequence, payload)
	return serializeMutableTestPacket(t, packet, err)
}

func serializeMutableTestPacket(t *testing.T, packet *scriptpkg.MutablePacket, err error) []byte {
	t.Helper()

	if err != nil {
		t.Fatalf("new packet: %v", err)
	}
	defer packet.Release()
	return append([]byte(nil), packet.Bytes()...)
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

func resolveTestNeighbor(t *testing.T, listener *pcapAdoptionListener, outbound <-chan []byte, sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) {
	t.Helper()

	listener.dispatchInboundFrame(buffer.MakeWithData(serializeARPRequestTestPacket(t, sourceIP, sourceMAC, targetIP)))
	select {
	case <-outbound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound ARP reply")
	}
}

func TestEchoTCPServiceRespondsToSYN(t *testing.T) {
	outbound := make(chan []byte, 4)
	routes := []net.IPNet{{
		IP:   net.IPv4(192, 168, 56, 0),
		Mask: net.CIDRMask(24, 32),
	}}
	identity := newTestEngineIdentity(t, fakeIdentity{
		Label:     "echo-host",
		IP:        net.IPv4(192, 168, 56, 10),
		Interface: net.Interface{Name: "eth0"},
		MAC:       adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, routes, func(_ *adoption.Identity, frame buffer.Buffer) error {
		outbound <- append([]byte(nil), bufferBytes(&frame)...)
		frame.Release()
		return nil
	})

	listener := newMemoryTestListener(nil)
	listener.addTestEngine(identity.IP, identity)

	service, err := startManagedService(identity, serviceEchoID, map[string]string{
		"port": "8080",
	}, nil)
	if err != nil {
		t.Fatalf("start echo service: %v", err)
	}
	defer service.stop()

	clientIP := net.IPv4(192, 168, 56, 20)
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}
	resolveTestNeighbor(t, listener, outbound, clientIP, clientMAC, identity.IP)

	frame := serializeTCPFrame(
		t,
		clientIP,
		identity.IP,
		clientMAC,
		net.HardwareAddr(identity.MAC),
		50505,
		8080,
		100,
		true,
	)
	listener.dispatchInboundFrame(buffer.MakeWithData(frame))

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

func TestEchoTCPServiceOutboundUsesTransportScriptWithApplicationScriptConfigured(t *testing.T) {
	store := storage.NewScriptStoreAtDir(t.TempDir())
	if _, err := store.Save(storage.SaveStoredScriptRequest{
		Name:    "transport-window",
		Surface: storage.SurfaceTransport,
		Source: `def main(packet, ctx):
    if packet.tcp != None:
        packet.tcp.window = 1234
`,
	}); err != nil {
		t.Fatalf("save transport script: %v", err)
	}
	if _, err := store.Save(storage.SaveStoredScriptRequest{
		Name:    "application-noop",
		Surface: storage.SurfaceApplication,
		Source: `def main(buffer, ctx):
    pass
`,
	}); err != nil {
		t.Fatalf("save application script: %v", err)
	}

	outbound := make(chan []byte, 4)
	listener := &pcapAdoptionListener{
		resolveScript: store.Lookup,
		writePacketData: func(frame []byte) error {
			outbound <- append([]byte(nil), frame...)
			return nil
		},
		scriptErrors: make(map[string]adoption.ScriptRuntimeError),
	}
	routes := []net.IPNet{{
		IP:   net.IPv4(192, 168, 56, 0),
		Mask: net.CIDRMask(24, 32),
	}}
	identity := newTestEngineIdentity(t, fakeIdentity{
		Label:                 "echo-host",
		IP:                    net.IPv4(192, 168, 56, 10),
		Interface:             net.Interface{Name: "eth0"},
		MAC:                   adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		TransportScriptName:   "transport-window",
		ApplicationScriptName: "application-noop",
	}, routes, listener.handleEngineOutbound)

	listener.addTestEngine(identity.IP, identity)

	service, err := startManagedService(identity, serviceEchoID, map[string]string{
		"port": "8080",
	}, store.Lookup)
	if err != nil {
		t.Fatalf("start echo service: %v", err)
	}
	defer service.stop()

	clientIP := net.IPv4(192, 168, 56, 20)
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}
	resolveTestNeighbor(t, listener, outbound, clientIP, clientMAC, identity.IP)

	frame := serializeTCPFrame(
		t,
		clientIP,
		identity.IP,
		clientMAC,
		net.HardwareAddr(identity.MAC),
		50505,
		8080,
		100,
		true,
	)
	listener.dispatchInboundFrame(buffer.MakeWithData(frame))

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
		if tcpPacket.Window != 1234 {
			t.Fatalf("expected transport script to set TCP window to 1234, got %d", tcpPacket.Window)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound SYN-ACK")
	}
}

func TestEchoTCPServiceRespondsToSYNWithChecksumOffloadStyleFrame(t *testing.T) {
	outbound := make(chan []byte, 4)
	routes := []net.IPNet{{
		IP:   net.IPv4(192, 168, 56, 0),
		Mask: net.CIDRMask(24, 32),
	}}
	identity := newTestEngineIdentity(t, fakeIdentity{
		Label:     "echo-host",
		IP:        net.IPv4(192, 168, 56, 10),
		Interface: net.Interface{Name: "eth0"},
		MAC:       adoption.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, routes, func(_ *adoption.Identity, frame buffer.Buffer) error {
		outbound <- append([]byte(nil), bufferBytes(&frame)...)
		frame.Release()
		return nil
	})

	listener := newMemoryTestListener(nil)
	listener.addTestEngine(identity.IP, identity)

	service, err := startManagedService(identity, serviceEchoID, map[string]string{
		"port": "8080",
	}, nil)
	if err != nil {
		t.Fatalf("start echo service: %v", err)
	}
	defer service.stop()

	clientIP := net.IPv4(192, 168, 56, 20)
	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}
	resolveTestNeighbor(t, listener, outbound, clientIP, clientMAC, identity.IP)

	frame := serializeTCPFrame(
		t,
		clientIP,
		identity.IP,
		clientMAC,
		net.HardwareAddr(identity.MAC),
		50505,
		8080,
		100,
		true,
	)
	frame[50] = 0
	frame[51] = 0
	listener.dispatchInboundFrame(buffer.MakeWithData(frame))

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
