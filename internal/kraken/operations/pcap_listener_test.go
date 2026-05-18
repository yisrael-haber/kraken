package operations

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"gvisor.dev/gvisor/pkg/buffer"
)

type fakeIdentity = adoption.Identity

func newMemoryTestListener(forward func(net.IP, buffer.Buffer) bool) *adoptionListener {
	return &adoptionListener{packetIO: &netruntime.InterfacePacketIO{}, forward: forward}
}

func TestPcapAdoptionListenerHealthy(t *testing.T) {
	t.Run("reports stopped listener", func(t *testing.T) {
		listener := &adoptionListener{}

		if err := listener.Healthy(); !errors.Is(err, adoption.ErrListenerStopped) {
			t.Fatalf("expected ErrListenerStopped, got %v", err)
		}
	})
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
	if got := arpInfo.String(); got != "192.168.56.10" {
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
	if got := ipv4Info.String(); got != "192.168.56.10" {
		t.Fatalf("expected IPv4 target IP 192.168.56.10, got %s", got)
	}
}

func TestPcapAdoptionListenerDispatchesDirectForwarding(t *testing.T) {
	forwardCalls := 0
	listener := newMemoryTestListener(
		func(destinationIP net.IP, frame buffer.Buffer) bool {
			if destinationIP.String() != "10.0.0.99" {
				t.Fatalf("expected forwarded destination IP 10.0.0.99, got %s", destinationIP)
			}
			forwardCalls++
			frame.Release()
			return true
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

	if forwardCalls != 1 {
		t.Fatalf("expected direct forwarding once, got %d", forwardCalls)
	}
}

func TestPcapAdoptionListenerDispatchesRoutedForwarding(t *testing.T) {
	forwardCalls := 0
	listener := newMemoryTestListener(
		func(destinationIP net.IP, frame buffer.Buffer) bool {
			if destinationIP.String() != "10.0.0.99" {
				return false
			}
			forwardCalls++
			frame.Release()
			return true
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

	if forwardCalls != 1 {
		t.Fatalf("expected routed forwarding once, got %d", forwardCalls)
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

	return serializeTestLayers(t, 0,
		&layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(layers.ARPRequest),
			SourceHwAddress:   sourceMAC,
			SourceProtAddress: sourceIP.To4(),
			DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
			DstProtAddress:    targetIP.To4(),
		},
	)
}

func serializeICMPEchoTestPacket(t *testing.T, sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) []byte {
	t.Helper()

	return serializeTestLayers(t, len(payload),
		&layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    sourceIP.To4(),
			DstIP:    targetIP.To4(),
		},
		&layers.ICMPv4{
			TypeCode: typeCode,
			Id:       id,
			Seq:      sequence,
		},
		gopacket.Payload(payload),
	)
}

func serializeTestLayers(t *testing.T, payloadSize int, items ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBufferExpectedSize(64, payloadSize)
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, items...); err != nil {
		t.Fatalf("serialize frame: %v", err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}
