package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestClassifyOutboundFrameRecognizesLoggedEvents(t *testing.T) {
	tests := []struct {
		name     string
		packet   *packetpkg.OutboundPacket
		event    string
		protocol string
	}{
		{
			name: "arp request",
			packet: packetpkg.BuildARPRequestPacket(
				net.IPv4(192, 168, 56, 10),
				net.HardwareAddr{0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc},
				net.IPv4(192, 168, 56, 1),
			),
			event:    "send-request",
			protocol: "arp",
		},
		{
			name: "arp reply",
			packet: packetpkg.BuildARPReplyPacket(
				net.IPv4(192, 168, 56, 10),
				net.HardwareAddr{0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc},
				net.IPv4(192, 168, 56, 1),
				net.HardwareAddr{0x08, 0x00, 0x27, 0x01, 0x02, 0x03},
			),
			event:    "send-reply",
			protocol: "arp",
		},
		{
			name: "icmp echo reply",
			packet: packetpkg.BuildICMPEchoPacket(
				net.IPv4(192, 168, 56, 10),
				net.HardwareAddr{0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc},
				net.IPv4(192, 168, 56, 1),
				net.HardwareAddr{0x08, 0x00, 0x27, 0x01, 0x02, 0x03},
				layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
				0x1111,
				7,
				[]byte("hello"),
			),
			event:    "send-echo-reply",
			protocol: "icmpv4",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := serializeTestPacket(t, test.packet)
			packet, err := parseScriptablePacket(frame)
			if err != nil {
				t.Fatalf("parse packet: %v", err)
			}
			info := classifyOutboundPacket(packet)
			if info.event != test.event {
				t.Fatalf("expected event %q, got %q", test.event, info.event)
			}
			if info.protocol != test.protocol {
				t.Fatalf("expected protocol %q, got %q", test.protocol, info.protocol)
			}
		})
	}
}

func TestBuildNetstackRoutesAddsDefaultGatewayWhenConfigured(t *testing.T) {
	routes, err := buildNetstackRoutes([]net.IPNet{
		{
			IP:   net.IPv4(192, 168, 56, 0),
			Mask: net.CIDRMask(24, 32),
		},
	}, net.IPv4(192, 168, 56, 1))
	if err != nil {
		t.Fatalf("build routes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if routes[1].Gateway != tcpip.AddrFrom4([4]byte{192, 168, 56, 1}) {
		t.Fatalf("expected gateway route to use 192.168.56.1, got %v", routes[1].Gateway)
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
