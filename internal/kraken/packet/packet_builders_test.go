package packet

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildARPReplyPacketClonesInputs(t *testing.T) {
	adoptedIP := net.ParseIP("192.168.56.10").To4()
	adoptedMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	requesterIP := net.ParseIP("192.168.56.1").To4()
	requesterMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	packet := BuildARPReplyPacket(adoptedIP, adoptedMAC, requesterIP, requesterMAC)

	adoptedIP[3] = 99
	adoptedMAC[5] = 0xaa
	requesterIP[3] = 77
	requesterMAC[5] = 0xbb

	if got := net.IP(packet.ARP.SourceProtAddress).String(); got != "192.168.56.10" {
		t.Fatalf("expected cloned adopted IP, got %s", got)
	}
	if got := net.HardwareAddr(packet.ARP.SourceHwAddress).String(); got != "02:00:00:00:00:10" {
		t.Fatalf("expected cloned adopted MAC, got %s", got)
	}
	if got := net.IP(packet.ARP.DstProtAddress).String(); got != "192.168.56.1" {
		t.Fatalf("expected cloned requester IP, got %s", got)
	}
	if got := net.HardwareAddr(packet.ARP.DstHwAddress).String(); got != "02:00:00:00:00:01" {
		t.Fatalf("expected cloned requester MAC, got %s", got)
	}
}

func TestBuildICMPEchoPacketClonesInputs(t *testing.T) {
	sourceIP := net.ParseIP("192.168.56.10").To4()
	sourceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	targetIP := net.ParseIP("192.168.56.1").To4()
	targetMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	payload := []byte{0x10, 0x11}

	packet := BuildICMPEchoPacket(
		sourceIP,
		sourceMAC,
		targetIP,
		targetMAC,
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		payload,
	)

	sourceIP[3] = 99
	sourceMAC[5] = 0xaa
	targetIP[3] = 77
	targetMAC[5] = 0xbb
	payload[0] = 0xff

	if got := packet.IPv4.SrcIP.String(); got != "192.168.56.10" {
		t.Fatalf("expected cloned source IP, got %s", got)
	}
	if got := packet.Ethernet.SrcMAC.String(); got != "02:00:00:00:00:10" {
		t.Fatalf("expected cloned source MAC, got %s", got)
	}
	if got := packet.IPv4.DstIP.String(); got != "192.168.56.1" {
		t.Fatalf("expected cloned target IP, got %s", got)
	}
	if got := packet.Ethernet.DstMAC.String(); got != "02:00:00:00:00:01" {
		t.Fatalf("expected cloned target MAC, got %s", got)
	}
	if len(packet.Payload) != 2 || packet.Payload[0] != 0x10 {
		t.Fatalf("expected cloned payload, got %v", packet.Payload)
	}
}

func TestParsePayloadHexSupportsCommonFormats(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  []byte
	}{
		{name: "spaced bytes", input: "DE AD BE EF", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "continuous hex", input: "deadbeef", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "0x prefixed bytes", input: "0xDE,0xAD,0xBE,0xEF", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "blank payload", input: "", want: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := ParsePayloadHex(testCase.input)
			if err != nil {
				t.Fatalf("parse payload hex: %v", err)
			}
			if len(got) != len(testCase.want) {
				t.Fatalf("expected %d bytes, got %d", len(testCase.want), len(got))
			}
			for index := range got {
				if got[index] != testCase.want[index] {
					t.Fatalf("expected payload %v, got %v", testCase.want, got)
				}
			}
		})
	}
}

func TestParsePayloadHexRejectsInvalidInput(t *testing.T) {
	_, err := ParsePayloadHex("XYZ")
	if err == nil || (!strings.Contains(err.Error(), "hex") && !strings.Contains(err.Error(), "byte")) {
		t.Fatalf("expected invalid payload hex error, got %v", err)
	}
}

func TestSerializeValidatedIntoHonorsManualLengthsAndChecksums(t *testing.T) {
	packet := BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		[]byte{0x10, 0x11},
	)

	packet.IPv4.Length = 0x4242
	packet.IPv4.Checksum = 0x1111
	packet.ICMPv4.Checksum = 0x2222
	packet.SetSerializationOptions(PacketSerializationOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	})

	buffer := gopacket.NewSerializeBufferExpectedSize(64, len(packet.Payload))
	if err := packet.SerializeValidatedInto(buffer); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	frame := buffer.Bytes()
	if got := binary.BigEndian.Uint16(frame[16:18]); got != 0x4242 {
		t.Fatalf("expected serialized IPv4 length 0x4242, got 0x%04x", got)
	}
	if got := binary.BigEndian.Uint16(frame[24:26]); got != 0x1111 {
		t.Fatalf("expected serialized IPv4 checksum 0x1111, got 0x%04x", got)
	}
	if got := binary.BigEndian.Uint16(frame[36:38]); got != 0x2222 {
		t.Fatalf("expected serialized ICMP checksum 0x2222, got 0x%04x", got)
	}
}
