package capture

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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

	if script.ctx.Adopted.Label != "Lab Host" {
		t.Fatalf("expected adopted label to be preserved, got %q", script.ctx.Adopted.Label)
	}
}

func TestBuildBoundPacketScriptSkipsContextWithoutScript(t *testing.T) {
	script := buildBoundPacketScript(fakeIdentity{
		label: "Lab Host",
		ip:    net.ParseIP("192.168.56.10").To4(),
		iface: net.Interface{Name: "eth0"},
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	})

	if script.ctx.ScriptName != "" {
		t.Fatalf("expected empty script name, got %q", script.ctx.ScriptName)
	}
	if script.ctx.Adopted.Label != "" || script.ctx.Adopted.IP != "" || script.ctx.Adopted.MAC != "" {
		t.Fatalf("expected adopted context to stay empty when no script is bound, got %+v", script.ctx.Adopted)
	}
}

func TestClassifyInboundFrameRecognizesAdoptedARPAndICMP(t *testing.T) {
	arpInfo, ok := classifyInboundFrame(serializeTestPacket(t, packetpkg.BuildARPRequestPacket(
		net.IPv4(192, 168, 56, 20),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x20},
		net.IPv4(192, 168, 56, 10),
	)))
	if !ok {
		t.Fatal("expected ARP request to classify")
	}
	if arpInfo.protocol != "arp" || arpInfo.arpOp != header.ARPRequest {
		t.Fatalf("expected ARP request classification, got %+v", arpInfo)
	}
	if got := arpInfo.targetIP.String(); got != "192.168.56.10" {
		t.Fatalf("expected ARP target IP 192.168.56.10, got %s", got)
	}

	icmpInfo, ok := classifyInboundFrame(serializeTestPacket(t, packetpkg.BuildICMPEchoPacket(
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
	if icmpInfo.protocol != "icmpv4" || icmpInfo.icmpType != header.ICMPv4Echo {
		t.Fatalf("expected ICMP echo request classification, got %+v", icmpInfo)
	}
	if icmpInfo.icmpID != 7 || icmpInfo.icmpSeq != 3 {
		t.Fatalf("expected id=7 seq=3, got id=%d seq=%d", icmpInfo.icmpID, icmpInfo.icmpSeq)
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
