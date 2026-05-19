package operations

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"gvisor.dev/gvisor/pkg/buffer"
)

const routingListenerDeviceName = "any"

type routingListener struct {
	packetIO *netruntime.InterfacePacketIO
	forward  func(net.IP, buffer.Buffer) bool
	stop     chan struct{}
	done     chan struct{}
}

func NewRoutingListener(forward func(net.IP, buffer.Buffer) bool) (adoption.RoutingListener, error) {
	packetIO, err := netruntime.OpenInterfacePacketIO(netruntime.PcapOptions{
		DeviceName:  routingListenerDeviceName,
		ReadTimeout: adoptionListenerReadTimeout,
		BPFFilter:   adoptionListenerInitialBPFFilter,
		Direction:   pcap.DirectionIn,
	})
	if err != nil {
		return nil, err
	}

	listener := &routingListener{
		packetIO: packetIO,
		forward:  forward,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go listener.run()
	return listener, nil
}

func (listener *routingListener) Close() error {
	close(listener.stop)
	listener.packetIO.Close()
	<-listener.done
	return nil
}

func (listener *routingListener) CaptureIPv4Segments(identities []adoption.Identity) error {
	return listener.packetIO.SetBPFFilter(buildRoutingBPFFilter(identities))
}

func (listener *routingListener) run() {
	linkType := listener.packetIO.LinkType()
	_ = listener.packetIO.Run(listener.stop, func(frame buffer.Buffer) {
		data := frame.Flatten()
		frame.Release()
		packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
		layer := packet.Layer(layers.LayerTypeIPv4)
		if layer == nil {
			return
		}
		ipv4 := layer.(*layers.IPv4)
		raw := make([]byte, 0, len(layer.LayerContents())+len(layer.LayerPayload()))
		raw = append(raw, layer.LayerContents()...)
		raw = append(raw, layer.LayerPayload()...)
		out := buffer.MakeWithData(raw)
		if !listener.forward(ipv4.DstIP.To4(), out) {
			out.Release()
		}
	})
	close(listener.done)
}
func buildRoutingBPFFilter(identities []adoption.Identity) string {
	if len(identities) == 0 {
		return adoptionListenerInitialBPFFilter
	}

	clauses := make([]string, 0, len(identities))
	for _, identity := range identities {
		ip := identity.IP.To4()
		mask := net.IPMask(identity.SubnetMask)
		ones, bits := mask.Size()
		if ip == nil || ones < 0 || bits != 32 {
			continue
		}
		clauses = append(clauses, fmt.Sprintf("(ip and dst net %s/%d and not dst host %s)", ip.Mask(mask), ones, ip))
	}
	if len(clauses) == 0 {
		return adoptionListenerInitialBPFFilter
	}
	return strings.Join(clauses, " or ")
}
