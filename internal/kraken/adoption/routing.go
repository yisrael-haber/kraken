package adoption

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"gvisor.dev/gvisor/pkg/buffer"
)

const routingInitialFilter = "less 1"

func (s *Manager) startRouting() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.routingPacketIO != nil {
		return nil
	}
	packetIO, err := netruntime.OpenInterfacePacketIO(netruntime.PcapOptions{
		DeviceName:  "any",
		ReadTimeout: 50 * time.Millisecond,
		BPFFilter:   routingInitialFilter,
		Direction:   pcap.DirectionIn,
	})
	if err != nil {
		return err
	}
	s.routingPacketIO = packetIO
	s.routingStop = make(chan struct{})
	s.routingDone = make(chan struct{})
	go s.runRouting(packetIO, s.routingStop, packetIO.LinkType())
	return s.refreshRoutingCaptureLocked()
}

func (s *Manager) runRouting(packetIO *netruntime.InterfacePacketIO, stop <-chan struct{}, linkType layers.LinkType) {
	_ = packetIO.Run(stop, func(frame buffer.Buffer) {
		data := frame.Flatten()
		frame.Release()
		packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
		layer := packet.Layer(layers.LayerTypeIPv4)
		if layer == nil {
			return
		}
		ipv4 := layer.(*layers.IPv4)
		raw := append(append([]byte(nil), layer.LayerContents()...), layer.LayerPayload()...)
		out := buffer.MakeWithData(raw)
		if !s.ForwardFrame(ipv4.DstIP.To4(), out) {
			out.Release()
		}
	})
	close(s.routingDone)
}

func (s *Manager) refreshRoutingCaptureLocked() error {
	if s.routingPacketIO == nil {
		return nil
	}
	return s.routingPacketIO.SetBPFFilter(s.routingFilterLocked())
}

func (s *Manager) routingFilterLocked() string {
	var clauses []string
	for _, identity := range s.entries {
		ip := identity.IP.To4()
		mask := net.IPMask(identity.SubnetMask)
		ones, bits := mask.Size()
		if ip == nil || ones < 0 || bits != 32 {
			continue
		}
		clauses = append(clauses, fmt.Sprintf("(ip and dst net %s/%d and not dst host %s)", ip.Mask(mask), ones, ip))
	}
	if len(clauses) == 0 {
		return routingInitialFilter
	}
	return strings.Join(clauses, " or ")
}
