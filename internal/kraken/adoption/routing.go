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

func (s *Manager) openRouting() error {
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
	linkType := packetIO.LinkType()
	go func() {
		_ = packetIO.Run(nil, func(frame buffer.Buffer) {
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
	}()
	return nil
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
		mask := net.IPMask(identity.SubnetMask)
		ones, _ := mask.Size()
		clauses = append(clauses, fmt.Sprintf("(ip and dst net %s/%d and not dst host %s)", identity.IP.Mask(mask), ones, identity.IP))
	}
	if len(clauses) == 0 {
		return routingInitialFilter
	}
	return strings.Join(clauses, " or ")
}
