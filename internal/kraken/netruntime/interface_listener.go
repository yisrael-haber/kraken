package netruntime

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type InterfaceListener struct {
	packetIO *InterfacePacketIO
	forward  func(net.IP, buffer.Buffer) bool

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func NewInterfaceListener(iface net.Interface, forward func(net.IP, buffer.Buffer) bool) (*InterfaceListener, error) {
	selection := interfaces.List()
	if selection.Warning != "" {
		return nil, fmt.Errorf("%s", selection.Warning)
	}
	if !slices.Contains(selection.Options, iface.Name) {
		return nil, fmt.Errorf("no pcap device matched interface %q", iface.Name)
	}
	packetIO, err := OpenInterfacePacketIO(PcapOptions{
		DeviceName:  iface.Name,
		ReadTimeout: 50 * time.Millisecond,
		BPFFilter:   "less 1",
		Direction:   pcap.DirectionIn,
	})
	if err != nil {
		return nil, err
	}

	listener := &InterfaceListener{
		packetIO: packetIO,
		forward:  forward,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go listener.run()
	return listener, nil
}

func (listener *InterfaceListener) Close() {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		listener.packetIO.Close()
		<-listener.done
	})
}

func (listener *InterfaceListener) Write(frame *buffer.Buffer) error {
	return listener.packetIO.Write(frame)
}

func (listener *InterfaceListener) CaptureIPv4Target(ip net.IP) error {
	filter := fmt.Sprintf("(arp and (arp dst host %s)) or (ip and (dst host %s))", ip, ip)
	if err := listener.packetIO.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("capture %s: %w", ip, err)
	}
	return nil
}

func (listener *InterfaceListener) dispatchInboundFrame(frame buffer.Buffer) {
	targetIP, ok := classifyInboundFrame(frame.Flatten())
	if ok && listener.forward(targetIP, frame) {
		return
	}
	frame.Release()
}

func (listener *InterfaceListener) run() {
	_ = listener.packetIO.Run(listener.stop, listener.dispatchInboundFrame)
	close(listener.done)
}

func classifyInboundFrame(frame []byte) (net.IP, bool) {
	if len(frame) < header.EthernetMinimumSize {
		return nil, false
	}

	payload := frame[header.EthernetMinimumSize:]
	switch header.Ethernet(frame).Type() {
	case header.ARPProtocolNumber:
		if len(payload) < header.ARPSize {
			return nil, false
		}
		arp := header.ARP(payload)
		if !arp.IsValid() {
			return nil, false
		}
		return net.IP(arp.ProtocolAddressTarget()), true
	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(payload)
		if !ipv4.IsValid(len(payload)) {
			return nil, false
		}
		return net.IP(ipv4.DestinationAddressSlice()), true
	default:
		return nil, false
	}
}
