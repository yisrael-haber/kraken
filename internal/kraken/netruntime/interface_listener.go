package netruntime

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type InterfaceListener struct {
	handle  *pcap.Handle
	forward func(net.IP, buffer.Buffer) bool

	done      chan struct{}
	closeOnce sync.Once
}

func NewInterfaceListener(iface net.Interface, forward func(net.IP, buffer.Buffer) bool) (*InterfaceListener, error) {
	handle, err := OpenPcapHandle(PcapOptions{
		DeviceName:  iface.Name,
		ReadTimeout: 50 * time.Millisecond,
		BPFFilter:   "less 1",
		Direction:   pcap.DirectionIn,
	})
	if err != nil {
		return nil, err
	}

	listener := &InterfaceListener{
		handle:  handle,
		forward: forward,
		done:    make(chan struct{}),
	}
	go listener.run()
	return listener, nil
}

func (listener *InterfaceListener) Close() {
	listener.closeOnce.Do(func() {
		listener.handle.Close()
		<-listener.done
	})
}

func (listener *InterfaceListener) Write(frame []byte) error {
	return listener.handle.WritePacketData(frame)
}

func (listener *InterfaceListener) SetCaptureFilter(filter string) error {
	if err := listener.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set interface capture filter: %w", err)
	}
	return nil
}

func (listener *InterfaceListener) run() {
	defer close(listener.done)
	for {
		data, _, err := listener.handle.ZeroCopyReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return
		}

		frame := buffer.MakeWithData(data)
		targetIP, ok := classifyInboundFrame(&frame)
		if !ok || !listener.forward(targetIP, frame) {
			frame.Release()
		}
	}
}

func classifyInboundFrame(frame *buffer.Buffer) (net.IP, bool) {
	ethernetView, ok := frame.PullUp(0, header.EthernetMinimumSize)
	if !ok {
		return nil, false
	}

	switch header.Ethernet(ethernetView.AsSlice()).Type() {
	case header.ARPProtocolNumber:
		arpView, ok := frame.PullUp(header.EthernetMinimumSize, header.ARPSize)
		if !ok {
			return nil, false
		}
		arp := header.ARP(arpView.AsSlice())
		if !arp.IsValid() {
			return nil, false
		}
		return net.IP(arp.ProtocolAddressTarget()), true
	case header.IPv4ProtocolNumber:
		ipv4View, ok := frame.PullUp(header.EthernetMinimumSize, header.IPv4MinimumSize)
		if !ok {
			return nil, false
		}
		ipv4 := header.IPv4(ipv4View.AsSlice())
		if !ipv4.IsValid(int(frame.Size()) - header.EthernetMinimumSize) {
			return nil, false
		}
		return net.IP(ipv4.DestinationAddressSlice()), true
	default:
		return nil, false
	}
}
