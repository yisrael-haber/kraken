package netruntime

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const interfaceListenerReadTimeout = 50 * time.Millisecond
const interfaceListenerInitialBPFFilter = "less 1"

type InterfaceListener struct {
	packetIO *InterfacePacketIO
	forward  func(net.IP, buffer.Buffer) bool

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func NewInterfaceListener(iface net.Interface, forward func(net.IP, buffer.Buffer) bool) (*InterfaceListener, error) {
	deviceName, err := CaptureDeviceNameForInterface(iface)
	if err != nil {
		return nil, err
	}
	packetIO, err := OpenInterfacePacketIO(PcapOptions{
		DeviceName:  deviceName,
		ReadTimeout: interfaceListenerReadTimeout,
		BPFFilter:   interfaceListenerInitialBPFFilter,
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

func (listener *InterfaceListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		listener.packetIO.Close()
		<-listener.done
	})
	return nil
}

func (listener *InterfaceListener) PacketIO() *InterfacePacketIO {
	return listener.packetIO
}

func (listener *InterfaceListener) CaptureIPv4Target(ip net.IP) error {
	if err := listener.packetIO.CaptureIPv4Target(ip); err != nil {
		return fmt.Errorf("capture %s: %w", ip, err)
	}
	return nil
}

func (listener *InterfaceListener) dispatchInboundFrame(frame buffer.Buffer) {
	targetIP, ok := classifyInboundFrame(frame.Flatten())
	if ok && listener.forward != nil && listener.forward(targetIP, frame) {
		return
	}
	frame.Release()
}

func (listener *InterfaceListener) run() {
	_ = listener.packetIO.Run(listener.stop, listener.dispatchInboundFrame)
	close(listener.done)
}

func CaptureDeviceNameForInterface(iface net.Interface) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap device enumeration failed: %w", err)
	}

	for _, device := range devices {
		if strings.TrimSpace(device.Name) == iface.Name {
			return device.Name, nil
		}
	}
	for _, device := range devices {
		if name, ok := systemInterfaceName(device.Name); ok && name == iface.Name {
			return device.Name, nil
		}
		if name, ok := systemInterfaceName(device.Description); ok && name == iface.Name {
			return device.Name, nil
		}
	}

	return "", fmt.Errorf("no pcap device matched interface %q", iface.Name)
}

func systemInterfaceName(name string) (string, bool) {
	iface, err := net.InterfaceByName(strings.TrimSpace(name))
	if err == nil && iface.Flags&net.FlagLoopback == 0 {
		return iface.Name, true
	}
	return "", false
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
