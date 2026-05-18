package operations

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const adoptionListenerReadTimeout = 50 * time.Millisecond
const adoptionListenerInitialBPFFilter = "less 1"

type adoptionListener struct {
	packetIO     *netruntime.InterfacePacketIO
	forward      func(net.IP, buffer.Buffer) bool
	deviceName   string
	hardwareAddr net.HardwareAddr
	routes       []net.IPNet

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	stateMu sync.RWMutex
	runErr  error
}

func NewListener(iface net.Interface, forward func(net.IP, buffer.Buffer) bool) (adoption.Listener, error) {
	deviceName, err := captureDeviceNameForInterface(iface)
	if err != nil {
		return nil, err
	}
	packetIO, err := netruntime.OpenInterfacePacketIO(netruntime.PcapOptions{
		DeviceName:  deviceName,
		ReadTimeout: adoptionListenerReadTimeout,
		BPFFilter:   adoptionListenerInitialBPFFilter,
		Direction:   pcap.DirectionIn,
	})
	if err != nil {
		return nil, err
	}

	listener := &adoptionListener{
		packetIO:     packetIO,
		forward:      forward,
		deviceName:   deviceName,
		hardwareAddr: iface.HardwareAddr,
		routes:       interfaceIPv4Networks(iface),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	go listener.run()

	return listener, nil
}

func (listener *adoptionListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		listener.packetIO.Close()
		<-listener.done
	})
	return nil
}

func (listener *adoptionListener) Healthy() error {
	if listener.done == nil {
		return adoption.ErrListenerStopped
	}

	listener.stateMu.RLock()
	runErr := listener.runErr
	listener.stateMu.RUnlock()
	if runErr != nil {
		return runErr
	}

	select {
	case <-listener.done:
		return adoption.ErrListenerStopped
	default:
		return nil
	}
}

func (listener *adoptionListener) InterfaceRoutes() []net.IPNet {
	return listener.routes
}

func (listener *adoptionListener) PacketIO() *netruntime.InterfacePacketIO {
	return listener.packetIO
}

func (listener *adoptionListener) StartRecording(source *adoption.Identity, outputPath string) (adoption.PacketRecordingStatus, error) {
	if source == nil || source.IP.To4() == nil {
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording requires a valid IPv4 identity")
	}

	if source.Recording != nil && source.Recording.Active {
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording is already active for %s", source.IP)
	}

	recorder, err := startPacketRecorder(netruntime.PcapOptions{
		DeviceName:  listener.deviceName,
		BufferSize:  recordingHandleBufferSize,
		ReadTimeout: recordingReadTimeout,
		BPFFilter:   buildRecordingBPFFilter(*source, listener.hardwareAddr),
	}, outputPath)
	if err != nil {
		return adoption.PacketRecordingStatus{}, err
	}

	previous := source.StoreRecorder(recorder)
	if previous != nil {
		previous.Stop()
	}

	return recorder.snapshot(), nil
}

func (listener *adoptionListener) dispatchInboundFrame(frame buffer.Buffer) {
	targetIP, ok := classifyInboundFrame(frame.Flatten())
	if ok && listener.forward != nil && listener.forward(targetIP, frame) {
		return
	}
	frame.Release()
}

func (listener *adoptionListener) run() {
	err := listener.packetIO.Run(listener.stop, listener.dispatchInboundFrame)
	if err == io.EOF {
		err = adoption.ErrListenerStopped
	}
	if err != nil {
		listener.stateMu.Lock()
		if listener.runErr == nil {
			listener.runErr = err
		}
		listener.stateMu.Unlock()
	}
	close(listener.done)
}

func (listener *adoptionListener) CaptureIPv4Target(ip net.IP) error {
	err := listener.packetIO.CaptureIPv4Target(ip)
	if err != nil {
		err = fmt.Errorf("capture %s: %w", ip, err)
	}

	listener.stateMu.Lock()
	listener.runErr = err
	listener.stateMu.Unlock()
	return err
}

func interfaceIPv4Networks(iface net.Interface) []net.IPNet {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	networks := make([]net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip != nil {
			networks = append(networks, net.IPNet{IP: ip.Mask(ipNet.Mask), Mask: ipNet.Mask})
		}
	}
	return networks
}

func captureDeviceNameForInterface(iface net.Interface) (string, error) {
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
