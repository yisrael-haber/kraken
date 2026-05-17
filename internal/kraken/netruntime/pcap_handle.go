package netruntime

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/buffer"
)

const CaptureSnapLen = 65535
const inactiveBPFFilter = "less 1"

var (
	ErrPacketIOClosed  = errors.New("pcap handle is closed")
	ErrPcapReadTimeout = errors.New("pcap read timed out")
)

type PcapOptions struct {
	DeviceName    string
	InterfaceName string
	Purpose       string
	BufferSize    int
	ReadTimeout   time.Duration
	BPFFilter     string
	Direction     pcap.Direction
}

type PcapHandle struct {
	handle *pcap.Handle
}

type InterfacePacketIO struct {
	options     PcapOptions
	handle      *PcapHandle
	iface       net.Interface
	routes      []net.IPNet
	forward     func(net.IP, buffer.Buffer) bool
	writePacket func([]byte) error
	mu          sync.Mutex
}

func NewInterfacePacketIO(forward func(net.IP, buffer.Buffer) bool, writePacket ...func([]byte) error) *InterfacePacketIO {
	pump := &InterfacePacketIO{forward: forward}
	if len(writePacket) != 0 {
		pump.writePacket = writePacket[0]
	}
	return pump
}

func OpenInboundInterfacePump(iface net.Interface, purpose string, readTimeout time.Duration, forward func(net.IP, buffer.Buffer) bool) (*InterfacePacketIO, error) {
	deviceName, err := CaptureDeviceNameForInterface(iface)
	if err != nil {
		return nil, err
	}

	pump, err := openInterfacePacketIO(PcapOptions{
		DeviceName:    deviceName,
		InterfaceName: iface.Name,
		Purpose:       purpose,
		ReadTimeout:   readTimeout,
		BPFFilter:     inactiveBPFFilter,
		Direction:     pcap.DirectionIn,
	})
	if err != nil {
		return nil, err
	}
	pump.iface = iface
	pump.routes = interfaceIPv4Networks(iface)
	pump.forward = forward
	return pump, nil
}

func openInterfacePacketIO(options PcapOptions) (*InterfacePacketIO, error) {
	handle, err := OpenPcapHandle(options)
	if err != nil {
		return nil, err
	}
	return &InterfacePacketIO{
		options: options,
		handle:  handle,
	}, nil
}

func (pump *InterfacePacketIO) InterfaceRoutes() []net.IPNet {
	return pump.routes
}

func (pump *InterfacePacketIO) ForwardFrame(destinationIP net.IP, frame buffer.Buffer) bool {
	return pump.forward != nil && pump.forward(destinationIP, frame)
}

func (pump *InterfacePacketIO) OpenRecorder(filter string, readTimeout time.Duration, bufferSize int) (*PcapHandle, error) {
	return OpenPcapHandle(PcapOptions{
		DeviceName:    pump.options.DeviceName,
		InterfaceName: pump.options.InterfaceName,
		Purpose:       "recording listener",
		BufferSize:    bufferSize,
		ReadTimeout:   readTimeout,
		BPFFilter:     filter,
	})
}

func (pump *InterfacePacketIO) InterfaceHardwareAddr() net.HardwareAddr {
	return pump.iface.HardwareAddr
}

func OpenPcapHandle(options PcapOptions) (*PcapHandle, error) {
	handle, err := openCaptureHandle(options)
	if err != nil {
		return nil, err
	}

	if options.BPFFilter != "" {
		if err := handle.SetBPFFilter(options.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("set pcap capture filter: %w", err)
		}
	}
	if options.Direction != 0 {
		if err := handle.SetDirection(options.Direction); err != nil {
			handle.Close()
			return nil, fmt.Errorf("set pcap capture direction on %s: %w", options.InterfaceName, err)
		}
	}

	return &PcapHandle{handle: handle}, nil
}

func openCaptureHandle(options PcapOptions) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(options.DeviceName)
	if err == nil {
		defer inactive.CleanUp()

		if err := inactive.SetSnapLen(CaptureSnapLen); err == nil {
			if err := inactive.SetPromisc(true); err == nil {
				if err := inactive.SetTimeout(options.ReadTimeout); err == nil {
					if options.BufferSize > 0 {
						_ = inactive.SetBufferSize(options.BufferSize)
					}
					_ = inactive.SetImmediateMode(true)
					handle, err := inactive.Activate()
					if err == nil {
						return handle, nil
					}
				}
			}
		}
	}

	handle, err := pcap.OpenLive(options.DeviceName, CaptureSnapLen, true, options.ReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("open %s on %s: %w", options.Purpose, options.InterfaceName, err)
	}
	return handle, nil
}

func (pcapHandle *PcapHandle) Close() error {
	if pcapHandle.handle == nil {
		return nil
	}
	pcapHandle.handle.Close()
	pcapHandle.handle = nil
	return nil
}

func (pcapHandle *PcapHandle) Read() (buffer.Buffer, error) {
	if pcapHandle.handle == nil {
		return buffer.Buffer{}, ErrPacketIOClosed
	}

	frame, _, err := pcapHandle.handle.ZeroCopyReadPacketData()
	if err == pcap.NextErrorTimeoutExpired {
		return buffer.Buffer{}, ErrPcapReadTimeout
	}
	if err != nil {
		return buffer.Buffer{}, err
	}
	return buffer.MakeWithData(frame), nil
}

func (pcapHandle *PcapHandle) Write(frame *buffer.Buffer) error {
	if pcapHandle.handle == nil {
		return ErrPacketIOClosed
	}

	return pcapHandle.handle.WritePacketData(frame.Flatten())
}

func (pump *InterfacePacketIO) Write(frame *buffer.Buffer) error {
	defer frame.Release()
	if pump.writePacket != nil {
		return pump.writePacket(frame.Flatten())
	}
	pump.mu.Lock()
	handle := pump.handle
	if handle == nil {
		pump.mu.Unlock()
		return ErrPacketIOClosed
	}
	err := handle.Write(frame)
	pump.mu.Unlock()
	return err
}

func (pump *InterfacePacketIO) Close() error {
	pump.mu.Lock()
	defer pump.mu.Unlock()
	if pump.handle == nil {
		return nil
	}
	err := pump.handle.Close()
	pump.handle = nil
	return err
}

func (pump *InterfacePacketIO) read() (buffer.Buffer, error) {
	pump.mu.Lock()
	handle := pump.handle
	if handle == nil {
		pump.mu.Unlock()
		return buffer.Buffer{}, ErrPacketIOClosed
	}
	frame, err := handle.Read()
	pump.mu.Unlock()
	return frame, err
}

func (pump *InterfacePacketIO) Run(stop <-chan struct{}, dispatch func(buffer.Buffer)) error {
	for {
		if stopped(stop) {
			return nil
		}

		frame, err := pump.read()
		if err == ErrPcapReadTimeout {
			continue
		}
		if err == ErrPacketIOClosed || err == io.EOF {
			return stoppedErr(stop, ErrPacketIOClosed)
		}
		if err != nil {
			return stoppedErr(stop, err)
		}

		dispatch(frame)
	}
}

func stopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func stoppedErr(stop <-chan struct{}, err error) error {
	if stopped(stop) {
		return nil
	}
	return err
}

func (pump *InterfacePacketIO) SetBPFFilter(filter string) error {
	if filter == "" {
		filter = inactiveBPFFilter
	}
	pump.mu.Lock()
	defer pump.mu.Unlock()
	if filter == pump.options.BPFFilter {
		return nil
	}

	options := pump.options
	options.BPFFilter = filter
	handle, err := OpenPcapHandle(options)
	if err != nil {
		return err
	}

	previous := pump.handle
	pump.handle = handle
	pump.options = options
	if previous != nil {
		_ = previous.Close()
	}
	return nil
}

func (pump *InterfacePacketIO) CaptureIPv4Target(ip net.IP) error {
	ip = ip.To4()
	if ip == nil {
		return pump.SetBPFFilter("")
	}
	return pump.SetBPFFilter(fmt.Sprintf("(arp and (arp dst host %s)) or (ip and (dst host %s))", ip, ip))
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
		if ip == nil {
			continue
		}

		networks = append(networks, net.IPNet{
			IP:   ip.Mask(ipNet.Mask),
			Mask: ipNet.Mask,
		})
	}

	return networks
}
