package netruntime

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/buffer"
)

const CaptureSnapLen = 65535

var ErrPcapReadTimeout = errors.New("pcap read timed out")

type PcapOptions struct {
	DeviceName  string
	BufferSize  int
	ReadTimeout time.Duration
	BPFFilter   string
	Direction   pcap.Direction
}

type InterfacePacketIO struct {
	handle *pcap.Handle
}

func OpenInterfacePacketIO(options PcapOptions) (*InterfacePacketIO, error) {
	handle, err := OpenPcapHandle(options)
	if err != nil {
		return nil, err
	}
	return &InterfacePacketIO{handle: handle}, nil
}

func (pump *InterfacePacketIO) LinkType() layers.LinkType {
	return pump.handle.LinkType()
}

func OpenPcapHandle(options PcapOptions) (*pcap.Handle, error) {
	var handle *pcap.Handle
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
					handle, err = inactive.Activate()
				}
			}
		}
	}

	if handle == nil {
		handle, err = pcap.OpenLive(options.DeviceName, CaptureSnapLen, true, options.ReadTimeout)
		if err != nil {
			return nil, fmt.Errorf("open pcap on %s: %w", options.DeviceName, err)
		}
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
			return nil, fmt.Errorf("set pcap capture direction on %s: %w", options.DeviceName, err)
		}
	}
	return handle, nil
}

func (pump *InterfacePacketIO) Write(frame *buffer.Buffer) error {
	defer frame.Release()
	return pump.handle.WritePacketData(frame.Flatten())
}

func (pump *InterfacePacketIO) Close() {
	pump.handle.Close()
}

func (pump *InterfacePacketIO) read() (buffer.Buffer, error) {
	frame, _, err := pump.handle.ZeroCopyReadPacketData()
	if err == pcap.NextErrorTimeoutExpired {
		return buffer.Buffer{}, ErrPcapReadTimeout
	}
	if err != nil {
		return buffer.Buffer{}, err
	}
	return buffer.MakeWithData(frame), nil
}

func (pump *InterfacePacketIO) Run(stop <-chan struct{}, dispatch func(buffer.Buffer)) error {
	for {
		select {
		case <-stop:
			return nil
		default:
		}

		frame, err := pump.read()
		if err == ErrPcapReadTimeout {
			continue
		}
		if err == io.EOF {
			select {
			case <-stop:
				return nil
			default:
				return io.EOF
			}
		}
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}

		dispatch(frame)
	}
}

func (pump *InterfacePacketIO) SetBPFFilter(filter string) error {
	return pump.handle.SetBPFFilter(filter)
}

func (pump *InterfacePacketIO) CaptureIPv4Target(ip net.IP) error {
	ip = ip.To4()
	if ip == nil {
		return pump.SetBPFFilter("")
	}
	return pump.SetBPFFilter(fmt.Sprintf("(arp and (arp dst host %s)) or (ip and (dst host %s))", ip, ip))
}
