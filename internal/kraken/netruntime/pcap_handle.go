package netruntime

import (
	"fmt"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/buffer"
)

const CaptureSnapLen = 65535

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
	inactive, err := pcap.NewInactiveHandle(options.DeviceName)
	if err != nil {
		return nil, fmt.Errorf("open pcap on %s: %w", options.DeviceName, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(CaptureSnapLen); err != nil {
		return nil, fmt.Errorf("set pcap snapshot length on %s: %w", options.DeviceName, err)
	}
	if options.DeviceName != "any" {
		if err := inactive.SetPromisc(true); err != nil {
			return nil, fmt.Errorf("enable pcap promiscuous mode on %s: %w", options.DeviceName, err)
		}
	}
	if err := inactive.SetTimeout(options.ReadTimeout); err != nil {
		return nil, fmt.Errorf("set pcap read timeout on %s: %w", options.DeviceName, err)
	}
	if options.BufferSize > 0 {
		if err := inactive.SetBufferSize(options.BufferSize); err != nil {
			return nil, fmt.Errorf("set pcap buffer size on %s: %w", options.DeviceName, err)
		}
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("enable pcap immediate mode on %s: %w", options.DeviceName, err)
	}
	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate pcap on %s: %w", options.DeviceName, err)
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
	if pump.handle != nil {
		pump.handle.Close()
	}
}

func (pump *InterfacePacketIO) Run(stop <-chan struct{}, dispatch func(buffer.Buffer)) error {
	for {
		select {
		case <-stop:
			return nil
		default:
		}

		data, _, err := pump.handle.ZeroCopyReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}

		dispatch(buffer.MakeWithData(data))
	}
}

func (pump *InterfacePacketIO) SetBPFFilter(filter string) error {
	return pump.handle.SetBPFFilter(filter)
}
