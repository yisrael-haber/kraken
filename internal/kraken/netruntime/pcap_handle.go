package netruntime

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/buffer"
)

const CaptureSnapLen = 65535

var (
	ErrPcapHandleClosed = errors.New("pcap handle is closed")
	ErrPcapReadTimeout  = errors.New("pcap read timed out")
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
		return buffer.Buffer{}, ErrPcapHandleClosed
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
		return ErrPcapHandleClosed
	}

	return pcapHandle.handle.WritePacketData(frame.Flatten())
}
