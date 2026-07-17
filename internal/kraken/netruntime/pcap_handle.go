package netruntime

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

const CaptureSnapLen = 65535

type PcapOptions struct {
	DeviceName  string
	BufferSize  int
	ReadTimeout time.Duration
	BPFFilter   string
	Direction   pcap.Direction
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
	if err := inactive.SetPromisc(true); err != nil {
		return nil, fmt.Errorf("enable pcap promiscuous mode on %s: %w", options.DeviceName, err)
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
