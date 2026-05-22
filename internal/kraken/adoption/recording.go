package adoption

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
)

const (
	recordingHandleBufferSize = 4 << 20
	recordingWriterBufferSize = 1 << 20
	recordingFlushInterval    = time.Second
	recordingReadTimeout      = 250 * time.Millisecond
)

type packetRecorder struct {
	handle    *pcap.Handle
	file      *os.File
	buffer    *bufio.Writer
	output    string
	startedAt string

	stop chan struct{}
	done chan struct{}
}

func startPacketRecorder(options netruntime.PcapOptions, outputPath string) (*packetRecorder, error) {
	handle, err := netruntime.OpenPcapHandle(options)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		handle.Close()
		return nil, fmt.Errorf("create recording directory: %w", err)
	}
	file, err := os.Create(outputPath)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("create recording file %q: %w", outputPath, err)
	}

	buffer := bufio.NewWriterSize(file, recordingWriterBufferSize)
	writer := pcapgo.NewWriter(buffer)
	if err := writer.WriteFileHeader(netruntime.CaptureSnapLen, layers.LinkTypeEthernet); err != nil {
		_ = file.Close()
		handle.Close()
		return nil, fmt.Errorf("write pcap file header: %w", err)
	}
	if err := buffer.Flush(); err != nil {
		_ = file.Close()
		handle.Close()
		return nil, fmt.Errorf("flush pcap file header: %w", err)
	}

	recorder := &packetRecorder{
		handle:    handle,
		file:      file,
		buffer:    buffer,
		output:    outputPath,
		startedAt: time.Now().UTC().Format(time.RFC3339Nano),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go recorder.run()
	return recorder, nil
}

func buildRecordingBPFFilter(identity Identity, ifaceMAC net.HardwareAddr) string {
	ipText := identity.IP.String()
	clauses := []string{
		fmt.Sprintf("(ip host %s)", ipText),
		fmt.Sprintf("(arp and (arp src host %s or arp dst host %s))", ipText, ipText),
	}

	mac := net.HardwareAddr(identity.MAC)
	if len(mac) != 0 && !bytes.Equal(mac, ifaceMAC) {
		clauses = append(clauses, fmt.Sprintf("(ether host %s)", mac.String()))
	}
	return strings.Join(clauses, " or ")
}

func (recorder *packetRecorder) run() {
	lastFlush := time.Now()
	writer := pcapgo.NewWriter(recorder.buffer)

	flushIfDue := func(now time.Time) error {
		if now.Sub(lastFlush) < recordingFlushInterval {
			return nil
		}
		if err := recorder.buffer.Flush(); err != nil {
			return fmt.Errorf("flush recording buffer: %w", err)
		}
		lastFlush = now
		return nil
	}

	defer func() {
		recorder.handle.Close()
		_ = recorder.buffer.Flush()
		_ = recorder.file.Close()
		close(recorder.done)
	}()

	for {
		select {
		case <-recorder.stop:
			return
		default:
		}

		data, _, err := recorder.handle.ZeroCopyReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			if err := flushIfDue(time.Now()); err != nil {
				return
			}
			continue
		}
		if err != nil {
			return
		}

		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(data),
			Length:        len(data),
		}, data); err != nil {
			return
		}
		if err := flushIfDue(time.Now()); err != nil {
			return
		}
	}
}

func (recorder *packetRecorder) Stop() {
	close(recorder.stop)
	<-recorder.done
}

func (recorder *packetRecorder) Status() *PacketRecordingStatus {
	if recorder == nil {
		return nil
	}
	return &PacketRecordingStatus{
		Active:     true,
		OutputPath: recorder.output,
		StartedAt:  recorder.startedAt,
	}
}
