package adoption

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	handle *pcap.Handle
	file   *os.File
	buffer *bufio.Writer
	writer *pcapgo.Writer

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	stateMu sync.RWMutex
	state   PacketRecordingStatus
}

func (s *Manager) StartRecording(ip net.IP, outputPath string) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if item.Recording != nil && item.Recording.Active {
		return Identity{}, fmt.Errorf("recording is already active for %s", item.IP)
	}

	deviceName, err := netruntime.CaptureDeviceNameForInterface(item.Interface)
	if err != nil {
		return Identity{}, err
	}
	recorder, err := startPacketRecorder(netruntime.PcapOptions{
		DeviceName:  deviceName,
		BufferSize:  recordingHandleBufferSize,
		ReadTimeout: recordingReadTimeout,
		BPFFilter:   buildRecordingBPFFilter(*item, item.Interface.HardwareAddr),
	}, outputPath)
	if err != nil {
		return Identity{}, err
	}

	if previous := item.StoreRecorder(recorder); previous != nil {
		previous.Stop()
	}
	item.Recording = recorder.snapshot()
	return *item, nil
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
		handle: handle,
		file:   file,
		buffer: buffer,
		writer: writer,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		state: PacketRecordingStatus{
			Active:     true,
			OutputPath: outputPath,
			StartedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		},
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
	var runErr error
	lastFlush := time.Now()

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
		recorder.finish(runErr)
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
			if runErr = flushIfDue(time.Now()); runErr != nil {
				return
			}
			continue
		}
		if err == io.EOF {
			select {
			case <-recorder.stop:
				return
			default:
				runErr = ErrListenerStopped
			}
			return
		}
		if err != nil {
			runErr = err
			return
		}

		if err := recorder.writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(data),
			Length:        len(data),
		}, data); err != nil {
			runErr = fmt.Errorf("write packet to capture file: %w", err)
			return
		}
		if runErr = flushIfDue(time.Now()); runErr != nil {
			return
		}
	}
}

func (recorder *packetRecorder) finish(runErr error) {
	recorder.stateMu.Lock()
	recorder.state.Active = false
	if runErr != nil && runErr != ErrListenerStopped {
		recorder.state.LastError = runErr.Error()
	}
	recorder.stateMu.Unlock()

	if recorder.handle != nil {
		recorder.handle.Close()
	}
	if recorder.buffer != nil {
		_ = recorder.buffer.Flush()
	}
	if recorder.file != nil {
		_ = recorder.file.Close()
	}
}

func (recorder *packetRecorder) Stop() {
	recorder.closeOnce.Do(func() {
		close(recorder.stop)
		<-recorder.done
	})
}

func (recorder *packetRecorder) snapshot() *PacketRecordingStatus {
	recorder.stateMu.RLock()
	defer recorder.stateMu.RUnlock()
	state := recorder.state
	return &state
}
