package operations

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const adoptionListenerReadTimeout = 50 * time.Millisecond

type adoptionListener struct {
	packetIO *netruntime.InterfacePacketIO

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	stateMu sync.RWMutex
	runErr  error
}

func NewListener(iface net.Interface, forward func(net.IP, buffer.Buffer) bool, lookupScript adoption.ScriptLookupFunc) (adoption.Listener, error) {
	packetIO, err := netruntime.OpenInboundInterfacePump(iface, "adoption listener", adoptionListenerReadTimeout, forward, lookupScript)
	if err != nil {
		return nil, err
	}

	listener := &adoptionListener{
		packetIO: packetIO,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go listener.run()

	return listener, nil
}

func (listener *adoptionListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.stop)
		if listener.packetIO != nil {
			_ = listener.packetIO.Close()
		}
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
	if listener.packetIO == nil {
		return nil
	}
	return listener.packetIO.InterfaceRoutes()
}

func (listener *adoptionListener) PacketIO() *netruntime.InterfacePacketIO {
	return listener.packetIO
}

func (listener *adoptionListener) LookupScript() adoption.ScriptLookupFunc {
	if listener.packetIO == nil {
		return nil
	}
	return listener.packetIO.LookupScript()
}

func (listener *adoptionListener) StartRecording(source *adoption.Identity, outputPath string) (adoption.PacketRecordingStatus, error) {
	if source == nil || source.IP.To4() == nil {
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording requires a valid IPv4 identity")
	}

	if source.Recording != nil && source.Recording.Active {
		return adoption.PacketRecordingStatus{}, fmt.Errorf("recording is already active for %s", source.IP)
	}

	recorder, err := startPacketRecorder(listener.packetIO, *source, outputPath)
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
	raw := bufferBytes(&frame)
	if len(raw) < header.EthernetMinimumSize {
		frame.Release()
		return
	}

	targetIP, ok := classifyInboundFrame(raw)
	if !ok {
		frame.Release()
		return
	}

	if listener.packetIO == nil || !listener.packetIO.ForwardFrame(targetIP, frame) {
		frame.Release()
	}
}

func (listener *adoptionListener) run() {
	err := listener.packetIO.Run(listener.stop, listener.dispatchInboundFrame)
	if err == netruntime.ErrPacketIOClosed {
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
	if listener.packetIO == nil {
		listener.stateMu.Lock()
		listener.runErr = adoption.ErrListenerStopped
		listener.stateMu.Unlock()
		return adoption.ErrListenerStopped
	}
	if err := listener.packetIO.CaptureIPv4Target(ip); err != nil {
		listener.stateMu.Lock()
		listener.runErr = fmt.Errorf("capture %s: %w", ip, err)
		listener.stateMu.Unlock()
		return listener.runErr
	}

	listener.stateMu.Lock()
	listener.runErr = nil
	listener.stateMu.Unlock()
	return nil
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
		target := ipv4.DestinationAddress().As4()
		return target[:], true
	default:
		return nil, false
	}
}

func bufferBytes(frame *buffer.Buffer) []byte {
	return frame.Flatten()
}
