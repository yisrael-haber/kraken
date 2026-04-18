package capture

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	adoptedNetstackNICID      = tcpip.NICID(1)
	adoptedNetstackDefaultMTU = 1500
)

type compactIPv4 struct {
	addr  [net.IPv4len]byte
	valid bool
}

type compactMAC struct {
	addr  [6]byte
	valid bool
}

func adoptedNetstackMTU(ifaceName string, override uint32) uint32 {
	if override >= 68 {
		return override
	}
	if iface, err := net.InterfaceByName(ifaceName); err == nil && iface.MTU > 0 {
		return uint32(iface.MTU)
	}
	return adoptedNetstackDefaultMTU
}

func compactIPv4FromIP(ip net.IP) compactIPv4 {
	ipv4 := common.NormalizeIPv4(ip)
	if ipv4 == nil {
		return compactIPv4{}
	}

	var addr [net.IPv4len]byte
	copy(addr[:], ipv4)
	return compactIPv4{
		addr:  addr,
		valid: true,
	}
}

func compactIPv4FromSlice(raw []byte) compactIPv4 {
	if len(raw) < net.IPv4len {
		return compactIPv4{}
	}

	var addr [net.IPv4len]byte
	copy(addr[:], raw[:net.IPv4len])
	return compactIPv4{
		addr:  addr,
		valid: true,
	}
}

func (ip compactIPv4) IP() net.IP {
	if !ip.valid {
		return nil
	}

	return net.IPv4(ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]).To4()
}

func compactMACFromSlice(raw []byte) compactMAC {
	if len(raw) < 6 {
		return compactMAC{}
	}

	allZero := true
	for _, part := range raw[:6] {
		if part != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return compactMAC{}
	}

	var addr [6]byte
	copy(addr[:], raw[:6])
	return compactMAC{
		addr:  addr,
		valid: true,
	}
}

func (mac compactMAC) HardwareAddr() net.HardwareAddr {
	if !mac.valid {
		return nil
	}

	addr := make(net.HardwareAddr, len(mac.addr))
	copy(addr, mac.addr[:])
	return addr
}

type netstackPingReply struct {
	id       uint16
	sequence uint16
	success  bool
	rtt      time.Duration
}

func buildNetstackRoutes(routes []net.IPNet, defaultGateway net.IP) ([]tcpip.Route, error) {
	items := make([]tcpip.Route, 0, len(routes)+1)
	for _, route := range routes {
		subnet, ok := ipNetToTCPIPSubnet(route)
		if !ok {
			continue
		}
		items = append(items, tcpip.Route{
			Destination: subnet,
			NIC:         adoptedNetstackNICID,
		})
	}

	gateway := common.NormalizeIPv4(defaultGateway)
	if gateway != nil {
		items = append(items, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			Gateway:     tcpip.AddrFrom4Slice(gateway.To4()),
			NIC:         adoptedNetstackNICID,
		})
	} else if len(items) == 0 {
		items = append(items, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         adoptedNetstackNICID,
		})
	}

	return items, nil
}

func ipNetToTCPIPSubnet(route net.IPNet) (tcpip.Subnet, bool) {
	ip := common.NormalizeIPv4(route.IP)
	if ip == nil || len(route.Mask) != net.IPv4len {
		return tcpip.Subnet{}, false
	}

	subnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4Slice(ip.Mask(route.Mask)),
		tcpip.MaskFromBytes(route.Mask),
	)
	if err != nil {
		return tcpip.Subnet{}, false
	}

	return subnet, true
}

func appendPacketBufferTo(dst []byte, packet *stack.PacketBuffer) []byte {
	if packet == nil {
		return dst[:0]
	}

	total := len(dst) + packet.Size()
	if cap(dst) < total {
		expanded := make([]byte, len(dst), total)
		copy(expanded, dst)
		dst = expanded
	}

	position := len(dst)
	dst = dst[:total]
	views, offset := packet.AsViewList()
	for view := views.Front(); view != nil; view = view.Next() {
		raw := view.AsSlice()
		if offset >= len(raw) {
			offset -= len(raw)
			continue
		}
		raw = raw[offset:]
		offset = 0
		position += copy(dst[position:], raw)
	}

	return dst[:position]
}

func packetBufferSlice(packet *stack.PacketBuffer) ([]byte, bool) {
	if packet == nil {
		return nil, false
	}

	views, offset := packet.AsViewList()
	view := views.Front()
	if view == nil || view.Next() != nil {
		return nil, false
	}

	raw := view.AsSlice()
	if offset > len(raw) {
		return nil, false
	}

	raw = raw[offset:]
	if len(raw) != packet.Size() {
		return nil, false
	}

	return raw, true
}

var errPingReadTimeout = errors.New("timed out waiting for ICMP reply")

func writeICMPEchoRequest(endpoint tcpip.Endpoint, sequence uint16, payload []byte) error {
	message := make([]byte, header.ICMPv4MinimumSize+len(payload))
	icmpMessage := header.ICMPv4(message)
	icmpMessage.SetType(header.ICMPv4Echo)
	icmpMessage.SetCode(header.ICMPv4UnusedCode)
	icmpMessage.SetSequence(sequence)
	copy(icmpMessage.Payload(), payload)

	if _, err := endpoint.Write(bytes.NewReader(message), tcpip.WriteOptions{}); err != nil {
		return fmt.Errorf("write ICMP echo request: %s", err)
	}

	return nil
}

func waitForICMPEchoReply(endpoint tcpip.Endpoint, wq *waiter.Queue, sequence uint16, sentAt time.Time, timeout time.Duration) (time.Duration, bool, error) {
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 2048)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, false, nil
		}

		count, err := readEndpointWithTimeout(endpoint, wq, buffer, remaining)
		if err != nil {
			if errors.Is(err, errPingReadTimeout) {
				return 0, false, nil
			}
			return 0, false, err
		}
		if count < header.ICMPv4MinimumSize {
			continue
		}

		icmpMessage := header.ICMPv4(buffer[:count])
		if icmpMessage.Type() != header.ICMPv4EchoReply || icmpMessage.Sequence() != sequence {
			continue
		}

		return time.Since(sentAt), true, nil
	}
}

func readEndpointWithTimeout(endpoint tcpip.Endpoint, wq *waiter.Queue, dst []byte, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		return 0, errPingReadTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	options := tcpip.ReadOptions{}
	reader := func() (int, tcpip.Error) {
		writer := tcpip.SliceWriter(dst)
		result, err := endpoint.Read(&writer, options)
		if err != nil {
			return 0, err
		}
		return result.Count, nil
	}

	count, err := reader()
	if _, wouldBlock := err.(*tcpip.ErrWouldBlock); wouldBlock {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)

		for {
			count, err = reader()
			if _, wouldBlock := err.(*tcpip.ErrWouldBlock); !wouldBlock {
				break
			}

			select {
			case <-timer.C:
				return 0, errPingReadTimeout
			case <-notifyCh:
			}
		}
	}

	if _, closed := err.(*tcpip.ErrClosedForReceive); closed {
		return 0, io.EOF
	}
	if err != nil {
		return 0, errors.New(err.String())
	}

	return count, nil
}
