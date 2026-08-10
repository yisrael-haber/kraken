package operations

import (
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestPingWithDialerReportsEchoReplies(t *testing.T) {
	result, err := PingWithDialer(PingAdoptedIPAddressRequest{
		Destination:    "192.0.2.1",
		IntervalMillis: 1,
		TimeoutMillis:  100,
		Count:          2,
	}, func(net.IP) (net.Conn, error) {
		return &pingTestConn{}, nil
	})
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	if result.Sent != 2 || result.Received != 2 || result.LossPercent != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, probe := range result.Probes {
		if probe.Status != "reply" || probe.Bytes != header.ICMPv4MinimumSize {
			t.Fatalf("unexpected probe: %+v", probe)
		}
	}
}

func TestPingRequestRejectsInvalidDestination(t *testing.T) {
	if _, err := PingWithDialer(PingAdoptedIPAddressRequest{Destination: "example.com"}, nil); err == nil {
		t.Fatal("expected invalid destination error")
	}
}

type pingTestConn struct {
	reply []byte
}

func (conn *pingTestConn) Read(dst []byte) (int, error) {
	if len(conn.reply) == 0 {
		panic("read without a prepared reply")
	}
	n := copy(dst, conn.reply)
	conn.reply = nil
	return n, nil
}

func (conn *pingTestConn) Write(request []byte) (int, error) {
	conn.reply = append(conn.reply[:0], request...)
	header.ICMPv4(conn.reply).SetType(header.ICMPv4EchoReply)
	return len(request), nil
}

func (*pingTestConn) Close() error                     { return nil }
func (*pingTestConn) LocalAddr() net.Addr              { return nil }
func (*pingTestConn) RemoteAddr() net.Addr             { return nil }
func (*pingTestConn) SetDeadline(time.Time) error      { return nil }
func (*pingTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*pingTestConn) SetWriteDeadline(time.Time) error { return nil }
