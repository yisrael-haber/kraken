package operations

import (
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestPingWithDialerReportsEchoReplies(t *testing.T) {
	conn := &pingTestConn{}
	result, err := PingWithDialer(PingAdoptedIPAddressRequest{
		SourceIP:       "192.0.2.10",
		Destination:    "192.0.2.1",
		IntervalMillis: 1,
		TimeoutMillis:  100,
		Count:          2,
		PayloadSize:    0,
	}, func(net.IP, uint16) (net.Conn, error) {
		return conn, nil
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
	_, err := PingWithDialer(PingAdoptedIPAddressRequest{Destination: "example.com"}, nil)
	if err == nil {
		t.Fatal("expected invalid destination error")
	}
}

type pingTestConn struct {
	reply []byte
}

func (conn *pingTestConn) Read(dst []byte) (int, error) {
	if len(conn.reply) == 0 {
		return 0, &pingTestTimeout{}
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
func (*pingTestConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (*pingTestConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (*pingTestConn) SetDeadline(time.Time) error      { return nil }
func (*pingTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*pingTestConn) SetWriteDeadline(time.Time) error { return nil }

type pingTestTimeout struct{}

func (*pingTestTimeout) Error() string   { return "i/o timeout" }
func (*pingTestTimeout) Timeout() bool   { return true }
func (*pingTestTimeout) Temporary() bool { return true }
