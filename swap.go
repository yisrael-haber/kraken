package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

var (
	swapDummyCounter atomic.Uint32
	swapQueueCounter atomic.Uint32
)

// allocateDummyIPs returns two unique link-local IPs used internally by a swap
// session's gVisor stacks. They are never advertised on the network — every
// egress packet is rewritten to the real client or server IP before it leaves.
func allocateDummyIPs() (srvDummy, cliDummy net.IP) {
	n := swapDummyCounter.Add(1)
	srvDummy = net.IP{169, 254, 201, byte(n & 0xff)}
	cliDummy = net.IP{169, 254, 202, byte(n & 0xff)}
	return
}

func allocateQueueNum() uint16 {
	// Start at 100 to avoid collisions with tools that default to queue 0.
	n := swapQueueCounter.Add(1)
	return uint16(100 + (n-1)%65436)
}

// swapSession holds all runtime state for one active MITM interception.
type swapSession struct {
	client net.IP
	server net.IP
	port   uint16
	iface  net.Interface

	clientNetstack *adoptedNetstack // srvDummy IP — acts as the server toward the client
	serverNetstack *adoptedNetstack // cliDummy IP — acts as the client toward the server

	// Optional L5+ transform hooks. nil = pass-through (mirror).
	clientToServer func([]byte) []byte
	serverToClient func([]byte) []byte

	// Optional path for a pcapng capture of the intercepted session.
	// Inbound packets (real IPs, before rewrite) and outbound packets
	// (real IPs, after mod) are both written to the same file.
	capturePath string

	cancel context.CancelFunc
	done   chan struct{} // closed when the session goroutine exits
}

type swapTable struct {
	mu       sync.Mutex
	sessions map[string]*swapSession
}

var globalSwaps = &swapTable{sessions: make(map[string]*swapSession)}

func (t *swapTable) key(client, server net.IP, port uint16) string {
	return fmt.Sprintf("%s|%s|%d", client, server, port)
}

func (t *swapTable) add(s *swapSession) {
	t.mu.Lock()
	t.sessions[t.key(s.client, s.server, s.port)] = s
	t.mu.Unlock()
}

func (t *swapTable) remove(client, server net.IP, port uint16) {
	t.mu.Lock()
	delete(t.sessions, t.key(client, server, port))
	t.mu.Unlock()
}

// classifySwapPacket inspects a raw IPv4 payload and reports which direction
// the packet is travelling relative to the monitored 3-tuple.
//
//   toServer == true  → client→server path (dst rewrite target: srvDummy)
//   toServer == false → server→client path (dst rewrite target: cliDummy)
//   ok == false       → payload too short or IPs don't match the 3-tuple
func classifySwapPacket(payload []byte, client, server net.IP) (toServer bool, ok bool) {
	if len(payload) < 20 {
		return false, false
	}
	srcIP := net.IP(payload[12:16])
	dstIP := net.IP(payload[16:20])
	switch {
	case srcIP.Equal(client) && dstIP.Equal(server):
		return true, true
	case srcIP.Equal(server) && dstIP.Equal(client):
		return false, true
	default:
		return false, false
	}
}

// runBridge copies data bidirectionally between clientConn and serverConn.
// Each direction passes through an optional transform (nil = identity).
// Blocks until both sides close.
func runBridge(
	clientConn, serverConn net.Conn,
	clientToServer, serverToClient func([]byte) []byte,
) {
	var wg sync.WaitGroup
	wg.Add(2)

	forward := func(dst, src net.Conn, transform func([]byte) []byte) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				data := buf[:n]
				if transform != nil {
					data = transform(data)
				}
				dst.Write(data)
			}
			if err != nil {
				dst.Close()
				return
			}
		}
	}

	go forward(serverConn, clientConn, clientToServer)
	go forward(clientConn, serverConn, serverToClient)
	wg.Wait()
}
