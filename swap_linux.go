//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func checkIPForwarding() error {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("cannot read ip_forward: %w", err)
	}
	if strings.TrimSpace(string(data)) != "1" {
		return fmt.Errorf(
			"IP forwarding is not enabled\n" +
				"  enable with: echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
	}
	return nil
}

// resolveSwapMAC returns the MAC for ip, checking the global ARP cache first
// and falling back to an ARP request from the interface's own IP/MAC on a miss.
func resolveSwapMAC(devName string, iface net.Interface, ip net.IP) (net.HardwareAddr, error) {
	if mac, ok := globalARPCache.lookup(ip); ok {
		return mac, nil
	}
	ifaceIP, err := ifaceIPv4(iface)
	if err != nil {
		return nil, err
	}
	mac, err := arpRequest(devName, iface.HardwareAddr, ifaceIP, ip)
	if err != nil {
		return nil, fmt.Errorf("ARP for %s failed: %w", ip, err)
	}
	globalARPCache.set(ip, mac)
	return mac, nil
}

// setupNftables creates an isolated nftables table named "kraken_<queueNum>"
// with a forward chain containing two rules that divert the targeted 3-tuple
// (both directions) to queueNum. Returns a cleanup func that drops the table.
func setupNftables(queueNum uint16, client, server net.IP, port uint16) (func(), error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables connect: %w", err)
	}

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   fmt.Sprintf("kraken_%d", queueNum),
	})

	policyAccept := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{
		Name:     "intercept",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyAccept,
	})

	portBytes := []byte{byte(port >> 8), byte(port)}
	tcpProto := []byte{unix.IPPROTO_TCP}

	// Rule 1: client → server:port
	c.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: client.To4()},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: server.To4()},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: tcpProto},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes},
			&expr.Queue{Num: queueNum},
		},
	})

	// Rule 2: server:port → client (return traffic)
	c.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: server.To4()},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: client.To4()},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: tcpProto},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes},
			&expr.Queue{Num: queueNum},
		},
	})

	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("nftables flush: %w", err)
	}

	cleanup := func() {
		c2, err := nftables.New()
		if err != nil {
			return
		}
		c2.DelTable(table)
		c2.Flush()
	}
	return cleanup, nil
}

func startSwap(s *swapSession) error {
	if err := checkIPForwarding(); err != nil {
		return err
	}

	srvDummy, cliDummy := allocateDummyIPs()
	queueNum := allocateQueueNum()

	devName, err := pcapDeviceName(s.iface)
	if err != nil {
		return fmt.Errorf("swap: %w", err)
	}

	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	if err != nil {
		return fmt.Errorf("swap: pcap: %w", err)
	}

	clientMAC, err := resolveSwapMAC(devName, s.iface, s.client)
	if err != nil {
		handle.Close()
		return fmt.Errorf("swap: %w", err)
	}
	serverMAC, err := resolveSwapMAC(devName, s.iface, s.server)
	if err != nil {
		handle.Close()
		return fmt.Errorf("swap: %w", err)
	}

	// Create a shared capture dumper for this session if requested.
	// Inbound packets (original, real IPs) are written by the NFQUEUE handler.
	// Outbound packets (after mod, real IPs) are written by runOutbound on each netstack.
	var sessionDumper *pcapDumper
	if s.capturePath != "" {
		sessionDumper, err = newPcapDumper(s.capturePath, layers.LinkTypeRaw)
		if err != nil {
			handle.Close()
			return fmt.Errorf("swap: capture: %w", err)
		}
		fmt.Printf("[swap] capturing session to %s\n", s.capturePath)
	}

	// clientNetstack: uses srvDummy IP, acts as the server toward the client.
	// Egress mod: rewrite src → real server IP, bypass ARP to client's MAC.
	clientNS, err := newAdoptedNetstack(srvDummy, s.iface.HardwareAddr, s.iface, handle, "")
	if err != nil {
		if sessionDumper != nil {
			sessionDumper.close()
		}
		handle.Close()
		return fmt.Errorf("swap: client netstack: %w", err)
	}
	clientNS.setMod(packetMod{IPSrc: s.server.To4(), EthDst: clientMAC})
	if sessionDumper != nil {
		clientNS.setDumper(sessionDumper)
	}

	// serverNetstack: uses cliDummy IP, acts as the client toward the server.
	// Egress mod: rewrite src → real client IP, bypass ARP to server's MAC.
	serverNS, err := newAdoptedNetstack(cliDummy, s.iface.HardwareAddr, s.iface, handle, "")
	if err != nil {
		clientNS.stop()
		if sessionDumper != nil {
			sessionDumper.close()
		}
		handle.Close()
		return fmt.Errorf("swap: server netstack: %w", err)
	}
	serverNS.setMod(packetMod{IPSrc: s.client.To4(), EthDst: serverMAC})
	if sessionDumper != nil {
		serverNS.setDumper(sessionDumper)
	}

	s.clientNetstack = clientNS
	s.serverNetstack = serverNS

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})

	// Register accept handler on clientNS before installing nftables rules so
	// no SYN arrives before we are listening.
	clientConnCh := make(chan net.Conn, 1)
	clientNS.listen(s.port, func(conn net.Conn) {
		select {
		case clientConnCh <- conn:
		default:
			conn.Close()
		}
	})

	// Install nftables rules — interception begins here.
	nftCleanup, err := setupNftables(queueNum, s.client, s.server, s.port)
	if err != nil {
		cancel()
		serverNS.stop()
		clientNS.stop()
		handle.Close()
		return err
	}

	// Open NFQUEUE. nfq is assigned before RegisterWithErrorFunc starts
	// delivering packets, so the handler closure captures the correct pointer.
	var nfq *nfqueue.Nfqueue
	handler := func(attrs nfqueue.Attribute) int {
		id := *attrs.PacketID
		payload := *attrs.Payload

		toServer, ok := classifySwapPacket(payload, s.client, s.server)
		if !ok {
			nfq.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		var ns *adoptedNetstack
		var rewriteDst net.IP
		if toServer {
			ns, rewriteDst = clientNS, srvDummy
		} else {
			ns, rewriteDst = serverNS, cliDummy
		}

		rewritten := applyPacketMod(payload, packetMod{IPDst: rewriteDst})
		ns.injectInboundRaw(rewritten)
		nfq.SetVerdict(id, nfqueue.NfDrop)
		return 0
	}

	nfq, err = nfqueue.Open(&nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  256,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		nftCleanup()
		cancel()
		serverNS.stop()
		clientNS.stop()
		handle.Close()
		return fmt.Errorf("swap: nfqueue open: %w", err)
	}

	if err := nfq.RegisterWithErrorFunc(ctx, handler, func(e error) int {
		if ctx.Err() == nil {
			fmt.Printf("[swap] nfqueue: %v\n", e)
		}
		return 0
	}); err != nil {
		nfq.Close()
		nftCleanup()
		cancel()
		serverNS.stop()
		clientNS.stop()
		handle.Close()
		return fmt.Errorf("swap: nfqueue register: %w", err)
	}

	fmt.Printf("[swap] intercepting %s → %s:%d\n", s.client, s.server, s.port)

	go func() {
		defer func() {
			close(s.done)
			nfq.Close()
			nftCleanup()
			cancel()
			serverNS.stop()
			clientNS.stop()
			handle.Close()
			globalSwaps.remove(s.client, s.server, s.port)
			fmt.Printf("[swap] session %s → %s:%d ended\n", s.client, s.server, s.port)
		}()

		// Dial the real server after NFQUEUE is active so the SYN-ACK is intercepted.
		serverConnCh := make(chan net.Conn, 1)
		serverErrCh := make(chan error, 1)
		go func() {
			conn, err := serverNS.dial(ctx, s.server, s.port)
			if err != nil {
				serverErrCh <- err
				return
			}
			serverConnCh <- conn
		}()

		var clientConn, serverConn net.Conn
		pending := 2
		for pending > 0 {
			select {
			case err := <-serverErrCh:
				fmt.Printf("[swap] server dial failed: %v\n", err)
				if clientConn != nil {
					clientConn.Close()
				}
				return
			case c := <-serverConnCh:
				serverConn = c
				pending--
				fmt.Printf("[swap] connected to server %s:%d\n", s.server, s.port)
			case c := <-clientConnCh:
				clientConn = c
				pending--
				fmt.Printf("[swap] client connected\n")
			case <-ctx.Done():
				if clientConn != nil {
					clientConn.Close()
				}
				if serverConn != nil {
					serverConn.Close()
				}
				return
			}
		}

		fmt.Printf("[swap] bridge active — mirroring %s ↔ %s:%d\n", s.client, s.server, s.port)
		runBridge(clientConn, serverConn, s.clientToServer, s.serverToClient)
	}()

	return nil
}
