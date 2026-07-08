package script

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/mandiant/gopacket/pkg/dcerpc"
)

func TestDCERPCModuleUsesOpenTCPSocket(t *testing.T) {
	identity := &scriptRPCSocketIdentity{}
	compiled, err := CompileGeneric("dcerpc", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
	identity = ctx.identities["10.0.0.1"]
	print(len(dcerpc.uuid("12345678-1234-5678-90ab-cdef01234567")))
	conn = socket.tcp(identity, "10.0.0.5:135")
	client = dcerpc.tcp(conn)
	client.bind("12345678-1234-5678-90ab-cdef01234567", major=1, minor=0)
	print(client.call(7, b"request"))
	client.close()
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{
			IP:             "10.0.0.1",
			SocketIdentity: identity,
		}},
	})
	if err != nil {
		t.Fatalf("execute generic script: %v\n%s", err, result.Stderr)
	}

	expected := strings.Join([]string{
		"16",
		`b"response"`,
		"",
	}, "\n")
	if result.Stdout != expected {
		t.Fatalf("unexpected output:\n%s", result.Stdout)
	}
	if identity.tcpIP != "10.0.0.5" || identity.tcpPort != 135 {
		t.Fatalf("unexpected tcp dial target %s:%d", identity.tcpIP, identity.tcpPort)
	}
	if identity.err != nil {
		t.Fatalf("fake rpc server failed: %v", identity.err)
	}
}

func TestDCERPCModuleTakesSocketOwnership(t *testing.T) {
	identity := &scriptRPCSocketIdentity{}
	compiled, err := CompileGeneric("dcerpc-ownership", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
	conn = socket.tcp(ctx.identities["10.0.0.1"], "10.0.0.5:135")
	client = dcerpc.tcp(conn)
	client.close()
	conn.close()
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{
			IP:             "10.0.0.1",
			SocketIdentity: identity,
		}},
	})
	if err == nil {
		t.Fatalf("expected transferred connection to reject direct close")
	}
	if !strings.Contains(result.Stderr, "socket.connection is owned by dcerpc.client") {
		t.Fatalf("unexpected stderr:\n%s", result.Stderr)
	}
}

func TestDCERPCModuleRejectsUDPSocket(t *testing.T) {
	identity := &scriptRPCSocketIdentity{}
	compiled, err := CompileGeneric("dcerpc-udp", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
	conn = socket.udp(ctx.identities["10.0.0.1"], "10.0.0.5:135")
	dcerpc.tcp(conn)
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{
			IP:             "10.0.0.1",
			SocketIdentity: identity,
		}},
	})
	if err == nil {
		t.Fatalf("expected dcerpc.tcp to reject udp connection")
	}
	if !strings.Contains(result.Stderr, "dcerpc.tcp requires a TCP connection from kraken/socket.tcp") {
		t.Fatalf("unexpected stderr:\n%s", result.Stderr)
	}
}

func TestDCERPCModuleCallAuthRequiresAuthenticatedBind(t *testing.T) {
	identity := &scriptRPCSocketIdentity{serve: func(net.Conn) error { return nil }}
	compiled, err := CompileGeneric("dcerpc-auth-required", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
	client = dcerpc.tcp(socket.tcp(ctx.identities["10.0.0.1"], "10.0.0.5:135"))
	client.call_auth(0, b"request")
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{
			IP:             "10.0.0.1",
			SocketIdentity: identity,
		}},
	})
	if err == nil {
		t.Fatalf("expected call_auth to require bind_auth")
	}
	if !strings.Contains(result.Stderr, "not authenticated") {
		t.Fatalf("unexpected stderr:\n%s", result.Stderr)
	}
}

func TestDCERPCModuleEndpointMapperLookup(t *testing.T) {
	identity := &scriptRPCSocketIdentity{serve: serveEndpointMapperRPC}
	compiled, err := CompileGeneric("dcerpc-epm", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
	conn = socket.tcp(ctx.identities["10.0.0.1"], "10.0.0.5:135")
	client = dcerpc.tcp(conn)
	endpoints = client.epm_lookup()
	print(len(endpoints))
	endpoint = endpoints[0]
	print(endpoint.uuid)
	print(endpoint.version)
	print(endpoint.major)
	print(endpoint.minor)
	print(endpoint.annotation)
	print(endpoint.bindings[0])
	binding = endpoint.tcp_binding()
	print(binding.host)
	print(binding.port)
	print(binding.address)
	print(endpoint.tcp_bindings[0].raw)
	client.close()
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{
			IP:             "10.0.0.1",
			SocketIdentity: identity,
		}},
	})
	if err != nil {
		t.Fatalf("execute generic script: %v\n%s", err, result.Stderr)
	}

	expected := strings.Join([]string{
		"1",
		"12345678-1234-5678-90AB-CDEF01234567",
		"v1.0",
		"1",
		"0",
		"Sample",
		"ncacn_ip_tcp:10.0.0.5[49664]",
		"10.0.0.5",
		"49664",
		"10.0.0.5:49664",
		"ncacn_ip_tcp:10.0.0.5[49664]",
		"",
	}, "\n")
	if result.Stdout != expected {
		t.Fatalf("unexpected output:\n%s", result.Stdout)
	}
	if identity.err != nil {
		t.Fatalf("fake epm server failed: %v", identity.err)
	}
}

func TestDCERPCModuleEndpointMapperFind(t *testing.T) {
	identity := &scriptRPCSocketIdentity{serve: serveEndpointMapperRPC}
	compiled, err := CompileGeneric("dcerpc-epm-find", `
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
	client = dcerpc.tcp(socket.tcp(ctx.identities["10.0.0.1"], "10.0.0.5:135"))
	endpoint = client.epm_find(uuid="12345678-1234-5678-90ab-cdef01234567", major=1)
	print(endpoint.uuid)
	print(endpoint.tcp_binding().address)
	print(client.epm_find(uuid="12345678-1234-5678-90ab-cdef01234567", major=None).major)
	print(client.epm_find(uuid="aaaaaaaa-1234-5678-90ab-cdef01234567") == None)
	client.close()
`)
	if err != nil {
		t.Fatalf("compile generic script: %v", err)
	}

	result, err := ExecuteGeneric(compiled, ExecutionContext{
		Identities: []ExecutionIdentity{{
			IP:             "10.0.0.1",
			SocketIdentity: identity,
		}},
	})
	if err != nil {
		t.Fatalf("execute generic script: %v\n%s", err, result.Stderr)
	}

	expected := strings.Join([]string{
		"12345678-1234-5678-90AB-CDEF01234567",
		"10.0.0.5:49664",
		"1",
		"True",
		"",
	}, "\n")
	if result.Stdout != expected {
		t.Fatalf("unexpected output:\n%s", result.Stdout)
	}
	if identity.err != nil {
		t.Fatalf("fake epm server failed: %v", identity.err)
	}
}

type scriptRPCSocketIdentity struct {
	tcpIP   string
	tcpPort int
	err     error
	serve   func(net.Conn) error
}

func (identity *scriptRPCSocketIdentity) DialScriptTCP(_ context.Context, ip net.IP, port int, _ SocketOptions) (net.Conn, error) {
	identity.tcpIP = ip.String()
	identity.tcpPort = port
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		serve := identity.serve
		if serve == nil {
			serve = serveMinimalRPC
		}
		identity.err = serve(server)
	}()
	return client, nil
}

func (identity *scriptRPCSocketIdentity) DialScriptUDP(net.IP, int, SocketOptions) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func serveMinimalRPC(conn net.Conn) error {
	header, err := readRPCHeader(conn)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.LittleEndian.Uint16(header[8:10])-16)); err != nil {
		return err
	}
	if _, err := conn.Write(rpcHeader(12, 0x03, 16, 1)); err != nil {
		return err
	}

	header, err = readRPCHeader(conn)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.LittleEndian.Uint16(header[8:10])-16)); err != nil {
		return err
	}
	responseBody := append([]byte{8, 0, 0, 0, 0, 0, 0, 0}, []byte("response")...)
	_, err = conn.Write(append(rpcHeader(2, 0x03, uint16(16+len(responseBody)), 2), responseBody...))
	return err
}

func serveEndpointMapperRPC(conn net.Conn) error {
	header, err := readRPCHeader(conn)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.LittleEndian.Uint16(header[8:10])-16)); err != nil {
		return err
	}
	if _, err := conn.Write(rpcHeader(12, 0x03, 16, 1)); err != nil {
		return err
	}

	header, err = readRPCHeader(conn)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.LittleEndian.Uint16(header[8:10])-16)); err != nil {
		return err
	}
	responseBody := append([]byte{0, 0, 0, 0, 0, 0, 0, 0}, endpointMapperLookupStub()...)
	_, err = conn.Write(append(rpcHeader(2, 0x03, uint16(16+len(responseBody)), 2), responseBody...))
	return err
}

func endpointMapperLookupStub() []byte {
	var response []byte
	response = append(response, make([]byte, 20)...)
	response = appendLittleEndianUint32(response, 1) // num_ents
	response = appendLittleEndianUint32(response, 1) // max_count
	response = appendLittleEndianUint32(response, 0) // offset
	response = appendLittleEndianUint32(response, 1) // actual_count
	response = append(response, make([]byte, 16)...)
	response = appendLittleEndianUint32(response, 1) // tower pointer
	response = appendLittleEndianUint32(response, 0) // annotation offset
	annotation := []byte("Sample\x00")
	response = appendLittleEndianUint32(response, uint32(len(annotation)))
	response = append(response, annotation...)
	response = appendNDRPadding(response)

	tower := endpointMapperTower()
	response = appendLittleEndianUint32(response, uint32(len(tower)))
	response = appendLittleEndianUint32(response, uint32(len(tower)))
	response = append(response, tower...)
	response = appendNDRPadding(response)
	response = appendLittleEndianUint32(response, 0) // status
	return response
}

func endpointMapperTower() []byte {
	var tower []byte
	tower = appendLittleEndianUint16(tower, 3)
	uuid, _ := dcerpc.ParseUUID("12345678-1234-5678-90ab-cdef01234567")
	lhs := append([]byte{0x0d}, uuid[:]...)
	lhs = appendLittleEndianUint16(lhs, 1)
	tower = appendTowerFloor(tower, lhs, []byte{0, 0})
	tower = appendTowerFloor(tower, []byte{0x07}, []byte{0xc2, 0x00})
	tower = appendTowerFloor(tower, []byte{0x09}, []byte{10, 0, 0, 5})
	return tower
}

func appendTowerFloor(data, lhs, rhs []byte) []byte {
	data = appendLittleEndianUint16(data, uint16(len(lhs)))
	data = append(data, lhs...)
	data = appendLittleEndianUint16(data, uint16(len(rhs)))
	data = append(data, rhs...)
	return data
}

func appendLittleEndianUint16(data []byte, value uint16) []byte {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], value)
	return append(data, buf[:]...)
}

func appendLittleEndianUint32(data []byte, value uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	return append(data, buf[:]...)
}

func appendNDRPadding(data []byte) []byte {
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	return data
}

func readRPCHeader(conn net.Conn) ([]byte, error) {
	header := make([]byte, 16)
	_, err := io.ReadFull(conn, header)
	return header, err
}

func rpcHeader(packetType, flags byte, fragmentLength uint16, callID uint32) []byte {
	header := make([]byte, 16)
	header[0] = 5
	header[2] = packetType
	header[3] = flags
	header[4] = 0x10
	binary.LittleEndian.PutUint16(header[8:10], fragmentLength)
	binary.LittleEndian.PutUint32(header[12:16], callID)
	return header
}
