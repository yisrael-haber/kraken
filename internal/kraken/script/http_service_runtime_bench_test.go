package script

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

func BenchmarkExecutePacketNoOp(b *testing.B) {
	storedScript := benchmarkPacketScript(b, `def main(packet, ctx):
    pass
`)
	ctx := ExecutionContext{
		ScriptName: storedScript.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		packet := benchmarkMutablePacket(b, packetpkg.BuildICMPEchoPacket(
			net.ParseIP("192.168.56.10").To4(),
			net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
			net.ParseIP("192.168.56.1").To4(),
			net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
			7,
			1,
			[]byte("hello"),
		))
		if _, err := Execute(storedScript, packet, ctx, nil); err != nil {
			b.Fatalf("execute packet script: %v", err)
		}
		packet.Release()
	}
}

func BenchmarkExecuteHTTPRequestNoOp(b *testing.B) {
	storedScript := benchmarkHTTPServiceScript(b, `def on_request(request, ctx):
    return None
`)
	ctx := benchmarkHTTPExecutionContext()
	request := benchmarkHTTPRequest()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		item := request
		response, err := ExecuteHTTPRequest(storedScript, &item, ctx, nil)
		if err != nil {
			b.Fatalf("execute HTTP request hook: %v", err)
		}
		if response != nil {
			b.Fatal("expected request hook to continue to handler")
		}
	}
}

func BenchmarkExecuteHTTPRequestShortCircuit(b *testing.B) {
	storedScript := benchmarkHTTPServiceScript(b, `bytes = require("kraken/bytes")

def on_request(request, ctx):
    body = bytes.fromASCII("blocked")
    return struct(
        statusCode = 451,
        reason = "Unavailable",
        version = "HTTP/1.1",
        headers = [struct(name = "Content-Length", value = str(len(body)))],
        body = body,
    )
`)
	ctx := benchmarkHTTPExecutionContext()
	request := benchmarkHTTPRequest()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		item := request
		response, err := ExecuteHTTPRequest(storedScript, &item, ctx, nil)
		if err != nil {
			b.Fatalf("execute HTTP request short-circuit hook: %v", err)
		}
		if response == nil || response.StatusCode != 451 {
			b.Fatalf("expected short-circuit response, got %+v", response)
		}
	}
}

func BenchmarkExecuteHTTPResponseNoOp(b *testing.B) {
	storedScript := benchmarkHTTPServiceScript(b, `def on_response(request, response, ctx):
    return None
`)
	ctx := benchmarkHTTPExecutionContext()
	request := benchmarkHTTPRequest()
	response := benchmarkHTTPResponse()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := request
		resp := response
		if err := ExecuteHTTPResponse(storedScript, &req, &resp, ctx, nil); err != nil {
			b.Fatalf("execute HTTP response hook: %v", err)
		}
	}
}

func benchmarkPacketScript(b *testing.B, source string) StoredScript {
	b.Helper()

	store := NewStoreAtDir(b.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "bench-packet",
		Surface: SurfacePacket,
		Source:  source,
	})
	if err != nil {
		b.Fatalf("save packet script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{
		Name:    saved.Name,
		Surface: SurfacePacket,
	})
	if err != nil {
		b.Fatalf("lookup packet script: %v", err)
	}
	return storedScript
}

func benchmarkHTTPServiceScript(b *testing.B, source string) StoredScript {
	b.Helper()

	store := NewStoreAtDir(b.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "bench-http",
		Surface: SurfaceHTTPService,
		Source:  source,
	})
	if err != nil {
		b.Fatalf("save HTTP service script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{
		Name:    saved.Name,
		Surface: SurfaceHTTPService,
	})
	if err != nil {
		b.Fatalf("lookup HTTP service script: %v", err)
	}
	return storedScript
}

func benchmarkHTTPRequest() HTTPRequest {
	return HTTPRequest{
		Method:  "GET",
		Target:  "/index.html?q=1",
		Version: "HTTP/1.1",
		Host:    "example.test",
		Headers: []HTTPHeader{
			{Name: "Host", Value: "example.test"},
			{Name: "User-Agent", Value: "kraken-bench"},
		},
		Body: []byte("payload"),
	}
}

func benchmarkHTTPResponse() HTTPResponse {
	return HTTPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Version:    "HTTP/1.1",
		Headers: []HTTPHeader{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Content-Length", Value: "7"},
		},
		Body: []byte("payload"),
	}
}

func benchmarkHTTPExecutionContext() HTTPExecutionContext {
	return HTTPExecutionContext{
		ScriptName: "bench-http",
		Adopted: ExecutionIdentity{
			Label:         "bench",
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
		Service: HTTPServiceInfo{
			Name:          "http",
			Port:          8080,
			RootDirectory: "/tmp",
			UseTLS:        true,
		},
		Connection: HTTPConnection{
			RemoteAddress: "192.168.56.20:50505",
		},
		TLS: HTTPTLSInfo{
			Enabled:            true,
			Version:            "TLS1.3",
			CipherSuite:        "TLS_AES_128_GCM_SHA256",
			ServerName:         "example.test",
			NegotiatedProtocol: "http/1.1",
		},
	}
}

func benchmarkMutablePacket(b *testing.B, outbound *packetpkg.OutboundPacket) *MutablePacket {
	b.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := outbound.SerializeValidatedInto(buffer); err != nil {
		b.Fatalf("serialize outbound packet: %v", err)
	}

	packet, err := NewMutablePacket(append([]byte(nil), buffer.Bytes()...))
	if err != nil {
		b.Fatalf("new mutable packet: %v", err)
	}
	return packet
}
