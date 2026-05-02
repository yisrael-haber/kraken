package script

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestExecuteApplicationBufferMutatesPayload(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "buffer-mutator",
		Surface: SurfaceApplication,
		Source: `load("kraken/bytes", "bytes")
def main(buffer, ctx):
    if buffer.direction == "inbound":
        buffer.payload = bytes.concat(bytes.fromASCII("x"), buffer.payload)
`,
	})
	if err != nil {
		t.Fatalf("save application script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceApplication})
	if err != nil {
		t.Fatalf("lookup application script: %v", err)
	}

	data := ApplicationData{
		Direction: "inbound",
		Payload:   []byte("abc"),
	}
	err = ExecuteApplicationBuffer(storedScript, &data, ApplicationContext{
		ScriptName: saved.Name,
		Service: ApplicationServiceInfo{
			Name:     "echo",
			Port:     7007,
			Protocol: "echo",
		},
		Connection: ApplicationConnection{
			LocalAddress:  "192.168.56.10:7007",
			RemoteAddress: "192.168.56.20:55000",
			Transport:     "tcp",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute application script: %v", err)
	}
	if got := string(data.Payload); got != "xabc" {
		t.Fatalf("expected application payload mutation, got %q", got)
	}
}

func TestExecuteApplicationBufferMutatesDNSOverTCP(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "dns-mutator",
		Surface: SurfaceApplication,
		Source: `def main(buffer, ctx):
    dns = buffer.layer("dns")
    dns.id = 0x4321
    dns.questions[0].name = "longer.example.org"
`,
	})
	if err != nil {
		t.Fatalf("save application script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceApplication})
	if err != nil {
		t.Fatalf("lookup application script: %v", err)
	}

	dns := &layers.DNS{
		ID:      0x1234,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatalf("serialize DNS: %v", err)
	}
	payload := buffer.Bytes()
	tcpPayload := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(tcpPayload[:2], uint16(len(payload)))
	copy(tcpPayload[2:], payload)

	data := ApplicationData{
		Direction: "inbound",
		Payload:   tcpPayload,
	}
	originalPrefix := binary.BigEndian.Uint16(tcpPayload[:2])
	err = ExecuteApplicationBuffer(storedScript, &data, ApplicationContext{
		ScriptName: saved.Name,
		Connection: ApplicationConnection{
			LocalAddress:  "192.168.56.10:53",
			RemoteAddress: "192.168.56.20:55000",
			Transport:     "tcp",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute application script: %v", err)
	}

	if got := binary.BigEndian.Uint16(data.Payload[:2]); got != originalPrefix {
		t.Fatalf("expected DNS over TCP prefix %d to be preserved, got %d", originalPrefix, got)
	}
	decoded := &layers.DNS{}
	if err := decoded.DecodeFromBytes(data.Payload[2:], gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("decode DNS result: %v", err)
	}
	if decoded.ID != 0x4321 {
		t.Fatalf("expected DNS ID 0x4321, got 0x%04x", decoded.ID)
	}
	if got := string(decoded.Questions[0].Name); got != "longer.example.org" {
		t.Fatalf("expected DNS name longer.example.org, got %q", got)
	}
}

func TestExecuteApplicationMutatesDNSOverUDP(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "dns-udp-mutator",
		Surface: SurfaceApplication,
		Source: `def main(buffer, ctx):
    dns = buffer.layer("dns")
    dns.id = 0x4321
    dns.questions[0].name = "example.org"
`,
	})
	if err != nil {
		t.Fatalf("save application script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceApplication})
	if err != nil {
		t.Fatalf("lookup application script: %v", err)
	}

	dns := &layers.DNS{
		ID:      0x1234,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatalf("serialize DNS: %v", err)
	}

	data := ApplicationData{
		Direction: "outbound",
		Payload:   append([]byte(nil), buffer.Bytes()...),
	}
	err = ExecuteApplicationBuffer(storedScript, &data, ApplicationContext{
		ScriptName: saved.Name,
		Connection: ApplicationConnection{
			LocalAddress:  "192.168.56.10:55000",
			RemoteAddress: "192.168.56.20:53",
			Transport:     "udp",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute application script: %v", err)
	}

	decoded := &layers.DNS{}
	if err := decoded.DecodeFromBytes(data.Payload, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("decode DNS result: %v", err)
	}
	if decoded.ID != 0x4321 {
		t.Fatalf("expected DNS ID 0x4321, got 0x%04x", decoded.ID)
	}
	if got := string(decoded.Questions[0].Name); got != "example.org" {
		t.Fatalf("expected DNS name example.org, got %q", got)
	}
}

func TestExecuteApplicationBufferMutatesTLSRecords(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "tls-mutator",
		Surface: SurfaceApplication,
		Source: `load("kraken/bytes", "bytes")
def main(buffer, ctx):
    tls = buffer.layer("tls")
    tls.records[0].payload = bytes.fromHex("1603030001")
`,
	})
	if err != nil {
		t.Fatalf("save application script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceApplication})
	if err != nil {
		t.Fatalf("lookup application script: %v", err)
	}

	data := ApplicationData{
		Direction: "outbound",
		Payload: []byte{
			0x17, 0x03, 0x03, 0x00, 0x03,
			0x01, 0x02, 0x03,
		},
	}
	err = ExecuteApplicationBuffer(storedScript, &data, ApplicationContext{
		ScriptName: saved.Name,
		Connection: ApplicationConnection{
			LocalAddress:  "192.168.56.10:443",
			RemoteAddress: "192.168.56.20:55000",
			Transport:     "tcp",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute application script: %v", err)
	}

	want := []byte{
		0x17, 0x03, 0x03, 0x00, 0x03,
		0x16, 0x03, 0x03, 0x00, 0x01,
	}
	if !bytes.Equal(data.Payload, want) {
		t.Fatalf("expected TLS payload %x, got %x", want, data.Payload)
	}
}

func TestExecuteApplicationBufferMutatesModbusTCP(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "modbus-mutator",
		Surface: SurfaceApplication,
		Source: `load("kraken/bytes", "bytes")
def main(buffer, ctx):
    modbus = buffer.layer("modbusTCP")
    modbus.transactionIdentifier = 0x2222
    modbus.payload = bytes.fromHex("03006b0003")
`,
	})
	if err != nil {
		t.Fatalf("save application script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceApplication})
	if err != nil {
		t.Fatalf("lookup application script: %v", err)
	}

	data := ApplicationData{
		Direction: "inbound",
		Payload: []byte{
			0x00, 0x01,
			0x00, 0x00,
			0x00, 0x06,
			0x11,
			0x03, 0x00, 0x6b, 0x00, 0x03,
		},
	}
	err = ExecuteApplicationBuffer(storedScript, &data, ApplicationContext{
		ScriptName: saved.Name,
		Connection: ApplicationConnection{
			LocalAddress:  "192.168.56.10:502",
			RemoteAddress: "192.168.56.20:55000",
			Transport:     "tcp",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute application script: %v", err)
	}

	if got := binary.BigEndian.Uint16(data.Payload[:2]); got != 0x2222 {
		t.Fatalf("expected transaction identifier 0x2222, got 0x%04x", got)
	}
	if got := binary.BigEndian.Uint16(data.Payload[4:6]); got != 6 {
		t.Fatalf("expected Modbus length 6, got %d", got)
	}
}
