package script

import "testing"

func TestExecuteTLSStreamMutatesPayload(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "tls-mutator",
		Surface: SurfaceTLSService,
		Source: `bytes = require("kraken/bytes")
def main(stream, ctx):
    if stream.direction == "inbound":
        stream.payload = bytes.concat(bytes.fromASCII("x"), stream.payload)
`,
	})
	if err != nil {
		t.Fatalf("save TLS stream script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceTLSService})
	if err != nil {
		t.Fatalf("lookup TLS stream script: %v", err)
	}

	data := StreamData{
		Direction: "inbound",
		Payload:   []byte("abc"),
	}
	err = ExecuteTLSStream(storedScript, &data, StreamExecutionContext{
		ScriptName: saved.Name,
		Service: StreamServiceInfo{
			Name:     "http",
			Port:     8443,
			Protocol: "tls",
			UseTLS:   true,
		},
		Connection: StreamConnection{
			LocalAddress:  "192.168.56.10:8443",
			RemoteAddress: "192.168.56.20:55000",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute TLS stream script: %v", err)
	}
	if got := string(data.Payload); got != "xabc" {
		t.Fatalf("expected TLS stream payload mutation, got %q", got)
	}
}

func TestExecuteSSHStreamMutatesPayload(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "ssh-mutator",
		Surface: SurfaceSSHService,
		Source: `bytes = require("kraken/bytes")
def main(stream, ctx):
    if stream.direction == "outbound":
        stream.payload = bytes.concat(stream.payload, bytes.fromASCII("!"))
`,
	})
	if err != nil {
		t.Fatalf("save SSH stream script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceSSHService})
	if err != nil {
		t.Fatalf("lookup SSH stream script: %v", err)
	}

	data := StreamData{
		Direction: "outbound",
		Payload:   []byte("SSH-2.0-Kraken"),
	}
	err = ExecuteSSHStream(storedScript, &data, StreamExecutionContext{
		ScriptName: saved.Name,
		Service: StreamServiceInfo{
			Name:     "ssh",
			Port:     2222,
			Protocol: "ssh",
		},
		Connection: StreamConnection{
			LocalAddress:  "192.168.56.10:2222",
			RemoteAddress: "192.168.56.20:55000",
		},
	}, nil)
	if err != nil {
		t.Fatalf("execute SSH stream script: %v", err)
	}
	if got := string(data.Payload); got != "SSH-2.0-Kraken!" {
		t.Fatalf("expected SSH stream payload mutation, got %q", got)
	}
}
