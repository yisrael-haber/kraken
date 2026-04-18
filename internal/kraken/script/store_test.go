package script

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
)

func packetScriptRef(name string) StoredScriptRef {
	return StoredScriptRef{
		Name:    name,
		Surface: SurfacePacket,
	}
}

func httpServiceScriptRef(name string) StoredScriptRef {
	return StoredScriptRef{
		Name:    name,
		Surface: SurfaceHTTPService,
	}
}

func tlsServiceScriptRef(name string) StoredScriptRef {
	return StoredScriptRef{
		Name:    name,
		Surface: SurfaceTLSService,
	}
}

func sshServiceScriptRef(name string) StoredScriptRef {
	return StoredScriptRef{
		Name:    name,
		Surface: SurfaceSSHService,
	}
}

func writeStoredScriptFixture(t *testing.T, baseDir, relativeDir string, ref StoredScriptRef, source string) string {
	t.Helper()

	normalized, err := normalizeStoredScriptRef(ref)
	if err != nil {
		t.Fatalf("normalize stored script ref: %v", err)
	}

	scriptDir := filepath.Join(baseDir, relativeDir)
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		t.Fatalf("mkdir stored script fixture dir: %v", err)
	}

	path, err := storeutil.PathForStoredItemWithExtension(scriptDir, normalized.Name, ".star")
	if err != nil {
		t.Fatalf("path for stored script fixture: %v", err)
	}
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("write stored script fixture: %v", err)
	}

	return path
}

func TestStoredScriptStoreSaveAndLookup(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "TTL Clamp",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 32
`,
	})
	if err != nil {
		t.Fatalf("save stored script: %v", err)
	}
	if !saved.Available {
		t.Fatalf("expected saved script to be available, compileError=%q", saved.CompileError)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored scripts: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 stored script, got %d", len(items))
	}
	if items[0].Name != saved.Name {
		t.Fatalf("expected stored script %q, got %q", saved.Name, items[0].Name)
	}

	loaded, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup stored script: %v", err)
	}
	if loaded.Name != saved.Name {
		t.Fatalf("expected loaded script %q, got %q", saved.Name, loaded.Name)
	}
	if loaded.compiled == nil || loaded.compiled.program == nil {
		t.Fatal("expected compiled program to be cached on lookup")
	}
}

func TestStoredScriptStoreUsesOrganizedSurfaceDirectories(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	packetSaved, err := store.Save(SaveStoredScriptRequest{
		Name:    "Alpha",
		Surface: SurfacePacket,
		Source:  "def main(packet, ctx):\n    pass\n",
	})
	if err != nil {
		t.Fatalf("save packet script: %v", err)
	}
	httpSaved, err := store.Save(SaveStoredScriptRequest{
		Name:    "Bravo",
		Surface: SurfaceHTTPService,
		Source:  "def on_request(request, ctx):\n    return None\n",
	})
	if err != nil {
		t.Fatalf("save HTTP service script: %v", err)
	}
	tlsSaved, err := store.Save(SaveStoredScriptRequest{
		Name:    "Charlie",
		Surface: SurfaceTLSService,
		Source:  "def main(stream, ctx):\n    pass\n",
	})
	if err != nil {
		t.Fatalf("save TLS service script: %v", err)
	}
	sshSaved, err := store.Save(SaveStoredScriptRequest{
		Name:    "Delta",
		Surface: SurfaceSSHService,
		Source:  "def main(stream, ctx):\n    pass\n",
	})
	if err != nil {
		t.Fatalf("save SSH service script: %v", err)
	}

	packetPath, err := pathForStoredScript(store.dir, packetScriptRef(packetSaved.Name))
	if err != nil {
		t.Fatalf("path for packet script: %v", err)
	}
	if got, want := filepath.Dir(packetPath), filepath.Join(store.dir, "Transport"); got != want {
		t.Fatalf("expected packet path dir %q, got %q", want, got)
	}

	httpPath, err := pathForStoredScript(store.dir, httpServiceScriptRef(httpSaved.Name))
	if err != nil {
		t.Fatalf("path for HTTP service script: %v", err)
	}
	if got, want := filepath.Dir(httpPath), filepath.Join(store.dir, "Application", "HTTP"); got != want {
		t.Fatalf("expected HTTP script path dir %q, got %q", want, got)
	}

	tlsPath, err := pathForStoredScript(store.dir, tlsServiceScriptRef(tlsSaved.Name))
	if err != nil {
		t.Fatalf("path for TLS service script: %v", err)
	}
	if got, want := filepath.Dir(tlsPath), filepath.Join(store.dir, "Application", "TLS"); got != want {
		t.Fatalf("expected TLS script path dir %q, got %q", want, got)
	}

	sshPath, err := pathForStoredScript(store.dir, sshServiceScriptRef(sshSaved.Name))
	if err != nil {
		t.Fatalf("path for SSH service script: %v", err)
	}
	if got, want := filepath.Dir(sshPath), filepath.Join(store.dir, "Application", "SSH"); got != want {
		t.Fatalf("expected SSH script path dir %q, got %q", want, got)
	}
}

func TestStoredScriptStoreMarksInvalidScriptsUnavailable(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Broken Script",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl =
`,
	})
	if err != nil {
		t.Fatalf("save broken script: %v", err)
	}
	if saved.Available {
		t.Fatal("expected broken script to be unavailable")
	}
	if saved.CompileError == "" {
		t.Fatal("expected broken script compile error")
	}

	_, err = store.Lookup(packetScriptRef(saved.Name))
	if !errors.Is(err, ErrStoredScriptInvalid) {
		t.Fatalf("expected invalid script lookup error, got %v", err)
	}
}

func TestStoredScriptStoreTimesOutTopLevelInfiniteLoop(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Busy Loop",
		Source: `while True:
    pass

def main(packet, ctx):
    pass
`,
	})
	if err != nil {
		t.Fatalf("save busy-loop script: %v", err)
	}
	if saved.Available {
		t.Fatal("expected busy-loop script to be unavailable")
	}
	if !strings.Contains(saved.CompileError, "validation timed out") {
		t.Fatalf("expected timeout compile error, got %q", saved.CompileError)
	}
}

func TestStoredScriptStoreRefreshReloadsExternalChanges(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	if _, err := store.Save(SaveStoredScriptRequest{
		Name: "Alpha",
		Source: `def main(packet, ctx):
    pass
`,
	}); err != nil {
		t.Fatalf("save alpha script: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list scripts: %v", err)
	}
	if len(items) != 1 || items[0].Name != "Alpha" {
		t.Fatalf("expected [Alpha], got %+v", items)
	}

	path, err := pathForStoredScript(store.dir, packetScriptRef("Beta"))
	if err != nil {
		t.Fatalf("path for beta: %v", err)
	}
	if err := os.WriteFile(path, []byte("def main(packet, ctx):\n    pass\n"), 0o644); err != nil {
		t.Fatalf("write beta script: %v", err)
	}

	items, err = store.List()
	if err != nil {
		t.Fatalf("list scripts after external write: %v", err)
	}
	if len(items) != 1 || items[0].Name != "Alpha" {
		t.Fatalf("expected cached [Alpha], got %+v", items)
	}

	items, err = store.Refresh()
	if err != nil {
		t.Fatalf("refresh scripts: %v", err)
	}
	if len(items) != 2 || items[0].Name != "Alpha" || items[1].Name != "Beta" {
		t.Fatalf("expected [Alpha Beta], got %+v", items)
	}
}

func TestStoredScriptStoreIgnoresLegacyDirectories(t *testing.T) {
	dir := t.TempDir()
	writeStoredScriptFixture(t, dir, "", packetScriptRef("Alpha"), "def main(packet, ctx):\n    pass\n")
	writeStoredScriptFixture(t, dir, "packet", packetScriptRef("Beta"), "def main(packet, ctx):\n    pass\n")
	writeStoredScriptFixture(t, dir, "http-service", httpServiceScriptRef("HTTP Hooks"), "def on_request(request, ctx):\n    return None\n")

	store := NewStoreAtDir(dir)

	items, err := store.List()
	if err != nil {
		t.Fatalf("list scripts: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected legacy dirs to be ignored, got %d scripts", len(items))
	}

	if _, err := store.Lookup(packetScriptRef("Alpha")); !errors.Is(err, ErrStoredScriptNotFound) {
		t.Fatalf("expected legacy root packet script to stay hidden, got %v", err)
	}
	if _, err := store.Lookup(packetScriptRef("Beta")); !errors.Is(err, ErrStoredScriptNotFound) {
		t.Fatalf("expected legacy packet dir script to stay hidden, got %v", err)
	}
	if _, err := store.Lookup(httpServiceScriptRef("HTTP Hooks")); !errors.Is(err, ErrStoredScriptNotFound) {
		t.Fatalf("expected legacy HTTP service script to stay hidden, got %v", err)
	}
}

func TestStoredScriptStoreLoadsOnlyOrganizedPathWhenLegacyCopiesExist(t *testing.T) {
	dir := t.TempDir()
	writeStoredScriptFixture(t, dir, "Transport", packetScriptRef("Alpha"), "def main(packet, ctx):\n    packet.ipv4.ttl = 32\n")
	writeStoredScriptFixture(t, dir, "", packetScriptRef("Alpha"), "def main(packet, ctx):\n    packet.ipv4.ttl = 9\n")
	writeStoredScriptFixture(t, dir, "packet", packetScriptRef("Alpha"), "def main(packet, ctx):\n    packet.ipv4.ttl = 5\n")

	store := NewStoreAtDir(dir)

	loaded, err := store.Get(packetScriptRef("Alpha"))
	if err != nil {
		t.Fatalf("get canonical packet script: %v", err)
	}
	if !strings.Contains(loaded.Source, "ttl = 32") {
		t.Fatalf("expected canonical source to win, got %q", loaded.Source)
	}
}

func TestStoredScriptStoreSaveLeavesLegacyCopiesUntouched(t *testing.T) {
	dir := t.TempDir()
	packetLegacyRoot := writeStoredScriptFixture(t, dir, "", packetScriptRef("Alpha"), "def main(packet, ctx):\n    pass\n")
	packetLegacyDir := writeStoredScriptFixture(t, dir, "packet", packetScriptRef("Alpha"), "def main(packet, ctx):\n    pass\n")
	httpLegacy := writeStoredScriptFixture(t, dir, "http-service", httpServiceScriptRef("Bravo"), "def on_request(request, ctx):\n    return None\n")

	store := NewStoreAtDir(dir)

	if _, err := store.Save(SaveStoredScriptRequest{
		Name:    "Alpha",
		Surface: SurfacePacket,
		Source:  "def main(packet, ctx):\n    packet.ipv4.ttl = 32\n",
	}); err != nil {
		t.Fatalf("save packet script: %v", err)
	}
	if _, err := store.Save(SaveStoredScriptRequest{
		Name:    "Bravo",
		Surface: SurfaceHTTPService,
		Source:  "def on_request(request, ctx):\n    return None\n",
	}); err != nil {
		t.Fatalf("save HTTP service script: %v", err)
	}

	if _, err := os.Stat(packetLegacyRoot); err != nil {
		t.Fatalf("expected packet legacy root copy to stay, got %v", err)
	}
	if _, err := os.Stat(packetLegacyDir); err != nil {
		t.Fatalf("expected packet legacy dir copy to stay, got %v", err)
	}
	if _, err := os.Stat(httpLegacy); err != nil {
		t.Fatalf("expected HTTP legacy copy to stay, got %v", err)
	}
}

func TestStoredScriptStoreDeleteLeavesLegacyCopiesUntouched(t *testing.T) {
	dir := t.TempDir()
	packetLegacyDir := writeStoredScriptFixture(t, dir, "packet", packetScriptRef("Alpha"), "def main(packet, ctx):\n    pass\n")

	store := NewStoreAtDir(dir)
	if _, err := store.Save(SaveStoredScriptRequest{
		Name:    "Alpha",
		Surface: SurfacePacket,
		Source:  "def main(packet, ctx):\n    packet.ipv4.ttl = 32\n",
	}); err != nil {
		t.Fatalf("save packet script: %v", err)
	}

	if err := store.Delete(packetScriptRef("Alpha")); err != nil {
		t.Fatalf("delete packet script: %v", err)
	}

	if _, err := os.Stat(packetLegacyDir); err != nil {
		t.Fatalf("expected legacy packet copy to stay after delete, got %v", err)
	}
	if _, err := store.Lookup(packetScriptRef("Alpha")); !errors.Is(err, ErrStoredScriptNotFound) {
		t.Fatalf("expected canonical script to be deleted, got %v", err)
	}
}

func TestStoredScriptStoreListReflectsSaveAfterCaching(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	if _, err := store.Save(SaveStoredScriptRequest{
		Name: "Alpha",
		Source: `def main(packet, ctx):
    pass
`,
	}); err != nil {
		t.Fatalf("save alpha script: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list scripts: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 cached script, got %d", len(items))
	}

	if _, err := store.Save(SaveStoredScriptRequest{
		Name: "Beta",
		Source: `def main(packet, ctx):
    pass
`,
	}); err != nil {
		t.Fatalf("save beta script: %v", err)
	}

	items, err = store.List()
	if err != nil {
		t.Fatalf("list scripts after second save: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 scripts after cache invalidation, got %d", len(items))
	}
}

func TestStoredScriptStoreIgnoresLegacyJavaScriptFiles(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	if err := os.WriteFile(filepath.Join(store.dir, "legacy.js"), []byte("def main(packet, ctx):\n    pass\n"), 0o644); err != nil {
		t.Fatalf("write legacy script: %v", err)
	}
	path, err := pathForStoredScript(store.dir, packetScriptRef("Alpha"))
	if err != nil {
		t.Fatalf("path for alpha: %v", err)
	}
	if err := os.WriteFile(path, []byte("def main(packet, ctx):\n    pass\n"), 0o644); err != nil {
		t.Fatalf("write alpha script: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list scripts: %v", err)
	}
	if len(items) != 1 || items[0].Name != "Alpha" {
		t.Fatalf("expected only Alpha to load, got %+v", items)
	}

	if _, err := store.Get(packetScriptRef("legacy")); !errors.Is(err, ErrStoredScriptNotFound) {
		t.Fatalf("expected legacy .js file to be ignored, got %v", err)
	}
}

func TestStoredScriptStoreSeparatesPacketAndHTTPServiceSurfaces(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	packetSaved, err := store.Save(SaveStoredScriptRequest{
		Name:    "Alpha",
		Surface: SurfacePacket,
		Source: `def main(packet, ctx):
    pass
`,
	})
	if err != nil {
		t.Fatalf("save packet script: %v", err)
	}

	httpSaved, err := store.Save(SaveStoredScriptRequest{
		Name:    "Alpha",
		Surface: SurfaceHTTPService,
		Source: `def on_request(request, ctx):
    return None
`,
	})
	if err != nil {
		t.Fatalf("save HTTP service script: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list scripts: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 scripts, got %d", len(items))
	}

	packetLoaded, err := store.Lookup(packetScriptRef(packetSaved.Name))
	if err != nil {
		t.Fatalf("lookup packet script: %v", err)
	}
	if packetLoaded.Surface != SurfacePacket {
		t.Fatalf("expected packet surface, got %q", packetLoaded.Surface)
	}

	httpLoaded, err := store.Lookup(StoredScriptRef{
		Name:    httpSaved.Name,
		Surface: SurfaceHTTPService,
	})
	if err != nil {
		t.Fatalf("lookup HTTP service script: %v", err)
	}
	if httpLoaded.Surface != SurfaceHTTPService {
		t.Fatalf("expected HTTP service surface, got %q", httpLoaded.Surface)
	}
}

func TestExecuteMutatesPacketFieldsAndPayload(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Mutate Echo Reply",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 12
    packet.icmpv4.seq = packet.icmpv4.seq + 3
    packet.payload[0] = 0x41
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		[]byte{0x10, 0x11},
	))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	ipv4Layer := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if ipv4Layer.TTL != 12 {
		t.Fatalf("expected IPv4 TTL 12, got %d", ipv4Layer.TTL)
	}
	if icmpLayer.Seq != 4 {
		t.Fatalf("expected ICMP sequence 4, got %d", icmpLayer.Seq)
	}
	if payload := icmpLayer.Payload; len(payload) != 2 || payload[0] != 0x41 {
		t.Fatalf("expected payload mutation to persist, got %v", payload)
	}
}

func TestExecuteBytesModuleBuildsPayloadFromContext(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Bytes Payload",
		Source: `bytes = require("kraken/bytes")

def main(packet, ctx):
    packet.payload = bytes.concat(
        bytes.fromASCII("PING:"),
        bytes.fromUTF8(ctx.scriptName),
        bytes.fromHex("00 ff"),
    )
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: "Bytes Payload",
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	want := []byte("PING:Bytes Payload\x00\xff")
	if got := icmpPayload(t, packet); len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("expected payload %v, got %v", want, got)
	}
}

func TestExecuteHTTPServiceHooksMutateRequestAndResponse(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "HTTP Hooks",
		Surface: SurfaceHTTPService,
		Source: `bytes = require("kraken/bytes")

def on_request(request, ctx):
    request.target = "/rewritten"

def on_response(request, response, ctx):
    body = bytes.fromASCII("ok")
    response.statusCode = 201
    response.headers = [
        struct(name = "Content-Type", value = "text/plain"),
        struct(name = "Content-Length", value = str(len(body))),
    ]
    response.body = body
`,
	})
	if err != nil {
		t.Fatalf("save HTTP service script: %v", err)
	}

	storedScript, err := store.Lookup(StoredScriptRef{
		Name:    saved.Name,
		Surface: SurfaceHTTPService,
	})
	if err != nil {
		t.Fatalf("lookup HTTP service script: %v", err)
	}

	request := HTTPRequest{
		Method:  "GET",
		Target:  "/",
		Version: "HTTP/1.1",
		Headers: []HTTPHeader{{Name: "Host", Value: "example.test"}},
	}
	ctx := HTTPExecutionContext{
		ScriptName: storedScript.Name,
		Service: HTTPServiceInfo{
			Name:   "http",
			Port:   8080,
			UseTLS: true,
		},
		TLS: HTTPTLSInfo{
			Enabled:     true,
			Version:     "TLS1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
		},
	}

	shortCircuit, err := ExecuteHTTPRequest(storedScript, &request, ctx, nil)
	if err != nil {
		t.Fatalf("execute request hook: %v", err)
	}
	if shortCircuit != nil {
		t.Fatal("expected request hook to continue to handler")
	}
	if request.Target != "/rewritten" {
		t.Fatalf("expected rewritten request target, got %q", request.Target)
	}

	response := HTTPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Version:    "HTTP/1.1",
	}
	if err := ExecuteHTTPResponse(storedScript, &request, &response, ctx, nil); err != nil {
		t.Fatalf("execute response hook: %v", err)
	}
	if response.StatusCode != 201 {
		t.Fatalf("expected HTTP status 201, got %d", response.StatusCode)
	}
	if got := string(response.Body); got != "ok" {
		t.Fatalf("expected response body ok, got %q", got)
	}
	if len(response.Headers) != 2 || response.Headers[1].Value != "2" {
		t.Fatalf("expected response headers to be replaced, got %+v", response.Headers)
	}
}

func TestExecuteGlobalBytesHelperBuildsPayloadFromContext(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Global Bytes Payload",
		Source: `def main(packet, ctx):
    packet.payload = bytes.fromUTF8(ctx.scriptName)
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: "icmp_shift",
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	want := []byte("icmp_shift")
	if got := icmpPayload(t, packet); len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("expected payload %v, got %v", want, got)
	}
}

func TestExecuteSupportsHeaderMutationAndSerializationControls(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Header Mutation",
		Source: `bytes = require("kraken/bytes")

def main(packet, ctx):
    packet.serialization.fixLengths = False
    packet.serialization.computeChecksums = False
    packet.ethernet.ethernetType = 0x88b5
    packet.ipv4.length = 77
    packet.ipv4.id = 0x1010
    packet.ipv4.protocol = 253
    packet.ipv4.checksum = 0x1111
    packet.icmpv4.type = 13
    packet.icmpv4.code = 7
    packet.icmpv4.checksum = 0x2222
    packet.icmpv4.id = 0x3333
    packet.icmpv4.seq = 0x4444
    packet.payload = bytes.fromHex("DE AD BE EF")
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	frame := packet.Bytes()
	if got := uint16(frame[12])<<8 | uint16(frame[13]); got != 0x88b5 {
		t.Fatalf("expected ethernet type 0x88b5, got 0x%04x", got)
	}
	if got := uint16(frame[16])<<8 | uint16(frame[17]); got != 77 {
		t.Fatalf("expected ipv4 length 77, got %d", got)
	}
	if got := uint16(frame[18])<<8 | uint16(frame[19]); got != 0x1010 {
		t.Fatalf("expected ipv4 id 0x1010, got 0x%04x", got)
	}
	if got := frame[23]; got != 253 {
		t.Fatalf("expected protocol 253, got %d", got)
	}
	if got := uint16(frame[24])<<8 | uint16(frame[25]); got != 0x1111 {
		t.Fatalf("expected ipv4 checksum 0x1111, got 0x%04x", got)
	}
	if got := frame[34]; got != 13 || frame[35] != 7 {
		t.Fatalf("expected icmp type/code 13/7, got %d/%d", got, frame[35])
	}
	if got := uint16(frame[36])<<8 | uint16(frame[37]); got != 0x2222 {
		t.Fatalf("expected icmp checksum 0x2222, got 0x%04x", got)
	}
	if got := uint16(frame[38])<<8 | uint16(frame[39]); got != 0x3333 {
		t.Fatalf("expected icmp id 0x3333, got 0x%04x", got)
	}
	if got := uint16(frame[40])<<8 | uint16(frame[41]); got != 0x4444 {
		t.Fatalf("expected icmp seq 0x4444, got 0x%04x", got)
	}
	if got := frame[42:]; len(got) != 4 || got[0] != 0xde || got[3] != 0xef {
		t.Fatalf("expected payload override, got %v", got)
	}
}

func TestExecuteSupportsNumericICMPTypeCodeShorthand(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Numeric TypeCode",
		Source: `def main(packet, ctx):
    packet.icmpv4.typeCode = "13/7"
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildICMPEchoPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		7,
		1,
		nil,
	))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	icmpLayer := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmpLayer.TypeCode.Type() != 13 || icmpLayer.TypeCode.Code() != 7 {
		t.Fatalf("expected numeric typeCode shorthand to apply, got %v", icmpLayer.TypeCode)
	}
}

func TestExecuteSupportsARPFieldMutation(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "ARP Mutation",
		Source: `def main(packet, ctx):
    packet.arp.addrType = 99
    packet.arp.protocol = 0x88b5
    packet.arp.operation = 7
    packet.arp.sourceHwAddress = "aa:bb:cc:dd:ee:ff"
    packet.arp.sourceProtAddress = "10.0.0.7"
    packet.arp.dstHwAddress = "11:22:33:44:55:66"
    packet.arp.dstProtAddress = "10.0.0.8"
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutablePacketFromOutboundPacket(t, packetpkg.BuildARPRequestPacket(
		net.ParseIP("192.168.56.10").To4(),
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		net.ParseIP("192.168.56.1").To4(),
	))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	arpLayer := decoded.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arpLayer.AddrType != layers.LinkType(99) || arpLayer.Protocol != layers.EthernetType(0x88b5) || arpLayer.Operation != 7 {
		t.Fatalf("expected ARP scalar overrides, got %+v", *arpLayer)
	}
	if got := net.HardwareAddr(arpLayer.SourceHwAddress).String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected source hw override, got %s", got)
	}
	if got := net.IP(arpLayer.SourceProtAddress).String(); got != "10.0.0.7" {
		t.Fatalf("expected source protocol override, got %s", got)
	}
	if got := net.HardwareAddr(arpLayer.DstHwAddress).String(); got != "11:22:33:44:55:66" {
		t.Fatalf("expected target hw override, got %s", got)
	}
	if got := net.IP(arpLayer.DstProtAddress).String(); got != "10.0.0.8" {
		t.Fatalf("expected target protocol override, got %s", got)
	}
}

func TestExecuteSupportsTCPFieldMutationAndOptions(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "TCP Mutation",
		Source: `bytes = require("kraken/bytes")

def main(packet, ctx):
    packet.tcp.srcPort = 4321
    packet.tcp.dstPort = 8080
    packet.tcp.seq = 0x01020304
    packet.tcp.ack = 0x11121314
    packet.tcp.flags = 0x3b
    packet.tcp.window = 0x2222
    packet.tcp.urgentPointer = 0x3333
    packet.tcp.options = bytes.fromHex("01 01 01 01")
    packet.tcp.options[3] = 0x00
    packet.tcp.dataOffset = 28
    packet.tcp.options[7] = 0xff
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutableTCPPacket(t, []byte("tcp"))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	tcpLayer, _ := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpLayer == nil {
		t.Fatalf("expected TCP layer, got %v", decoded.Layers())
	}
	if tcpLayer.SrcPort != 4321 || tcpLayer.DstPort != 8080 {
		t.Fatalf("expected TCP ports 4321->8080, got %d->%d", tcpLayer.SrcPort, tcpLayer.DstPort)
	}
	if tcpLayer.Seq != 0x01020304 || tcpLayer.Ack != 0x11121314 {
		t.Fatalf("expected TCP seq/ack override, got 0x%08x/0x%08x", tcpLayer.Seq, tcpLayer.Ack)
	}
	if !tcpLayer.FIN || !tcpLayer.SYN || !tcpLayer.ACK || !tcpLayer.URG {
		t.Fatalf("expected FIN|SYN|ACK|URG flags, got %+v", tcpLayer)
	}
	if tcpLayer.Window != 0x2222 || tcpLayer.Urgent != 0x3333 {
		t.Fatalf("expected TCP window/urgent override, got 0x%04x/0x%04x", tcpLayer.Window, tcpLayer.Urgent)
	}
	if got := int(tcpLayer.DataOffset) * 4; got != 28 {
		t.Fatalf("expected TCP header length 28, got %d", got)
	}
	if got := append([]byte(nil), tcpLayer.Contents[20:28]...); string(got) != string([]byte{0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff}) {
		t.Fatalf("expected TCP options override, got %v", got)
	}
	if got := append([]byte(nil), tcpLayer.Payload...); string(got) != "tcp" {
		t.Fatalf("expected TCP payload to stay intact, got %q", string(got))
	}
}

func TestExecuteSupportsHTTPModuleOnTCPPayload(t *testing.T) {
	store := NewStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "HTTP Mutation",
		Source: `bytes = require("kraken/bytes")
http = require("kraken/http")

def main(packet, ctx):
    message = http.parse(packet.payload)
    packet.tcp.dstPort = 8080
    message.method = "POST"
    message.target = "/upload"
    message.headers = [
        struct(name="Host", value="example.test"),
        struct(name="X-Kraken", value=ctx.scriptName),
        struct(name="Content-Length", value="3"),
    ]
    message.body = bytes.fromASCII("abc")
    packet.payload = http.build(message)
`,
	})
	if err != nil {
		t.Fatalf("save script: %v", err)
	}

	script, err := store.Lookup(packetScriptRef(saved.Name))
	if err != nil {
		t.Fatalf("lookup script: %v", err)
	}

	packet := mustMutableTCPPacket(t, []byte("GET / HTTP/1.1\r\nHost: old.example\r\n\r\n"))

	if _, err := Execute(script, packet, ExecutionContext{
		ScriptName: script.Name,
		Adopted: ExecutionIdentity{
			IP:            "192.168.56.10",
			MAC:           "02:00:00:00:00:10",
			InterfaceName: "eth0",
		},
	}, nil); err != nil {
		t.Fatalf("execute script: %v", err)
	}

	decoded := decodeMutablePacket(packet)
	tcpLayer, _ := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpLayer == nil {
		t.Fatalf("expected TCP layer, got %v", decoded.Layers())
	}
	if tcpLayer.DstPort != 8080 {
		t.Fatalf("expected TCP destination port override, got %d", tcpLayer.DstPort)
	}

	want := "POST /upload HTTP/1.1\r\nHost: example.test\r\nX-Kraken: HTTP Mutation\r\nContent-Length: 3\r\n\r\nabc"
	if got := string(tcpLayer.Payload); got != want {
		t.Fatalf("expected HTTP payload %q, got %q", want, got)
	}
}

func mustMutablePacketFromOutboundPacket(t *testing.T, outbound *packetpkg.OutboundPacket) *MutablePacket {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := outbound.SerializeValidatedInto(buffer); err != nil {
		t.Fatalf("serialize outbound packet: %v", err)
	}

	packet, err := NewMutablePacket(append([]byte(nil), buffer.Bytes()...))
	if err != nil {
		t.Fatalf("new mutable packet: %v", err)
	}
	return packet
}

func mustMutableTCPPacket(t *testing.T, payload []byte) *MutablePacket {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(192, 168, 56, 10),
		DstIP:    net.IPv4(192, 168, 56, 1),
	}
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 80,
		Seq:     0x01010101,
		Ack:     0x02020202,
		ACK:     true,
		PSH:     true,
		Window:  4096,
	}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatalf("set TCP checksum layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ethernet, ipv4, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize TCP packet: %v", err)
	}

	packet, err := NewMutablePacket(append([]byte(nil), buffer.Bytes()...))
	if err != nil {
		t.Fatalf("new mutable packet: %v", err)
	}
	return packet
}

func decodeMutablePacket(packet *MutablePacket) gopacket.Packet {
	return gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.NoCopy)
}

func icmpPayload(t *testing.T, packet *MutablePacket) []byte {
	t.Helper()

	decoded := decodeMutablePacket(packet)
	icmpLayer, _ := decoded.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmpLayer == nil {
		t.Fatalf("expected ICMPv4 layer, got %v", decoded.Layers())
	}
	return append([]byte(nil), icmpLayer.Payload...)
}
