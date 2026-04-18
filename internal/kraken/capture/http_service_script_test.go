package capture

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

func TestHTTPServiceHandlerShortCircuitsRequest(t *testing.T) {
	binding := mustHTTPServiceScriptBinding(t, `bytes = require("kraken/bytes")

def on_request(request, ctx):
    body = bytes.fromASCII("blocked")
    return struct(
        statusCode = 451,
        reason = "Unavailable For Legal Reasons",
        version = "HTTP/1.1",
        headers = [
            struct(name = "Content-Type", value = "text/plain"),
            struct(name = "Content-Length", value = str(len(body))),
        ],
        body = body,
    )
`)

	managed := newManagedTCPService(tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, nil, nil)

	baseCalled := false
	handler := newHTTPServiceHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		baseCalled = true
	}), fakeIdentity{
		label: "web",
		ip:    net.IPv4(192, 168, 56, 10),
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, binding, managed, nil)

	request := httptest.NewRequest(http.MethodGet, "http://example.test/secret", nil)
	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, request)

	response := writer.Result()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if baseCalled {
		t.Fatal("expected request script to short-circuit the base handler")
	}
	if response.StatusCode != 451 {
		t.Fatalf("expected status 451, got %d", response.StatusCode)
	}
	if got := string(body); got != "blocked" {
		t.Fatalf("expected body %q, got %q", "blocked", got)
	}
	if got := managed.snapshot().LastError; got != "" {
		t.Fatalf("expected script error to stay clear, got %q", got)
	}
}

func TestHTTPServiceHandlerResponseHookRewritesResponse(t *testing.T) {
	binding := mustHTTPServiceScriptBinding(t, `bytes = require("kraken/bytes")

def on_response(request, response, ctx):
    body = bytes.fromASCII("rewritten")
    response.statusCode = 202
    response.headers = [
        struct(name = "Content-Type", value = "text/plain"),
        struct(name = "Content-Length", value = str(len(body))),
    ]
    response.body = body
`)

	managed := newManagedTCPService(tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, nil, nil)

	handler := newHTTPServiceHandler(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("base"))
	}), fakeIdentity{
		label: "web",
		ip:    net.IPv4(192, 168, 56, 10),
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, binding, managed, nil)

	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))

	response := writer.Result()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if response.StatusCode != 202 {
		t.Fatalf("expected status 202, got %d", response.StatusCode)
	}
	if got := string(body); got != "rewritten" {
		t.Fatalf("expected body %q, got %q", "rewritten", got)
	}
	if got := response.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("expected rewritten content type, got %q", got)
	}
	if got := managed.snapshot().LastError; got != "" {
		t.Fatalf("expected script error to stay clear, got %q", got)
	}
}

func TestHTTPServiceHandlerResponseOnlyPreservesRequestBody(t *testing.T) {
	binding := mustHTTPServiceScriptBinding(t, `def on_response(request, response, ctx):
    response.headers = [
        struct(name = "Content-Type", value = "text/plain"),
        struct(name = "Content-Length", value = str(len(request.body))),
    ]
    response.body = request.body
`)

	managed := newManagedTCPService(tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, nil, nil)

	var seenBody string
	handler := newHTTPServiceHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read base request body: %v", err)
		}
		seenBody = string(payload)
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte("base"))
	}), fakeIdentity{
		label: "web",
		ip:    net.IPv4(192, 168, 56, 10),
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, binding, managed, nil)

	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("payload=1")))

	response := writer.Result()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if seenBody != "payload=1" {
		t.Fatalf("expected base handler body %q, got %q", "payload=1", seenBody)
	}
	if got := string(body); got != "payload=1" {
		t.Fatalf("expected response body %q, got %q", "payload=1", got)
	}
	if got := managed.snapshot().LastError; got != "" {
		t.Fatalf("expected script error to stay clear, got %q", got)
	}
}

func TestHTTPServiceHandlerRecordsScriptFailures(t *testing.T) {
	binding := mustHTTPServiceScriptBinding(t, `def on_request(request, ctx):
    request.target = "not a uri"
`)

	managed := newManagedTCPService(tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, nil, nil)

	handler := newHTTPServiceHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("base handler should not be reached when request rewriting fails")
	}), fakeIdentity{
		label: "web",
		ip:    net.IPv4(192, 168, 56, 10),
		mac:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x10},
	}, tcpServiceSpec{
		service: adoption.TCPServiceHTTP,
		port:    8080,
	}, binding, managed, nil)

	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))

	response := writer.Result()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", response.StatusCode)
	}
	if got := string(body); got != "HTTP service script failed" {
		t.Fatalf("expected failure body, got %q", got)
	}
	lastErr := managed.snapshot().LastError
	if !strings.Contains(lastErr, "HTTP service script") || !strings.Contains(lastErr, "http.request.target") {
		t.Fatalf("expected stored script error, got %q", lastErr)
	}
}

func mustHTTPServiceScriptBinding(t *testing.T, source string) *httpServiceScriptBinding {
	t.Helper()

	store := scriptpkg.NewStoreAtDir(t.TempDir())
	saved, err := store.Save(scriptpkg.SaveStoredScriptRequest{
		Name:    "http-service-test",
		Surface: scriptpkg.SurfaceHTTPService,
		Source:  source,
	})
	if err != nil {
		t.Fatalf("save HTTP service script: %v", err)
	}

	storedScript, err := store.Lookup(scriptpkg.StoredScriptRef{
		Name:    saved.Name,
		Surface: scriptpkg.SurfaceHTTPService,
	})
	if err != nil {
		t.Fatalf("lookup HTTP service script: %v", err)
	}

	hasRequest, hasResponse, err := scriptpkg.HTTPServiceHooks(storedScript)
	if err != nil {
		t.Fatalf("inspect HTTP service hooks: %v", err)
	}

	return &httpServiceScriptBinding{
		script:      storedScript,
		hasRequest:  hasRequest,
		hasResponse: hasResponse,
	}
}
