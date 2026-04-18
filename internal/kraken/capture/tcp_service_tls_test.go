package capture

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewSelfSignedCertificateIncludesAdoptedIP(t *testing.T) {
	certificate, err := newSelfSignedCertificate(net.IPv4(192, 168, 56, 10))
	if err != nil {
		t.Fatalf("new self-signed certificate: %v", err)
	}
	if len(certificate.Certificate) != 1 {
		t.Fatalf("expected a single certificate, got %d", len(certificate.Certificate))
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse self-signed certificate: %v", err)
	}
	if got := leaf.Subject.CommonName; got != "192.168.56.10" {
		t.Fatalf("expected common name 192.168.56.10, got %q", got)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.IPv4(192, 168, 56, 10)) {
		t.Fatalf("expected certificate SAN to include adopted IP, got %v", leaf.IPAddresses)
	}
}

func TestManagedServiceSnapshotReportsHTTPConfig(t *testing.T) {
	service := newManagedService(serviceSpec{
		service: listenerServiceHTTPID,
		config: map[string]string{
			"port":           "8443",
			"protocol":       "https",
			"rootDirectory":  "/tmp/root",
			"tlsScriptName":  "tls-observe",
			"httpScriptName": "",
		},
	}, 8443)

	snapshot := service.snapshot()
	if snapshot.Config["protocol"] != "https" {
		t.Fatalf("expected HTTPS config in snapshot, got %+v", snapshot)
	}
	if snapshot.Port != 8443 || snapshot.Config["rootDirectory"] != "/tmp/root" {
		t.Fatalf("unexpected snapshot values %+v", snapshot)
	}
	if snapshot.Config["tlsScriptName"] != "tls-observe" {
		t.Fatalf("expected TLS script in snapshot, got %+v", snapshot)
	}
}

func TestStartHTTPListenerServiceRejectsHTTPScriptForHTTPS(t *testing.T) {
	_, err := startHTTPListenerService(ServiceContext{}, nil, map[string]string{
		"port":           "8443",
		"protocol":       "https",
		"rootDirectory":  t.TempDir(),
		"httpScriptName": "http-only",
	})
	if err == nil || err.Error() != "HTTP Script is only supported for plaintext HTTP; use TLS Script for HTTPS" {
		t.Fatalf("expected plaintext HTTP script rejection, got %v", err)
	}
}

func TestStartHTTPListenerServiceRejectsTLSScriptForHTTP(t *testing.T) {
	_, err := startHTTPListenerService(ServiceContext{}, nil, map[string]string{
		"port":          "8080",
		"protocol":      "http",
		"rootDirectory": t.TempDir(),
		"tlsScriptName": "tls-only",
	})
	if err == nil || err.Error() != "TLS Script is only supported for HTTPS" {
		t.Fatalf("expected TLS script rejection on HTTP, got %v", err)
	}
}

func TestLoadOrCreateSSHHostSignersCreatesDefaultKey(t *testing.T) {
	hostKeyDir := t.TempDir()

	signers, err := loadOrCreateSSHHostSigners(hostKeyDir)
	if err != nil {
		t.Fatalf("load or create SSH host signers: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected one default SSH host signer, got %d", len(signers))
	}

	keyPath := filepath.Join(hostKeyDir, "host_ed25519.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat SSH host key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("expected SSH host key mode 0600, got %o", mode)
	}
}

func TestLoadOrCreateSSHHostSignersLoadsExistingKeys(t *testing.T) {
	hostKeyDir := t.TempDir()

	first, err := createSSHHostSigner(filepath.Join(hostKeyDir, "first.pem"))
	if err != nil {
		t.Fatalf("create first SSH host signer: %v", err)
	}
	second, err := createSSHHostSigner(filepath.Join(hostKeyDir, "second.pem"))
	if err != nil {
		t.Fatalf("create second SSH host signer: %v", err)
	}

	signers, err := loadOrCreateSSHHostSigners(hostKeyDir)
	if err != nil {
		t.Fatalf("load SSH host signers: %v", err)
	}
	if len(signers) != 2 {
		t.Fatalf("expected two SSH host signers, got %d", len(signers))
	}
	if string(signers[0].PublicKey().Marshal()) != string(first.PublicKey().Marshal()) {
		t.Fatalf("expected first signer to come from first.pem")
	}
	if string(signers[1].PublicKey().Marshal()) != string(second.PublicKey().Marshal()) {
		t.Fatalf("expected second signer to come from second.pem")
	}
}

func TestResolveSSHCommand(t *testing.T) {
	command, err := resolveSSHCommand([]string{"/bin/bash", "-lc", "id"}, true)
	if err != nil {
		t.Fatalf("resolve explicit SSH command: %v", err)
	}
	if len(command) != 3 || command[0] != "/bin/bash" {
		t.Fatalf("unexpected explicit SSH command %v", command)
	}

	command, err = resolveSSHCommand(nil, true)
	if err != nil {
		t.Fatalf("resolve default SSH shell: %v", err)
	}
	if len(command) == 0 || command[0] == "" {
		t.Fatalf("expected default SSH shell, got %v", command)
	}
	if runtime.GOOS != "windows" && command[0][0] != '/' {
		t.Fatalf("expected absolute unix shell path, got %v", command)
	}

	if _, err := resolveSSHCommand(nil, false); err == nil {
		t.Fatal("expected no-command SSH session without PTY to fail")
	}
}

func TestSSHCommandExitCode(t *testing.T) {
	if code := sshCommandExitCode(nil); code != 0 {
		t.Fatalf("expected zero exit code, got %d", code)
	}

	exitErr := &exec.ExitError{}
	if code := sshCommandExitCode(exitErr); code != exitErr.ExitCode() {
		t.Fatalf("expected exit status %d, got %d", exitErr.ExitCode(), code)
	}

	if code := sshCommandExitCode(errors.New("boom")); code != 1 {
		t.Fatalf("expected generic SSH execution failure to map to 1, got %d", code)
	}
}
