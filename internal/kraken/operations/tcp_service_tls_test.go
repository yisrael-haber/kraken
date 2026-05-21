package operations

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
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
