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
	if len(certificate.Certificate) == 0 {
		t.Fatalf("expected a certificate")
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse self-signed certificate: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.IPv4(192, 168, 56, 10)) {
		t.Fatalf("expected certificate SAN to include adopted IP, got %v", leaf.IPAddresses)
	}
}

func TestLoadOrCreateSSHHostSignerPersistsDefaultKey(t *testing.T) {
	hostKeyDir := t.TempDir()
	hostKeyPath := filepath.Join(hostKeyDir, "host_ed25519.pem")

	signer, err := loadOrCreateSSHHostSigner(hostKeyPath)
	if err != nil {
		t.Fatalf("load or create SSH host signer: %v", err)
	}

	info, err := os.Stat(hostKeyPath)
	if err != nil {
		t.Fatalf("stat SSH host key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("expected SSH host key mode 0600, got %o", mode)
	}

	reloaded, err := loadOrCreateSSHHostSigner(hostKeyPath)
	if err != nil {
		t.Fatalf("reload SSH host signer: %v", err)
	}
	if string(reloaded.PublicKey().Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatalf("expected persisted SSH host signer")
	}
}
