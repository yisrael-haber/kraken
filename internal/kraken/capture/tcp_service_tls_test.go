package capture

import (
	"crypto/x509"
	"net"
	"testing"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
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

func TestManagedTCPServiceSnapshotReportsTLS(t *testing.T) {
	service := newManagedTCPService(tcpServiceSpec{
		service:       adoption.TCPServiceHTTP,
		port:          8443,
		rootDirectory: "/tmp/root",
		useTLS:        true,
	}, make(chan struct{}), nil)

	snapshot := service.snapshot()
	if !snapshot.UseTLS {
		t.Fatalf("expected TLS flag in snapshot, got %+v", snapshot)
	}
	if snapshot.Port != 8443 || snapshot.RootDirectory != "/tmp/root" {
		t.Fatalf("unexpected snapshot values %+v", snapshot)
	}
}
