package operations

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

func newHTTPService(config map[string]string) (Service, error) {
	port, err := servicePort(config)
	if err != nil {
		return nil, err
	}
	rootDirectory := config["rootDirectory"]
	if rootDirectory == "" {
		return nil, fmt.Errorf("Root is required")
	}
	rootDirectory = filepath.Clean(rootDirectory)
	info, err := os.Stat(rootDirectory)
	if err != nil {
		return nil, fmt.Errorf("Root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("Root must be a directory")
	}

	switch config["protocol"] {
	case "":
		config["protocol"] = "http"
	case "http", "https":
	default:
		return nil, fmt.Errorf("Protocol has an invalid value")
	}

	metadata := ServiceMetadata{
		Service: "http",
		Port:    port,
		Config:  config,
		Summary: []ServiceSummaryItem{
			{Label: "Proto", Value: strings.ToUpper(config["protocol"])},
			{Label: "Root", Value: config["rootDirectory"], Code: true},
		},
	}

	fileServer := fasthttp.FSHandler(rootDirectory, 0)
	var tlsMu sync.Mutex
	var tlsConfig *tls.Config
	handler := func(conn net.Conn) error {
		if config["protocol"] == "https" {
			tlsMu.Lock()
			if tlsConfig == nil {
				certificate, err := newSelfSignedCertificate(conn.LocalAddr().(*net.TCPAddr).IP)
				if err != nil {
					tlsMu.Unlock()
					return err
				}
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{certificate},
					MinVersion:   tls.VersionTLS12,
				}
			}
			conn = tls.Server(conn, tlsConfig)
			tlsMu.Unlock()
		}
		return fasthttp.ServeConn(conn, fileServer)
	}
	return newTCPService(metadata, handler), nil
}

func newSelfSignedCertificate(ip net.IP) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate HTTPS private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate HTTPS serial number: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create HTTPS certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}, nil
}
