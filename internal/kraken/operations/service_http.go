package operations

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type httpService struct {
	server   *http.Server
	listener net.Listener
	done     chan struct{}
	waitErr  error
}

func StartHTTP(listener net.Listener, config map[string]string) (*httpService, error) {
	rootDirectory, err := validateHTTPRootDirectory(config["rootDirectory"])
	if err != nil {
		return nil, err
	}

	protocol, err := httpServiceProtocol(config)
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           http.FileServer(http.Dir(rootDirectory)),
	}
	if protocol == "https" {
		certificate, err := newSelfSignedCertificate(listenerIP(listener))
		if err != nil {
			return nil, err
		}
		listener = tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
	}

	running := &httpService{
		server:   server,
		listener: listener,
		done:     make(chan struct{}),
	}

	go running.run()
	return running, nil
}

func (service *httpService) run() {
	defer close(service.done)

	if err := service.server.Serve(service.listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		service.waitErr = err
	}
}

func (service *httpService) Close() error {
	return errors.Join(service.server.Close(), service.listener.Close())
}

func (service *httpService) Wait() error {
	<-service.done
	return service.waitErr
}

func httpServiceProtocol(config map[string]string) (string, error) {
	switch config["protocol"] {
	case "", "http":
		return "http", nil
	case "https":
		return "https", nil
	default:
		return "", fmt.Errorf("Protocol has an invalid value")
	}
}

func listenerIP(listener net.Listener) net.IP {
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func validateHTTPRootDirectory(rootDirectory string) (string, error) {
	if rootDirectory == "" {
		return "", fmt.Errorf("Root is required")
	}

	rootDirectory = filepath.Clean(rootDirectory)
	info, err := os.Stat(rootDirectory)
	if err != nil {
		return "", fmt.Errorf("Root: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("Root must be a directory")
	}

	return rootDirectory, nil
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
	normalizedIP := ip.To4()
	certificateTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "kraken-self-signed",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"kraken-self-signed"},
	}
	if normalizedIP != nil {
		certificateTemplate.IPAddresses = []net.IP{normalizedIP}
		certificateTemplate.Subject.CommonName = normalizedIP.String()
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create HTTPS certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}, nil
}
