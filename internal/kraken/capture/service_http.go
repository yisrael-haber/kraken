package capture

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

type httpListenerService struct {
	server   *http.Server
	listener net.Listener
	done     chan struct{}

	mu      sync.Mutex
	waitErr error
}

func httpListenerServiceDefinition() ListenerServiceDefinition {
	return ListenerServiceDefinition{
		ID:          listenerServiceHTTPID,
		Label:       "HTTP",
		DefaultPort: 8080,
		tracksHTTP:  true,
		Fields: []adoption.ServiceFieldDefinition{
			{
				Name:         "port",
				Label:        "Port",
				Type:         adoption.ServiceFieldTypePort,
				Required:     true,
				DefaultValue: "8080",
			},
			{
				Name:         "protocol",
				Label:        "Protocol",
				Type:         adoption.ServiceFieldTypeSelect,
				Required:     true,
				DefaultValue: "http",
				Options: []adoption.ServiceFieldOption{
					{Value: "http", Label: "HTTP"},
					{Value: "https", Label: "HTTPS"},
				},
			},
			{
				Name:     "rootDirectory",
				Label:    "Root",
				Type:     adoption.ServiceFieldTypeDirectory,
				Required: true,
			},
		},
		Start: startHTTPListenerService,
		Summary: func(config map[string]string) []adoption.ServiceSummaryItem {
			items := []adoption.ServiceSummaryItem{
				{Label: "Proto", Value: strings.ToUpper(httpServiceProtocol(config))},
			}
			if rootDirectory := strings.TrimSpace(config["rootDirectory"]); rootDirectory != "" {
				items = append(items, adoption.ServiceSummaryItem{Label: "Root", Value: rootDirectory, Code: true})
			}
			return items
		},
	}
}

func startHTTPListenerService(ctx ServiceContext, listener net.Listener, config map[string]string) (RunningService, error) {
	rootDirectory, err := validateHTTPRootDirectory(config["rootDirectory"])
	if err != nil {
		return nil, err
	}

	protocol := httpServiceProtocol(config)
	port, err := strconv.Atoi(config["port"])
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("Port must be between 1 and 65535")
	}

	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveListener := listener
	binding, err := newApplicationScriptBinding(ctx, scriptpkg.ApplicationServiceInfo{
		Name:     listenerServiceHTTPID,
		Port:     port,
		Protocol: protocol,
	}, nil)
	if err != nil {
		return nil, err
	}
	serveListener = wrapListenerWithApplicationScript(serveListener, binding)
	if protocol == "https" {
		if ctx.Identity == nil || common.NormalizeIPv4(ctx.Identity.IP()) == nil {
			return nil, fmt.Errorf("service requires a valid IPv4 identity")
		}
		tlsConfig, err := newSelfSignedTLSBundle(ctx.Identity.IP())
		if err != nil {
			return nil, err
		}
		serveListener = tls.NewListener(serveListener, tlsConfig)
	}

	running := &httpListenerService{
		server:   server,
		listener: serveListener,
		done:     make(chan struct{}),
	}
	server.Handler = http.FileServer(http.Dir(rootDirectory))

	go running.run()
	return running, nil
}

func (service *httpListenerService) run() {
	defer close(service.done)

	if err := service.server.Serve(service.listener); err != nil && !isClosedNetworkError(err) {
		service.setWaitError(fmt.Errorf("serve HTTP: %w", err))
	}
}

func (service *httpListenerService) setWaitError(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	if service.waitErr == nil {
		service.waitErr = err
	}
	service.mu.Unlock()
}

func (service *httpListenerService) Close() error {
	if service == nil {
		return nil
	}

	return errors.Join(service.server.Close(), service.listener.Close())
}

func (service *httpListenerService) Wait() error {
	if service == nil {
		return nil
	}

	<-service.done
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.waitErr
}

func httpServiceProtocol(config map[string]string) string {
	if strings.EqualFold(strings.TrimSpace(config["protocol"]), "https") {
		return "https"
	}

	return "http"
}

func validateHTTPRootDirectory(rootDirectory string) (string, error) {
	rootDirectory = strings.TrimSpace(rootDirectory)
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

func newSelfSignedTLSBundle(ip net.IP) (*tls.Config, error) {
	certificate, err := newSelfSignedCertificate(ip)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}, nil
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
	normalizedIP := common.NormalizeIPv4(ip)
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
		certificateTemplate.IPAddresses = []net.IP{append(net.IP(nil), normalizedIP...)}
		certificateTemplate.Subject.CommonName = normalizedIP.String()
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create HTTPS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse HTTPS certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}
