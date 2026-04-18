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
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type tcpServiceSpec struct {
	service       string
	port          int
	rootDirectory string
	useTLS        bool
	scriptName    string
}

type managedTCPService struct {
	mu       sync.RWMutex
	spec     tcpServiceSpec
	started  time.Time
	active   bool
	lastErr  string
	stopFn   func() error
	done     chan struct{}
	stopOnce sync.Once
}

type echoTCPServer struct {
	listener *gonet.TCPListener
	done     chan struct{}

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (listener *pcapAdoptionListener) StartTCPService(source adoption.Identity, service string, port int, rootDirectory string, useTLS bool, scriptName string) (adoption.TCPServiceStatus, error) {
	key := recordingKey(source.IP())
	if key == "" {
		return adoption.TCPServiceStatus{}, fmt.Errorf("TCP service requires a valid IPv4 identity")
	}

	group, err := listener.engineGroupForIdentity(source)
	if err != nil {
		return adoption.TCPServiceStatus{}, err
	}

	spec := tcpServiceSpec{
		service:       strings.ToLower(strings.TrimSpace(service)),
		port:          port,
		rootDirectory: strings.TrimSpace(rootDirectory),
		useTLS:        useTLS,
		scriptName:    adoption.NormalizeScriptName(scriptName),
	}

	previous := listener.takeTCPService(source.IP(), spec.service)
	if previous != nil {
		previous.stop()
	}

	managed, err := startManagedTCPService(group, source, spec, listener.resolveScript)
	if err != nil {
		return adoption.TCPServiceStatus{}, err
	}

	listener.storeTCPService(source.IP(), managed)
	return managed.snapshot(), nil
}

func (listener *pcapAdoptionListener) StopTCPService(ip net.IP, service string) error {
	managed := listener.takeTCPService(ip, service)
	if managed != nil {
		managed.stop()
	}

	return nil
}

func (listener *pcapAdoptionListener) TCPServiceSnapshot(ip net.IP) []adoption.TCPServiceStatus {
	key := recordingKey(ip)
	if key == "" {
		return nil
	}

	listener.servicesMu.RLock()
	services := listener.services[key]
	listener.servicesMu.RUnlock()
	if len(services) == 0 {
		return nil
	}

	items := make([]adoption.TCPServiceStatus, 0, len(services))
	for _, managed := range services {
		if managed != nil {
			items = append(items, managed.snapshot())
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Service < items[j].Service
	})

	return items
}

func (listener *pcapAdoptionListener) takeTCPService(ip net.IP, service string) *managedTCPService {
	key := recordingKey(ip)
	if key == "" {
		return nil
	}

	listener.servicesMu.Lock()
	defer listener.servicesMu.Unlock()

	byService := listener.services[key]
	if len(byService) == 0 {
		return nil
	}

	managed := byService[service]
	delete(byService, service)
	if len(byService) == 0 {
		delete(listener.services, key)
	}

	return managed
}

func (listener *pcapAdoptionListener) takeTCPServices(ip net.IP) []*managedTCPService {
	listener.servicesMu.Lock()
	defer listener.servicesMu.Unlock()

	if len(listener.services) == 0 {
		return nil
	}

	if ip == nil {
		items := make([]*managedTCPService, 0, len(listener.services)*2)
		for key, byService := range listener.services {
			items = append(items, drainManagedTCPServices(byService)...)
			delete(listener.services, key)
		}
		return items
	}

	key := recordingKey(ip)
	if key == "" {
		return nil
	}

	byService := listener.services[key]
	if len(byService) == 0 {
		return nil
	}

	items := drainManagedTCPServices(byService)
	delete(listener.services, key)

	return items
}

func (listener *pcapAdoptionListener) storeTCPService(ip net.IP, managed *managedTCPService) {
	key := recordingKey(ip)
	if key == "" || managed == nil {
		return
	}

	listener.servicesMu.Lock()
	if listener.services == nil {
		listener.services = make(map[string]map[string]*managedTCPService)
	}
	byService := listener.services[key]
	if byService == nil {
		byService = make(map[string]*managedTCPService)
		listener.services[key] = byService
	}
	byService[managed.specSnapshot().service] = managed
	listener.servicesMu.Unlock()
}

func drainManagedTCPServices(byService map[string]*managedTCPService) []*managedTCPService {
	if len(byService) == 0 {
		return nil
	}

	items := make([]*managedTCPService, 0, len(byService))
	for service, managed := range byService {
		if managed != nil {
			items = append(items, managed)
		}
		delete(byService, service)
	}

	return items
}

func (listener *pcapAdoptionListener) restoreTCPServices(identity adoption.Identity, group *adoptedEngineGroup, suspended []*managedTCPService) {
	if identity == nil || group == nil || len(suspended) == 0 {
		return
	}

	for _, previous := range suspended {
		if previous == nil {
			continue
		}

		spec := previous.specSnapshot()
		managed, err := startManagedTCPService(group, identity, spec, listener.resolveScript)
		if err != nil {
			managed = newFailedManagedTCPService(spec, err)
		}
		listener.storeTCPService(identity.IP(), managed)
	}
}

func startManagedTCPService(group *adoptedEngineGroup, identity adoption.Identity, spec tcpServiceSpec, resolveScript adoption.ScriptLookupFunc) (*managedTCPService, error) {
	if identity == nil {
		return nil, fmt.Errorf("TCP service requires an adopted identity")
	}

	switch spec.service {
	case adoption.TCPServiceEcho:
		return startEchoTCPService(group, identity.IP(), spec)
	case adoption.TCPServiceHTTP:
		return startHTTPTCPService(group, identity, spec, resolveScript)
	default:
		return nil, fmt.Errorf("unsupported TCP service %q", spec.service)
	}
}

func startEchoTCPService(group *adoptedEngineGroup, ip net.IP, spec tcpServiceSpec) (*managedTCPService, error) {
	tcpListener, err := listenGroupTCP(group, ip, spec.port)
	if err != nil {
		return nil, err
	}

	server := &echoTCPServer{
		listener: tcpListener,
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	managed := newManagedTCPService(spec, server.done, server.Close)
	go func() {
		defer close(server.done)
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				if !isClosedNetworkError(err) {
					managed.fail(fmt.Errorf("accept echo connection: %w", err))
				}
				return
			}

			server.trackConn(conn)
			go server.runConn(conn)
		}
	}()

	return managed, nil
}

func startHTTPTCPService(group *adoptedEngineGroup, identity adoption.Identity, spec tcpServiceSpec, resolveScript adoption.ScriptLookupFunc) (*managedTCPService, error) {
	rootDirectory, err := validateHTTPRootDirectory(spec.rootDirectory)
	if err != nil {
		return nil, err
	}
	spec.rootDirectory = rootDirectory

	tcpListener, err := listenGroupTCP(group, identity.IP(), spec.port)
	if err != nil {
		return nil, err
	}
	closeListener := true
	defer func() {
		if closeListener {
			_ = tcpListener.Close()
		}
	}()

	var binding *httpServiceScriptBinding
	if spec.scriptName != "" {
		if resolveScript == nil {
			return nil, fmt.Errorf("HTTP service scripts are unavailable")
		}
		storedScript, err := resolveScript(scriptpkg.StoredScriptRef{
			Name:    spec.scriptName,
			Surface: scriptpkg.SurfaceHTTPService,
		})
		if err != nil {
			return nil, err
		}
		hasRequest, hasResponse, err := scriptpkg.HTTPServiceHooks(storedScript)
		if err != nil {
			return nil, err
		}
		binding = &httpServiceScriptBinding{
			script:      storedScript,
			hasRequest:  hasRequest,
			hasResponse: hasResponse,
		}
	}

	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveListener := net.Listener(tcpListener)
	var localCertificate *scriptpkg.TLSCertificate
	if spec.useTLS {
		tlsConfig, err := newSelfSignedTLSConfig(identity.IP())
		if err != nil {
			return nil, err
		}
		if len(tlsConfig.Certificates) != 0 && len(tlsConfig.Certificates[0].Certificate) != 0 {
			if leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0]); err == nil {
				certificate := tlsCertificateFromX509(leaf)
				localCertificate = &certificate
			}
		}
		serveListener = tls.NewListener(tcpListener, tlsConfig)
	}

	done := make(chan struct{})
	managed := newManagedTCPService(spec, done, func() error {
		return errors.Join(server.Close(), serveListener.Close())
	})
	server.Handler = newHTTPServiceHandler(
		http.FileServer(http.Dir(rootDirectory)),
		identity,
		spec,
		binding,
		managed,
		localCertificate,
	)
	go func() {
		defer close(done)
		group.registerManagedHTTPPort(uint16(spec.port))
		defer group.unregisterManagedHTTPPort(uint16(spec.port))
		if err := server.Serve(serveListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !isClosedNetworkError(err) {
			managed.fail(fmt.Errorf("serve HTTP: %w", err))
		}
	}()

	closeListener = false
	return managed, nil
}

func listenGroupTCP(group *adoptedEngineGroup, ip net.IP, port int) (*gonet.TCPListener, error) {
	ip = common.NormalizeIPv4(ip)
	if group == nil || ip == nil {
		return nil, fmt.Errorf("TCP service requires a valid IPv4 identity")
	}

	return gonet.ListenTCP(group.stack, tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
}

func validateHTTPRootDirectory(rootDirectory string) (string, error) {
	rootDirectory = strings.TrimSpace(rootDirectory)
	if rootDirectory == "" {
		return "", fmt.Errorf("rootDirectory is required")
	}

	rootDirectory = filepath.Clean(rootDirectory)
	info, err := os.Stat(rootDirectory)
	if err != nil {
		return "", fmt.Errorf("rootDirectory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("rootDirectory must be a directory")
	}

	return rootDirectory, nil
}

func newManagedTCPService(spec tcpServiceSpec, done chan struct{}, stopFn func() error) *managedTCPService {
	return &managedTCPService{
		spec:    spec,
		started: time.Now().UTC(),
		active:  true,
		stopFn:  stopFn,
		done:    done,
	}
}

func newFailedManagedTCPService(spec tcpServiceSpec, err error) *managedTCPService {
	service := &managedTCPService{
		spec:   spec,
		active: false,
	}
	service.fail(err)
	return service
}

func (service *managedTCPService) snapshot() adoption.TCPServiceStatus {
	if service == nil {
		return adoption.TCPServiceStatus{}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	status := adoption.TCPServiceStatus{
		Service:       service.spec.service,
		Active:        service.active,
		Port:          service.spec.port,
		RootDirectory: service.spec.rootDirectory,
		UseTLS:        service.spec.useTLS,
		ScriptName:    service.spec.scriptName,
		LastError:     service.lastErr,
	}
	if !service.started.IsZero() {
		status.StartedAt = service.started.Format(time.RFC3339Nano)
	}

	return status
}

func (service *managedTCPService) specSnapshot() tcpServiceSpec {
	if service == nil {
		return tcpServiceSpec{}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.spec
}

func (service *managedTCPService) fail(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	service.active = false
	service.lastErr = err.Error()
	service.mu.Unlock()
}

func (service *managedTCPService) recordError(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	if service.active {
		service.lastErr = err.Error()
	}
	service.mu.Unlock()
}

func (service *managedTCPService) clearLastError() {
	if service == nil {
		return
	}

	service.mu.Lock()
	if service.active {
		service.lastErr = ""
	}
	service.mu.Unlock()
}

func (service *managedTCPService) stop() {
	if service == nil {
		return
	}

	service.stopOnce.Do(func() {
		service.mu.Lock()
		service.active = false
		service.lastErr = ""
		stopFn := service.stopFn
		done := service.done
		service.mu.Unlock()

		if stopFn != nil {
			_ = stopFn()
		}
		if done != nil {
			<-done
		}
	})
}

func (server *echoTCPServer) trackConn(conn net.Conn) {
	if server == nil || conn == nil {
		return
	}

	server.mu.Lock()
	server.conns[conn] = struct{}{}
	server.mu.Unlock()
}

func (server *echoTCPServer) untrackConn(conn net.Conn) {
	if server == nil || conn == nil {
		return
	}

	server.mu.Lock()
	delete(server.conns, conn)
	server.mu.Unlock()
}

func (server *echoTCPServer) Close() error {
	if server == nil {
		return nil
	}

	server.mu.Lock()
	conns := make([]net.Conn, 0, len(server.conns))
	for conn := range server.conns {
		conns = append(conns, conn)
	}
	server.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}

	if server.listener == nil {
		return nil
	}

	return server.listener.Close()
}

func (server *echoTCPServer) runConn(conn net.Conn) {
	if conn == nil {
		return
	}
	defer server.untrackConn(conn)
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func newSelfSignedTLSConfig(ip net.IP) (*tls.Config, error) {
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

func isClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return true
	}

	return strings.Contains(err.Error(), "use of closed network connection")
}
