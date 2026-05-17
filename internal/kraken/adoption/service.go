package adoption

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"gvisor.dev/gvisor/pkg/buffer"
)

type Manager struct {
	mu         sync.RWMutex
	entries    map[[4]byte]*Identity
	routeMatch func(net.IP) (net.IP, bool)
	scripts    *storage.ScriptStore
}

func NewManager(routeMatch func(net.IP) (net.IP, bool), scripts *storage.ScriptStore) *Manager {
	if routeMatch == nil {
		panic("adoption: route match dependency is required")
	}

	return &Manager{
		entries:    make(map[[4]byte]*Identity),
		routeMatch: routeMatch,
		scripts:    scripts,
	}
}

func (s *Manager) Adopt(request Identity, listener Listener) (Identity, error) {
	if err := prepareIdentity(&request); err != nil {
		return Identity{}, err
	}

	return s.adoptIdentity(request, listener)
}

func (s *Manager) Snapshot() []Identity {
	s.mu.RLock()
	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, *item)
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].InterfaceName != items[j].InterfaceName {
			return items[i].InterfaceName < items[j].InterfaceName
		}
		return bytes.Compare(items[i].IP, items[j].IP) < 0
	})
	return items
}

func (s *Manager) UpdateScripts(ip net.IP, transportScriptName, applicationScriptName string) error {
	transportScriptName = strings.TrimSpace(transportScriptName)
	applicationScriptName = strings.TrimSpace(applicationScriptName)

	item, err := s.lookup(ip)
	if err != nil {
		return err
	}
	transportScript, err := s.lookupScript(transportScriptName, storage.SurfaceTransport)
	if err != nil {
		return err
	}
	applicationScript, err := s.lookupScript(applicationScriptName, storage.SurfaceApplication)
	if err != nil {
		return err
	}
	item.transportScript = transportScript
	item.applicationScript = applicationScript
	item.engine.UpdateTransportScript(transportScript)
	return nil
}

func (s *Manager) StartRecording(ip net.IP, outputPath string) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	status, err := item.listener.StartRecording(item, outputPath)
	if err != nil {
		return Identity{}, err
	}
	item.Recording = &status
	return *item, nil
}

func (s *Manager) StopRecording(ip net.IP) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if recorder := item.TakeRecorder(); recorder != nil {
		recorder.Stop()
	}
	item.Recording = nil
	return *item, nil
}

func (s *Manager) StartService(ip net.IP, request ManagedService, starter ServiceStarter) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if request.Service == "" {
		return Identity{}, fmt.Errorf("service is required")
	}
	if previous := item.takeService(request.Service); previous != nil {
		previous.Stop()
	}

	service := NewManagedService(request)
	process, err := starter(item, service)
	if err != nil {
		return Identity{}, err
	}
	service.Start(process)
	item.storeService(service)
	return *item, nil
}

func (s *Manager) StopService(ip net.IP, service string) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if running := item.takeService(service); running != nil {
		running.Stop()
	}
	return *item, nil
}

func (s *Manager) lookupScript(scriptName string, surface storage.Surface) (*script.CompiledScript, error) {
	if scriptName == "" {
		return nil, nil
	}
	storedScript, err := s.scripts.Lookup(storage.StoredScriptRef{
		Name:    scriptName,
		Surface: surface,
	})
	if err != nil {
		if errors.Is(err, storage.ErrStoredScriptNotFound) {
			return nil, script.MissingStoredScriptError(scriptName)
		}
		return nil, err
	}
	return storedScript.Compiled, nil
}

func (s *Manager) Release(ip net.IP) error {
	key := identityKey(ip)

	s.mu.Lock()
	item, exists := s.entries[key]
	if !exists {
		s.mu.Unlock()
		return errAdoptedIPNotFound(ip)
	}
	delete(s.entries, key)
	s.mu.Unlock()

	return item.Close()
}

func (s *Manager) adoptIdentity(identity Identity, listener Listener) (Identity, error) {
	key := identityKey(identity.IP)

	if listener == nil {
		return Identity{}, fmt.Errorf("listener for interface %s is not registered", identity.InterfaceName)
	}
	closeListener := true
	defer func() {
		if closeListener {
			_ = listener.Close()
		}
	}()

	if err := listener.Healthy(); err != nil {
		return Identity{}, err
	}
	if err := identity.Init(listener, identity.transportScript, identity.applicationScript); err != nil {
		return Identity{}, err
	}

	s.mu.Lock()
	if _, exists := s.entries[key]; exists {
		s.mu.Unlock()
		return Identity{}, errAdoptedIPAlreadyExists(identity.IP)
	}
	s.mu.Unlock()

	if err := listener.CaptureIPv4Target(identity.IP); err != nil {
		return Identity{}, err
	}

	s.mu.Lock()
	s.entries[key] = &identity
	s.mu.Unlock()

	closeListener = false
	return identity, nil
}

func (s *Manager) Lookup(ip net.IP) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	return *item, nil
}

func (s *Manager) lookup(ip net.IP) (*Identity, error) {
	key := identityKey(ip)

	s.mu.RLock()
	item, exists := s.entries[key]
	s.mu.RUnlock()
	if !exists {
		return nil, errAdoptedIPNotFound(ip)
	}
	return item, nil
}

func (s *Manager) ForwardFrame(destinationIP net.IP, frame buffer.Buffer) bool {
	destinationIP = destinationIP.To4()
	if destinationIP == nil {
		return false
	}

	if item, err := s.lookup(destinationIP); err == nil {
		item.InjectFrame(frame)
		return true
	}

	viaIP, exists := s.routeMatch(destinationIP)
	if !exists {
		return false
	}

	item, err := s.lookup(viaIP)
	if err != nil {
		return false
	}
	item.InjectFrame(frame)
	return true
}

func identityKey(ip net.IP) [4]byte {
	return *(*[4]byte)(ip.To4())
}

func errAdoptedIPNotFound(ip net.IP) error {
	return fmt.Errorf("IP %s is not currently adopted", ip)
}

func errAdoptedIPAlreadyExists(ip net.IP) error {
	return fmt.Errorf("IP %s is already adopted", ip)
}

func (s *Manager) Close() error {
	s.mu.Lock()
	var closeErr error
	for key, item := range s.entries {
		delete(s.entries, key)
		if err := item.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	s.mu.Unlock()

	return closeErr
}
