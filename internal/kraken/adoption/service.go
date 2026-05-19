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
	mu              sync.RWMutex
	entries         map[[4]byte]*Identity
	routingListener RoutingListener
	scripts         *storage.ScriptStore
}

func NewManager(scripts *storage.ScriptStore) *Manager {
	return &Manager{
		entries: make(map[[4]byte]*Identity),
		scripts: scripts,
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
	captureErr := s.refreshRoutingCaptureLocked()
	s.mu.Unlock()

	closeErr := item.Close()
	if captureErr != nil {
		return captureErr
	}
	return closeErr
}

func (s *Manager) UseRoutingListener(listener RoutingListener) error {
	s.mu.Lock()
	previous := s.routingListener
	s.routingListener = listener
	err := s.refreshRoutingCaptureLocked()
	s.mu.Unlock()

	if previous != nil && previous != listener {
		_ = previous.Close()
	}
	return err
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
		return Identity{}, fmt.Errorf("IP %s is already adopted", identity.IP)
	}
	s.entries[key] = &identity
	s.mu.Unlock()

	if err := listener.CaptureIPv4Target(identity.IP); err != nil {
		s.mu.Lock()
		delete(s.entries, key)
		s.mu.Unlock()
		return Identity{}, err
	}
	s.mu.Lock()
	if err := s.refreshRoutingCaptureLocked(); err != nil {
		delete(s.entries, key)
		s.mu.Unlock()
		return Identity{}, err
	}
	s.mu.Unlock()

	closeListener = false
	return identity, nil
}

func (s *Manager) refreshRoutingCaptureLocked() error {
	if s.routingListener == nil {
		return nil
	}
	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, *item)
	}
	return s.routingListener.CaptureIPv4Segments(items)
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

	s.mu.RLock()
	item := s.entries[identityKey(destinationIP)]
	if item == nil {
		item = s.routeIdentity(destinationIP)
	}
	s.mu.RUnlock()

	if item == nil {
		return false
	}
	item.InjectFrame(frame)
	return true
}

func (s *Manager) routeIdentity(destinationIP net.IP) *Identity {
	var selected *Identity
	selectedPrefix := -1
	for _, item := range s.entries {
		mask := net.IPMask(item.SubnetMask)
		if len(mask) != net.IPv4len {
			continue
		}
		if network := item.IP.Mask(mask); !network.Equal(destinationIP.Mask(mask)) {
			continue
		}
		prefix, _ := mask.Size()
		if prefix > selectedPrefix {
			selected = item
			selectedPrefix = prefix
		}
	}
	return selected
}

func identityKey(ip net.IP) [4]byte {
	return *(*[4]byte)(ip.To4())
}

func errAdoptedIPNotFound(ip net.IP) error {
	return fmt.Errorf("IP %s is not currently adopted", ip)
}

func (s *Manager) Close() error {
	s.mu.Lock()
	routingListener := s.routingListener
	s.routingListener = nil
	items := make([]*Identity, 0, len(s.entries))
	for key, item := range s.entries {
		delete(s.entries, key)
		items = append(items, item)
	}
	s.mu.Unlock()

	var closeErr error
	if routingListener != nil {
		closeErr = routingListener.Close()
	}
	for _, item := range items {
		if err := item.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}
