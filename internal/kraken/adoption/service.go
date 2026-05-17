package adoption

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
)

type Manager struct {
	mu         sync.RWMutex
	entries    map[[4]byte]Identity
	routeMatch func(net.IP) (net.IP, bool)
}

func NewManager(routeMatch func(net.IP) (net.IP, bool)) *Manager {
	if routeMatch == nil {
		panic("adoption: route match dependency is required")
	}

	return &Manager{
		entries:    make(map[[4]byte]Identity),
		routeMatch: routeMatch,
	}
}

func (s *Manager) Adopt(request Identity, listener Listener) (Identity, error) {
	if err := normalizeIdentity(&request); err != nil {
		return Identity{}, err
	}

	return s.adoptIdentity(request, listener)
}

func (s *Manager) Snapshot() []Identity {
	s.mu.RLock()
	items := make([]Identity, 0, len(s.entries))
	for _, item := range s.entries {
		items = append(items, item.Snapshot())
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
	_, err := s.apply(ip, func(item *Identity) error {
		transportScript, err := resolveTransportScript(transportScriptName, item.listener.LookupScript())
		if err != nil {
			return err
		}
		item.TransportScriptName = transportScriptName
		item.ApplicationScriptName = applicationScriptName
		item.engine.UpdateTransportScript(transportScript)
		return nil
	})
	return err
}

func (s *Manager) StartRecording(ip net.IP, outputPath string) (Identity, error) {
	return s.apply(ip, func(item *Identity) error {
		status, err := item.listener.StartRecording(item, outputPath)
		if err == nil {
			item.Recording = &status
		}
		return err
	})
}

func (s *Manager) StopRecording(ip net.IP) (Identity, error) {
	return s.apply(ip, func(item *Identity) error {
		if recorder := item.TakeRecorder(); recorder != nil {
			recorder.Stop()
		}
		item.Recording = nil
		return nil
	})
}

func (s *Manager) StartService(ip net.IP, status ServiceStatus, starter ServiceStarter) (Identity, error) {
	return s.apply(ip, func(item *Identity) error {
		if strings.TrimSpace(status.Service) == "" {
			return fmt.Errorf("service is required")
		}
		if previous := item.takeService(status.Service); previous != nil {
			previous.Stop()
		}

		service := NewManagedService(status)
		process, err := starter(item, service)
		if err != nil {
			return err
		}
		service.Start(process)
		item.storeService(service)
		return nil
	})
}

func (s *Manager) StopService(ip net.IP, service string) (Identity, error) {
	return s.apply(ip, func(item *Identity) error {
		running := item.takeService(service)
		if running == nil {
			return nil
		}
		running.Stop()
		port := running.Port()
		if servicePortReleased(item, port) {
			return nil
		}
		return fmt.Errorf("port %d is still busy", port)
	})
}

func servicePortReleased(identity *Identity, port int) bool {
	for attempt := 0; attempt < 6; attempt++ {
		probe, err := identity.ListenTCP(port)
		if err == nil {
			_ = probe.Close()
			return true
		}

		time.Sleep(25 * time.Millisecond)
	}

	return false
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
	if err := listener.Healthy(); err != nil {
		_ = listener.Close()
		return Identity{}, err
	}
	if err := identity.Init(listener); err != nil {
		_ = listener.Close()
		return Identity{}, err
	}

	s.mu.Lock()
	if _, exists := s.entries[key]; exists {
		s.mu.Unlock()
		_ = listener.Close()
		return Identity{}, errAdoptedIPAlreadyExists(identity.IP)
	}

	s.entries[key] = identity
	s.mu.Unlock()

	if err := listener.CaptureIPv4Target(identity.IP); err != nil {
		s.mu.Lock()
		delete(s.entries, key)
		s.mu.Unlock()
		_ = listener.Close()
		return Identity{}, err
	}

	s.mu.Lock()
	s.entries[key] = identity
	s.mu.Unlock()

	return identity, nil
}

func (s *Manager) Lookup(ip net.IP) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	return item.Snapshot(), nil
}

func (s *Manager) lookup(ip net.IP) (Identity, error) {
	key := identityKey(ip)

	s.mu.RLock()
	item, exists := s.entries[key]
	s.mu.RUnlock()
	if !exists {
		return Identity{}, errAdoptedIPNotFound(ip)
	}
	return item, nil
}

func (s *Manager) apply(ip net.IP, operation func(*Identity) error) (Identity, error) {
	item, err := s.lookup(ip)
	if err != nil {
		return Identity{}, err
	}
	if err := operation(&item); err != nil {
		return Identity{}, err
	}
	s.mu.Lock()
	s.entries[identityKey(item.IP)] = item
	s.mu.Unlock()
	return item.Snapshot(), nil
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
	if err != nil || item.listener == nil {
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
