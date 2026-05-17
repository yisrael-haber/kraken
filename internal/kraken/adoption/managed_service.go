package adoption

import (
	"sync"
	"time"
)

type ServiceProcess interface {
	Close() error
	Wait() error
}

type ServiceStarter func(*Identity, *ManagedService) (ServiceProcess, error)

type ManagedService struct {
	Service   string               `json:"service"`
	Active    bool                 `json:"active"`
	Port      int                  `json:"port"`
	Config    map[string]string    `json:"config,omitempty"`
	Summary   []ServiceSummaryItem `json:"summary,omitempty"`
	StartedAt string               `json:"startedAt,omitempty"`
	LastError string               `json:"lastError,omitempty"`

	mu       sync.Mutex
	process  ServiceProcess
	stopOnce sync.Once
}

func NewManagedService(service ManagedService) *ManagedService {
	service.Active = true
	service.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return &service
}

func (service *ManagedService) Start(process ServiceProcess) {
	service.process = process
	go service.monitor()
}

func (service *ManagedService) monitor() {
	waitErr := service.process.Wait()

	service.mu.Lock()
	if waitErr != nil && service.Active {
		service.LastError = waitErr.Error()
	}
	service.Active = false
	service.mu.Unlock()
}

func (service *ManagedService) Stop() {
	service.stopOnce.Do(func() {
		service.mu.Lock()
		service.Active = false
		service.LastError = ""
		service.mu.Unlock()

		_ = service.process.Close()
		_ = service.process.Wait()
	})
}

func (service *ManagedService) Snapshot() ManagedService {
	service.mu.Lock()
	status := ManagedService{
		Service:   service.Service,
		Active:    service.Active,
		Port:      service.Port,
		Config:    service.Config,
		Summary:   service.Summary,
		StartedAt: service.StartedAt,
		LastError: service.LastError,
	}
	service.mu.Unlock()
	return status
}
