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
	mu       sync.Mutex
	status   ServiceStatus
	stopping bool
	process  ServiceProcess
	done     chan struct{}
	stopOnce sync.Once
}

func NewManagedService(status ServiceStatus) *ManagedService {
	status.Active = true
	status.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return &ManagedService{
		status: status,
		done:   make(chan struct{}),
	}
}

func (service *ManagedService) Port() int {
	return service.status.Port
}

func (service *ManagedService) Start(process ServiceProcess) {
	service.process = process
	go service.monitor()
}

func (service *ManagedService) monitor() {
	waitErr := service.process.Wait()

	service.mu.Lock()
	stopping := service.stopping
	service.status.Active = false
	if !stopping && waitErr != nil {
		service.status.LastError = waitErr.Error()
	}
	service.mu.Unlock()
	close(service.done)
}

func (service *ManagedService) Stop() {
	service.stopOnce.Do(func() {
		service.mu.Lock()
		service.stopping = true
		service.status.Active = false
		service.status.LastError = ""
		service.status.ScriptError = nil
		service.mu.Unlock()

		_ = service.process.Close()
		<-service.done
	})
}

func (service *ManagedService) Snapshot() ServiceStatus {
	service.mu.Lock()
	status := service.status
	service.mu.Unlock()
	return status
}

func (service *ManagedService) RecordScriptError(err ScriptRuntimeError) {
	if err.LastError == "" {
		return
	}

	service.mu.Lock()
	if service.status.Active {
		service.status.LastError = err.LastError
		service.status.ScriptError = &err
	}
	service.mu.Unlock()
}

func (service *ManagedService) ClearScriptError() {
	service.mu.Lock()
	if service.status.Active {
		service.status.LastError = ""
		service.status.ScriptError = nil
	}
	service.mu.Unlock()
}
