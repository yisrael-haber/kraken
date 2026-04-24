package adoption

import (
	"errors"
	"fmt"
	"net"

	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

var ErrListenerStopped = errors.New("adoption listener is not running")

type Identity interface {
	Label() string
	IP() net.IP
	Interface() net.Interface
	MAC() net.HardwareAddr
	DefaultGateway() net.IP
	MTU() uint32
	TransportScriptName() string
	ApplicationScriptName() string
}

type RouteMatchFunc func(destinationIP net.IP) (routingpkg.StoredRoute, bool)
type ScriptLookupFunc func(ref scriptpkg.StoredScriptRef) (scriptpkg.StoredScript, error)
type ForwardLookupFunc func(destinationIP net.IP) (ForwardingDecision, bool)

type ForwardingDecision struct {
	Listener Listener
	Identity Identity
	Route    routingpkg.StoredRoute
	Routed   bool
}

type Listener interface {
	Close() error
	Healthy() error
	EnsureIdentity(identity Identity) error
	InjectFrame(frame []byte) error
	RouteFrame(via Identity, route routingpkg.StoredRoute, frame []byte) error
	Ping(source Identity, targetIP net.IP, count int, payload []byte) (PingAdoptedIPAddressResult, error)
	ResolveDNS(source Identity, request ResolveDNSAdoptedIPAddressRequest) (ResolveDNSAdoptedIPAddressResult, error)
	ARPCacheSnapshot() []ARPCacheItem
	StatusSnapshot(ip net.IP) ListenerStatus
	StartRecording(source Identity, outputPath string) (PacketRecordingStatus, error)
	StopRecording(ip net.IP) error
	RecordingSnapshot(ip net.IP) *PacketRecordingStatus
	StartService(source Identity, service string, config map[string]string) (ServiceStatus, error)
	StopService(ip net.IP, service string) error
	ServiceSnapshot(ip net.IP) []ServiceStatus
	ForgetIdentity(ip net.IP)
}

type NewListenerFunc func(net.Interface, ForwardLookupFunc, ScriptLookupFunc) (Listener, error)

func defaultScriptLookup(scriptpkg.StoredScriptRef) (scriptpkg.StoredScript, error) {
	return scriptpkg.StoredScript{}, scriptpkg.ErrStoredScriptNotFound
}

func defaultRouteMatch(net.IP) (routingpkg.StoredRoute, bool) {
	return routingpkg.StoredRoute{}, false
}

func defaultNewListener(net.Interface, ForwardLookupFunc, ScriptLookupFunc) (Listener, error) {
	return nil, fmt.Errorf("adoption listeners are unavailable")
}
