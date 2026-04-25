package operations

import (
	"context"
	"net"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
)

type adoptedEngine struct {
	runtime  *netruntime.Engine
	identity adoption.Identity
}

func newAdoptedEngine(config netruntime.EngineConfig, outbound func(*adoptedEngine, []byte) error) (*adoptedEngine, error) {
	binding := &adoptedEngine{}
	runtime, err := netruntime.NewEngine(config, func(_ *netruntime.Engine, frame []byte) error {
		return outbound(binding, frame)
	})
	if err != nil {
		return nil, err
	}
	binding.runtime = runtime
	return binding, nil
}

func engineConfigForIdentity(identity adoption.Identity, routes []net.IPNet) netruntime.EngineConfig {
	return netruntime.EngineConfig{
		InterfaceName:  identity.Interface.Name,
		MAC:            identity.MAC,
		DefaultGateway: identity.DefaultGateway,
		Routes:         routes,
		MTU:            identity.MTU,
	}
}

func (engine *adoptedEngine) addIdentity(identity adoption.Identity) error {
	if engine == nil || engine.runtime == nil {
		return nil
	}
	if err := engine.runtime.AddEndpoint(netruntime.Endpoint{IP: identity.IP}); err != nil {
		return err
	}
	engine.identity = identity
	return nil
}

func (engine *adoptedEngine) removeIdentity(ip net.IP) {
	if engine == nil || engine.runtime == nil {
		return
	}
	engine.runtime.RemoveEndpoint(ip)
	ip = common.NormalizeIPv4(ip)
	if ip != nil && engine.identity.IP.Equal(ip) {
		engine.identity = adoption.Identity{}
	}
}

func (engine *adoptedEngine) identitySnapshot() *adoption.Identity {
	if engine == nil || common.NormalizeIPv4(engine.identity.IP) == nil {
		return nil
	}
	identity := engine.identity
	return &identity
}

func (engine *adoptedEngine) hasBoundTransportScripts() bool {
	return engine != nil && engine.identity.TransportScriptName != ""
}

func (engine *adoptedEngine) injectFrame(frame []byte) {
	if engine != nil && engine.runtime != nil {
		engine.runtime.InjectFrame(frame)
	}
}

func (engine *adoptedEngine) rememberPeer(ip net.IP, mac net.HardwareAddr) {
	if engine != nil && engine.runtime != nil {
		engine.runtime.RememberPeer(ip, mac)
	}
}

func (engine *adoptedEngine) peerMAC(ip net.IP) (net.HardwareAddr, bool) {
	if engine == nil || engine.runtime == nil {
		return nil, false
	}
	return engine.runtime.PeerMAC(ip)
}

func (engine *adoptedEngine) close() {
	if engine != nil && engine.runtime != nil {
		engine.runtime.Close()
	}
}

func (engine *adoptedEngine) matchesIdentity(identity adoption.Identity) bool {
	return engine != nil && engine.runtime != nil && engine.runtime.MatchesConfig(engineConfigForIdentity(identity, nil))
}

func (engine *adoptedEngine) arpCacheSnapshot() []adoption.ARPCacheItem {
	if engine == nil || engine.runtime == nil {
		return nil
	}
	items := engine.runtime.ARPCacheSnapshot()
	snapshot := make([]adoption.ARPCacheItem, 0, len(items))
	for _, item := range items {
		snapshot = append(snapshot, adoption.ARPCacheItem{IP: item.IP, MAC: item.MAC})
	}
	return snapshot
}

func (engine *adoptedEngine) ping(sourceIP, targetIP net.IP, count int, payload []byte, timeout time.Duration) ([]netruntime.PingReply, error) {
	return engine.runtime.Ping(sourceIP, targetIP, count, payload, timeout)
}

func (engine *adoptedEngine) listenTCP(ip net.IP, port int) (net.Listener, error) {
	return engine.runtime.ListenTCP(ip, port)
}

func (engine *adoptedEngine) dialTCP(ctx context.Context, sourceIP, targetIP net.IP, port int) (net.Conn, error) {
	return engine.runtime.DialTCP(ctx, sourceIP, targetIP, port)
}

func (engine *adoptedEngine) dialUDP(sourceIP, targetIP net.IP, port int) (net.Conn, error) {
	return engine.runtime.DialUDP(sourceIP, targetIP, port)
}

func engineKey(ip net.IP) string {
	normalized := common.NormalizeIPv4(ip)
	if normalized == nil {
		return ""
	}
	return normalized.String()
}
