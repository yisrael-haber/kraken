package operations

import (
	"bytes"
	"context"
	"net"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"gvisor.dev/gvisor/pkg/buffer"
)

type adoptedEngine struct {
	runtime  *netruntime.Engine
	identity adoption.Identity
}

func newAdoptedEngine(config netruntime.EngineConfig, outbound func(*adoptedEngine, buffer.Buffer) error) (*adoptedEngine, error) {
	binding := &adoptedEngine{}
	runtime, err := netruntime.NewEngine(config, func(frame buffer.Buffer) error {
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
		IP:             identity.IP,
		InterfaceName:  identity.InterfaceName,
		MAC:            net.HardwareAddr(identity.MAC),
		DefaultGateway: identity.DefaultGateway,
		Routes:         routes,
		MTU:            uint32(identity.MTU),
	}
}

func (engine *adoptedEngine) addIdentity(identity adoption.Identity) error {
	if engine == nil || engine.runtime == nil {
		return nil
	}
	engine.identity = identity
	return nil
}

func (engine *adoptedEngine) removeIdentity(ip net.IP) {
	if engine == nil || engine.runtime == nil {
		return
	}
	ip = ip.To4()
	if ip != nil && engine.identity.IP.Equal(ip) {
		engine.identity = adoption.Identity{}
	}
}

func (engine *adoptedEngine) identitySnapshot() *adoption.Identity {
	if engine == nil || engine.identity.IP.To4() == nil {
		return nil
	}
	identity := engine.identity
	return &identity
}

func (engine *adoptedEngine) hasBoundTransportScripts() bool {
	return engine != nil && engine.identity.TransportScriptName != ""
}

func (engine *adoptedEngine) injectFrame(frame buffer.Buffer) {
	if engine != nil && engine.runtime != nil {
		engine.runtime.InjectFrame(frame)
		return
	}
	frame.Release()
}

func (engine *adoptedEngine) close() {
	if engine != nil && engine.runtime != nil {
		engine.runtime.Close()
	}
}

func (engine *adoptedEngine) matchesIdentity(identity adoption.Identity) bool {
	if engine == nil || engine.runtime == nil {
		return false
	}
	existing := engine.identity
	if existing.InterfaceName != "" && identity.InterfaceName != "" && existing.InterfaceName != identity.InterfaceName {
		return false
	}
	if existing.MTU != 0 && identity.MTU != 0 && existing.MTU != identity.MTU {
		return false
	}
	if !bytes.Equal(existing.MAC, identity.MAC) {
		return false
	}
	if existing.DefaultGateway == nil {
		return true
	}
	gateway := identity.DefaultGateway.To4()
	return gateway != nil && existing.DefaultGateway.Equal(gateway)
}

func (engine *adoptedEngine) listenTCP(port int) (net.Listener, error) {
	return engine.runtime.ListenTCP(port)
}

func (engine *adoptedEngine) dialTCP(ctx context.Context, targetIP net.IP, port int) (net.Conn, error) {
	return engine.runtime.DialTCP(ctx, targetIP, port)
}

func (engine *adoptedEngine) dialUDP(targetIP net.IP, port int) (net.Conn, error) {
	return engine.runtime.DialUDP(targetIP, port)
}

func engineKey(ip net.IP) string {
	normalized := ip.To4()
	if normalized == nil {
		return ""
	}
	return normalized.String()
}
