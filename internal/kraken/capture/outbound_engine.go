package capture

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (listener *pcapAdoptionListener) handleEngineOutbound(engine *adoptedEngine, pkts stack.PacketBufferList) (int, tcpip.Error) {
	sent := 0
	for _, pkt := range pkts.AsSlice() {
		if err := listener.handleEngineOutboundPacket(engine, pkt); err != nil {
			if sent == 0 {
				return 0, &tcpip.ErrAborted{}
			}
			return sent, nil
		}
		sent++
	}
	return sent, nil
}

func (listener *pcapAdoptionListener) handleEngineOutboundPacket(engine *adoptedEngine, pkt *stack.PacketBuffer) error {
	if listener == nil || engine == nil || pkt == nil {
		return nil
	}

	identity := engine.identitySnapshot()
	scriptCtx := buildBoundTransportScript(identity)
	if scriptCtx.ScriptName == "" {
		if frame, ok := packetBufferSlice(pkt); ok {
			return listener.writePacket(frame)
		}
	}

	frame := listener.takeFrameBuffer(pkt.Size())
	frame = appendPacketBufferTo(frame[:0], pkt)
	defer listener.releaseFrameBuffer(frame[:0])

	return listener.emitPreparedFrame(frame, scriptCtx)
}

func (listener *pcapAdoptionListener) applyMutableScriptByName(packet *script.MutablePacket, surface script.Surface, name string, ctx script.ExecutionContext, dispatch func([]byte) error) (script.PacketExecutionResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return script.PacketExecutionResult{}, nil
	}
	if listener.resolveScript == nil {
		return script.PacketExecutionResult{}, fmt.Errorf("stored scripts are unavailable")
	}

	storedScript, err := listener.resolveScript(script.StoredScriptRef{
		Name:    name,
		Surface: surface,
	})
	if err != nil {
		if errors.Is(err, script.ErrStoredScriptNotFound) {
			return script.PacketExecutionResult{}, fmt.Errorf("stored script %q was not found", name)
		}
		return script.PacketExecutionResult{}, err
	}
	if storedScript.Name == "" {
		return script.PacketExecutionResult{}, fmt.Errorf("stored script %q was not found", name)
	}

	result, err := script.ExecuteWithDispatch(storedScript, packet, ctx, nil, dispatch)
	if err != nil {
		return script.PacketExecutionResult{}, err
	}
	return result, nil
}

func (listener *pcapAdoptionListener) emitPreparedFrame(frame []byte, ctx script.ExecutionContext) error {
	if listener == nil {
		return nil
	}
	if ctx.ScriptName == "" {
		return listener.writePacket(frame)
	}

	mutablePacket, err := script.NewMutablePacket(frame)
	if err != nil {
		return err
	}
	defer mutablePacket.Release()

	result, err := listener.applyMutableScriptByName(mutablePacket, script.SurfaceTransport, ctx.ScriptName, ctx, listener.writePacket)
	if err != nil {
		return err
	}
	if result.DropOriginal {
		return nil
	}

	return listener.writePacket(mutablePacket.Bytes())
}
