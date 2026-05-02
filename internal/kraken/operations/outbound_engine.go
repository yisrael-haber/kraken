package operations

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

func (listener *pcapAdoptionListener) handleEngineOutbound(engine *adoptedEngine, frame []byte) error {
	if listener == nil || engine == nil || len(frame) == 0 {
		return nil
	}

	identity := engine.identitySnapshot()
	if identity == nil {
		return nil
	}
	scriptCtx := buildBoundTransportScript(*identity)
	if scriptCtx.ScriptName == "" {
		return listener.writePacket(frame)
	}

	prepared := listener.takeFrameBuffer(len(frame))
	prepared = append(prepared[:0], frame...)
	defer listener.releaseFrameBuffer(prepared[:0])

	if err := listener.emitPreparedFrame(prepared, scriptCtx); err != nil {
		return err
	}
	return nil
}

func (listener *pcapAdoptionListener) applyMutableScriptByName(packet *script.MutablePacket, surface script.Surface, name string, ctx script.ExecutionContext, dispatch func([]byte) error) (script.PacketExecutionResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return script.PacketExecutionResult{}, nil
	}
	if listener.resolveScript == nil {
		return script.PacketExecutionResult{}, fmt.Errorf("stored scripts are unavailable")
	}

	storedScript, err := listener.resolveScript(storage.StoredScriptRef{
		Name:    name,
		Surface: storage.Surface(surface),
	})
	if err != nil {
		if errors.Is(err, storage.ErrStoredScriptNotFound) {
			return script.PacketExecutionResult{}, fmt.Errorf("stored script %q was not found", name)
		}
		return script.PacketExecutionResult{}, err
	}
	if storedScript.Name == "" || storedScript.Compiled == nil {
		return script.PacketExecutionResult{}, fmt.Errorf("stored script %q was not found", name)
	}

	result, err := script.ExecuteWithDispatch(storedScript.Compiled, packet, ctx, nil, dispatch)
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
		listener.recordTransportScriptError(ctx, err)
		return err
	}
	if result.DropOriginal {
		return nil
	}

	return listener.writePacket(mutablePacket.Bytes())
}
