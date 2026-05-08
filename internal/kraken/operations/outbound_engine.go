package operations

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"gvisor.dev/gvisor/pkg/buffer"
)

func (listener *pcapAdoptionListener) handleEngineOutbound(identity *adoption.Identity, frame buffer.Buffer) error {
	defer frame.Release()
	if listener == nil || identity == nil || frame.Size() == 0 {
		return nil
	}

	scriptCtx := buildBoundTransportScript(*identity)
	if scriptCtx.ScriptName == "" {
		return listener.writePacketBuffer(&frame)
	}

	if err := listener.emitPreparedFrame(&frame, scriptCtx); err != nil {
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

func (listener *pcapAdoptionListener) emitPreparedFrame(frame *buffer.Buffer, ctx script.ExecutionContext) error {
	if listener == nil {
		return nil
	}
	if ctx.ScriptName == "" {
		return listener.writePacketBuffer(frame)
	}

	mutablePacket, err := script.NewMutablePacket(mutableBufferBytes(frame))
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
