package capture

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (listener *pcapAdoptionListener) handleEngineGroupOutbound(group *adoptedEngineGroup, pkts stack.PacketBufferList) (int, tcpip.Error) {
	sent := 0
	for _, pkt := range pkts.AsSlice() {
		if err := listener.handleEngineOutboundPacket(group, pkt); err != nil {
			if sent == 0 {
				return 0, &tcpip.ErrAborted{}
			}
			return sent, nil
		}
		sent++
	}
	return sent, nil
}

func (listener *pcapAdoptionListener) handleEngineOutboundPacket(group *adoptedEngineGroup, pkt *stack.PacketBuffer) error {
	if listener == nil || group == nil || pkt == nil {
		return nil
	}

	hasBoundScripts := group.hasBoundScripts()
	if !hasBoundScripts {
		if frame, ok := packetBufferSlice(pkt); ok {
			return listener.writePacket(frame)
		}
	}

	skipPacketScript := hasBoundScripts && group.isManagedHTTPPacket(pkt)
	if skipPacketScript {
		if frame, ok := packetBufferSlice(pkt); ok {
			return listener.writePacket(frame)
		}
	}

	frame := listener.takeFrameBuffer(pkt.Size())
	frame = appendPacketBufferTo(frame[:0], pkt)
	defer listener.releaseFrameBuffer(frame[:0])

	if !hasBoundScripts || skipPacketScript {
		return listener.writePacket(frame)
	}

	identity, exists := group.identityForSourceAddress(pkt.EgressRoute.LocalAddress, pkt)
	if !exists {
		return listener.writePacket(frame)
	}

	scriptCtx := buildBoundPacketScript(identity)
	if scriptCtx.ScriptName == "" {
		return listener.writePacket(frame)
	}

	mutablePacket, err := script.NewMutablePacket(frame)
	if err != nil {
		return err
	}
	defer mutablePacket.Release()

	if err := listener.applyBoundMutableScript(mutablePacket, scriptCtx); err != nil {
		return err
	}

	frame = mutablePacket.Bytes()
	return listener.writePacket(frame)
}

func (listener *pcapAdoptionListener) applyBoundMutableScript(packet *script.MutablePacket, ctx script.ExecutionContext) error {
	return listener.applyMutableScriptByName(packet, ctx.ScriptName, ctx)
}

func (listener *pcapAdoptionListener) applyMutableScriptByName(packet *script.MutablePacket, name string, ctx script.ExecutionContext) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if listener.resolveScript == nil {
		return fmt.Errorf("stored scripts are unavailable")
	}

	storedScript, err := listener.resolveScript(script.StoredScriptRef{
		Name:    name,
		Surface: script.SurfacePacket,
	})
	if err != nil {
		if errors.Is(err, script.ErrStoredScriptNotFound) {
			return fmt.Errorf("stored script %q was not found", name)
		}
		return err
	}
	if storedScript.Name == "" {
		return fmt.Errorf("stored script %q was not found", name)
	}

	return script.Execute(storedScript, packet, ctx, nil)
}
