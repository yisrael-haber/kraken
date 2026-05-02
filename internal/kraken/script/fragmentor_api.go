package script

import (
	"fmt"
	"sync"

	"go.starlark.net/starlark"
)

type PacketExecutionResult struct {
	DropOriginal     bool
	DispatchedFrames [][]byte
}

type packetExecutionState struct {
	mu               sync.Mutex
	dispatchedFrames [][]byte
	trackedPackets   []*MutablePacket
	dispatch         func([]byte) error
}

func (state *packetExecutionState) dispatchFrame(frame []byte) error {
	if state == nil || len(frame) == 0 {
		return nil
	}

	if state.dispatch != nil {
		if err := state.dispatch(append([]byte(nil), frame...)); err != nil {
			return err
		}
		return nil
	}

	cloned := append([]byte(nil), frame...)
	state.mu.Lock()
	state.dispatchedFrames = append(state.dispatchedFrames, cloned)
	state.mu.Unlock()
	return nil
}

func (state *packetExecutionState) track(packet *MutablePacket) {
	if state == nil || packet == nil {
		return
	}

	state.mu.Lock()
	state.trackedPackets = append(state.trackedPackets, packet)
	state.mu.Unlock()
}

func (state *packetExecutionState) result(packet *MutablePacket) PacketExecutionResult {
	if state == nil {
		return PacketExecutionResult{DropOriginal: packet != nil && packet.Dropped()}
	}

	state.mu.Lock()
	frames := append([][]byte(nil), state.dispatchedFrames...)
	state.mu.Unlock()
	return PacketExecutionResult{
		DropOriginal:     packet != nil && packet.Dropped(),
		DispatchedFrames: frames,
	}
}

func (state *packetExecutionState) cleanup(exclude *MutablePacket) {
	if state == nil {
		return
	}

	state.mu.Lock()
	packets := append([]*MutablePacket(nil), state.trackedPackets...)
	state.trackedPackets = nil
	state.mu.Unlock()

	for _, packet := range packets {
		if packet != nil && packet != exclude {
			packet.Release()
		}
	}
}

func buildFragmentorModule(state *packetExecutionState) starlark.Value {
	return newScriptObject("fragmentor", false, starlark.StringDict{
		"fragment": starlark.NewBuiltin("fragmentor.fragment", func(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if state == nil {
				return nil, fmt.Errorf("fragmentor is only available during packet script execution")
			}

			var packetValue starlark.Value
			var maxPayloadSize int
			if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 2, &packetValue, &maxPayloadSize); err != nil {
				return nil, err
			}

			packet, ok := packetValue.(*MutablePacket)
			if !ok || packet == nil {
				return nil, fmt.Errorf("fragmentor.fragment: packet must be a packet")
			}

			fragments, err := packet.FragmentIPv4ByPayload(maxPayloadSize)
			if err != nil {
				return nil, err
			}

			items := make([]starlark.Value, 0, len(fragments))
			for _, fragment := range fragments {
				state.track(fragment)
				items = append(items, fragment)
			}
			return starlark.NewList(items), nil
		}),
		"dispatch": starlark.NewBuiltin("fragmentor.dispatch", func(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if state == nil {
				return nil, fmt.Errorf("fragmentor is only available during packet script execution")
			}

			var packetValue starlark.Value
			if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &packetValue); err != nil {
				return nil, err
			}

			packet, ok := packetValue.(*MutablePacket)
			if !ok || packet == nil {
				return nil, fmt.Errorf("fragmentor.dispatch: packet must be a packet")
			}
			if err := packet.finalize(); err != nil {
				return nil, err
			}

			if err := state.dispatchFrame(packet.Bytes()); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}),
	})
}
