package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

type PacketExecutionResult struct {
	DropOriginal     bool
	DispatchedFrames [][]byte
}

type packetExecutionState struct {
	dispatchedFrames [][]byte
	dispatch         func([]byte) error
}

func (state *packetExecutionState) dispatchFrame(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}

	if state.dispatch != nil {
		if err := state.dispatch(append([]byte(nil), frame...)); err != nil {
			return err
		}
		return nil
	}

	state.dispatchedFrames = append(state.dispatchedFrames, append([]byte(nil), frame...))
	return nil
}

func (state *packetExecutionState) result(packet *MutablePacket) PacketExecutionResult {
	frames := append([][]byte(nil), state.dispatchedFrames...)
	return PacketExecutionResult{
		DropOriginal:     packet.dropped,
		DispatchedFrames: frames,
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
