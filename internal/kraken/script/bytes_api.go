package script

import (
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func buildBytesModule() starlark.Value {
	return &starlarkstruct.Module{
		Name: "kraken/bytes",
		Members: starlark.StringDict{
			"from_utf8": starlark.NewBuiltin("bytes.from_utf8", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var text string
				if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &text); err != nil {
					return nil, err
				}
				return &byteBuffer{data: []byte(text)}, nil
			}),
			"concat": starlark.NewBuiltin("bytes.concat", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				payload := []byte{}
				for index, argument := range args {
					switch part := argument.(type) {
					case *byteBuffer:
						payload = append(payload, part.data...)
					case starlark.Bytes:
						payload = append(payload, []byte(part)...)
					default:
						return nil, fmt.Errorf("kraken/bytes.concat argument %d: must be bytes", index+1)
					}
				}
				return &byteBuffer{data: payload}, nil
			}),
		},
	}
}
