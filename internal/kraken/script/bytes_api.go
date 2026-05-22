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
			"fromUTF8": starlark.NewBuiltin("bytes.fromUTF8", bytesFromUTF8),
			"concat":   starlark.NewBuiltin("bytes.concat", bytesConcat),
		},
	}
}

func bytesFromUTF8(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}
	return &byteBuffer{data: []byte(text)}, nil
}

func bytesConcat(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	parts := make([][]byte, len(args))
	totalLen := 0
	for index, argument := range args {
		part, err := byteSliceFromValue(argument)
		if err != nil {
			return nil, fmt.Errorf("kraken/bytes.concat argument %d: %w", index+1, err)
		}
		parts[index] = part
		totalLen += len(part)
	}

	payload := make([]byte, 0, totalLen)
	for _, part := range parts {
		payload = append(payload, part...)
	}

	return &byteBuffer{data: payload}, nil
}
