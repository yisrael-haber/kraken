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
			"from_utf8": starlark.NewBuiltin("bytes.from_utf8", bytesFromUTF8),
			"concat":    starlark.NewBuiltin("bytes.concat", bytesConcat),
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
	length := 0
	for index, argument := range args {
		switch part := argument.(type) {
		case *byteBuffer:
			length += len(part.data)
		case starlark.Bytes:
			length += len(part)
		default:
			return nil, fmt.Errorf("kraken/bytes.concat argument %d: must be bytes", index+1)
		}
	}

	payload := make([]byte, length)
	offset := 0
	for _, argument := range args {
		switch part := argument.(type) {
		case *byteBuffer:
			offset += copy(payload[offset:], part.data)
		case starlark.Bytes:
			offset += copy(payload[offset:], string(part))
		}
	}
	return &byteBuffer{data: payload}, nil
}
