package script

import (
	"fmt"
	"unicode"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

func buildBytesModule() (starlark.Value, error) {
	return &starlarkstruct.Module{
		Name: "kraken/bytes",
		Members: starlark.StringDict{
			"fromASCII": starlark.NewBuiltin("bytes.fromASCII", bytesFromASCII),
			"fromUTF8":  starlark.NewBuiltin("bytes.fromUTF8", bytesFromUTF8),
			"fromHex":   starlark.NewBuiltin("bytes.fromHex", bytesFromHex),
			"concat":    starlark.NewBuiltin("bytes.concat", bytesConcat),
			"toHex":     starlark.NewBuiltin("bytes.toHex", bytesToHex),
		},
	}, nil
}

func bytesFromASCII(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	payload := []byte(text)
	for _, value := range payload {
		if value > unicode.MaxASCII {
			return nil, fmt.Errorf("kraken/bytes.fromASCII only supports ASCII text")
		}
	}

	return newOwnedByteBuffer(payload), nil
}

func bytesFromUTF8(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}
	return newOwnedByteBuffer([]byte(text)), nil
}

func bytesFromHex(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}

	payload, err := packetpkg.ParsePayloadHex(text)
	if err != nil {
		return nil, fmt.Errorf("kraken/bytes.fromHex: %v", err)
	}
	return newOwnedByteBuffer(payload), nil
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

	return newOwnedByteBuffer(payload), nil
}

func bytesToHex(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &value); err != nil {
		return nil, err
	}

	payload, err := byteSliceFromValue(value)
	if err != nil {
		return nil, fmt.Errorf("kraken/bytes.toHex: %w", err)
	}
	return starlark.String(formatLowerPayloadHex(payload)), nil
}

func formatLowerPayloadHex(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	const digits = "0123456789abcdef"

	formatted := make([]byte, len(payload)*3-1)
	for index, value := range payload {
		offset := index * 3
		if index > 0 {
			formatted[offset-1] = ' '
		}
		formatted[offset] = digits[value>>4]
		formatted[offset+1] = digits[value&0x0f]
	}

	return string(formatted)
}
