package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

type scriptObject struct {
	typeName string
	fields   starlark.StringDict
}

func (object *scriptObject) Attr(name string) (starlark.Value, error) {
	value, exists := object.fields[name]
	if !exists {
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", object.typeName, name))
	}
	return value, nil
}

func (object *scriptObject) AttrNames() []string { return object.fields.Keys() }

func (object *scriptObject) String() string       { return fmt.Sprintf("<%s>", object.typeName) }
func (object *scriptObject) Type() string         { return object.typeName }
func (object *scriptObject) Freeze()              {}
func (object *scriptObject) Truth() starlark.Bool { return true }
func (object *scriptObject) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", object.Type())
}

type byteBuffer struct {
	data []byte
}

func (buffer *byteBuffer) String() string {
	return starlark.Bytes(string(buffer.data)).String()
}

func (buffer *byteBuffer) Type() string         { return "kraken.bytes" }
func (buffer *byteBuffer) Freeze()              {}
func (buffer *byteBuffer) Truth() starlark.Bool { return len(buffer.data) > 0 }
func (buffer *byteBuffer) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", buffer.Type())
}

func (buffer *byteBuffer) Len() int { return len(buffer.data) }

func (buffer *byteBuffer) Index(index int) starlark.Value {
	return starlark.MakeInt(int(buffer.data[index]))
}

func (buffer *byteBuffer) Slice(start, end, step int) starlark.Value {
	return &byteBuffer{data: append([]byte(nil), buffer.data[start:end]...)}
}

func isNone(value starlark.Value) bool {
	return value == nil || value == starlark.None
}

func byteSliceFromValue(value starlark.Value) ([]byte, error) {
	switch value := value.(type) {
	case nil, starlark.NoneType:
		return nil, nil
	case *byteBuffer:
		return value.data, nil
	case starlark.Bytes:
		return []byte(value), nil
	}
	return nil, fmt.Errorf("must be bytes")
}
