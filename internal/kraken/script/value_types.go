package script

import (
	"bytes"
	"fmt"

	"go.starlark.net/starlark"
)

type scriptObject struct {
	typeName string
	fields   starlark.StringDict
}

func newScriptObject(typeName string, fields starlark.StringDict) *scriptObject {
	return &scriptObject{typeName: typeName, fields: fields}
}

func (object *scriptObject) Attr(name string) (starlark.Value, error) {
	value, exists := object.fields[name]
	if !exists {
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", object.typeName, name))
	}
	return value, nil
}

func (object *scriptObject) AttrNames() []string {
	return object.fields.Keys()
}

func (object *scriptObject) String() string       { return fmt.Sprintf("<%s>", object.typeName) }
func (object *scriptObject) Type() string         { return object.typeName }
func (object *scriptObject) Freeze()              {}
func (object *scriptObject) Truth() starlark.Bool { return true }
func (object *scriptObject) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", object.Type())
}

type byteBuffer struct {
	data  []byte
	onSet func()
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

func (buffer *byteBuffer) Len() int {
	return len(buffer.data)
}

func (buffer *byteBuffer) Index(index int) starlark.Value {
	return starlark.MakeInt(int(buffer.data[index]))
}

func (buffer *byteBuffer) Slice(start, end, step int) starlark.Value {
	if step == 1 {
		return &byteBuffer{data: append([]byte(nil), buffer.data[start:end]...)}
	}

	sign := 1
	if step < 0 {
		sign = -1
	}

	sliced := make([]byte, 0, max(0, end-start))
	for index := start; sign*(end-index) > 0; index += step {
		sliced = append(sliced, buffer.data[index])
	}
	return &byteBuffer{data: sliced}
}

func (buffer *byteBuffer) Iterate() starlark.Iterator {
	return &byteBufferIterator{data: buffer.data}
}

func (buffer *byteBuffer) SetIndex(index int, value starlark.Value) error {
	converted, err := byteValueFromStarlark(value)
	if err != nil {
		return err
	}
	buffer.data[index] = converted
	if buffer.onSet != nil {
		buffer.onSet()
	}
	return nil
}

func (buffer *byteBuffer) Has(value starlark.Value) (bool, error) {
	switch needle := value.(type) {
	case *byteBuffer:
		return bytes.Contains(buffer.data, needle.data), nil
	case starlark.Bytes:
		return bytes.Contains(buffer.data, []byte(needle)), nil
	case starlark.Int:
		converted, err := byteValueFromStarlark(needle)
		if err != nil {
			return false, err
		}
		return bytes.IndexByte(buffer.data, converted) >= 0, nil
	default:
		return false, fmt.Errorf("'in %s' requires bytes or int as left operand, not %s", buffer.Type(), value.Type())
	}
}

type byteBufferIterator struct {
	data  []byte
	index int
}

func (iterator *byteBufferIterator) Next(value *starlark.Value) bool {
	if iterator.index >= len(iterator.data) {
		return false
	}
	*value = starlark.MakeInt(int(iterator.data[iterator.index]))
	iterator.index++
	return true
}

func (iterator *byteBufferIterator) Done() {}

func isNone(value starlark.Value) bool {
	return value == nil || value == starlark.None
}

func attrValue(value starlark.Value, name string) (starlark.Value, error) {
	if isNone(value) {
		return starlark.None, nil
	}

	attrs, ok := value.(starlark.HasAttrs)
	if !ok {
		return nil, fmt.Errorf("must be an object, not %s", value.Type())
	}

	attr, err := attrs.Attr(name)
	if err != nil {
		return nil, err
	}
	if attr == nil {
		return starlark.None, nil
	}
	return attr, nil
}

func integerValue(value starlark.Value) (int64, error) {
	number, ok := value.(starlark.Int)
	if !ok {
		return 0, fmt.Errorf("must be an integer")
	}
	var converted int64
	if err := starlark.AsInt(number, &converted); err != nil {
		return 0, err
	}
	return converted, nil
}

func byteValueFromStarlark(value starlark.Value) (byte, error) {
	number, err := integerValue(value)
	if err != nil {
		return 0, err
	}
	if number < 0 || number > 255 {
		return 0, fmt.Errorf("must be between 0 and 255")
	}
	return byte(number), nil
}

func byteSliceFromValue(value starlark.Value) ([]byte, error) {
	switch value := value.(type) {
	case nil:
		return nil, nil
	case starlark.NoneType:
		return nil, nil
	case *byteBuffer:
		return value.data, nil
	case starlark.Bytes:
		return []byte(value), nil
	}

	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("must be bytes or a sequence of byte values")
	}

	iterator := iterable.Iterate()
	defer iterator.Done()

	payload := make([]byte, 0, max(0, starlark.Len(value)))
	var item starlark.Value
	for iterator.Next(&item) {
		converted, err := byteValueFromStarlark(item)
		if err != nil {
			return nil, err
		}
		payload = append(payload, converted)
	}

	return payload, nil
}

func toStarlarkValue(value any) (starlark.Value, error) {
	switch value := value.(type) {
	case nil:
		return starlark.None, nil
	case starlark.Value:
		return value, nil
	case bool:
		return starlark.Bool(value), nil
	case string:
		return starlark.String(value), nil
	case []byte:
		return &byteBuffer{data: append([]byte(nil), value...)}, nil
	case int:
		return starlark.MakeInt(value), nil
	case int8:
		return starlark.MakeInt64(int64(value)), nil
	case int16:
		return starlark.MakeInt64(int64(value)), nil
	case int32:
		return starlark.MakeInt64(int64(value)), nil
	case int64:
		return starlark.MakeInt64(value), nil
	case uint:
		return starlark.MakeUint(value), nil
	case uint8:
		return starlark.MakeUint64(uint64(value)), nil
	case uint16:
		return starlark.MakeUint64(uint64(value)), nil
	case uint32:
		return starlark.MakeUint64(uint64(value)), nil
	case uint64:
		return starlark.MakeUint64(value), nil
	case float32:
		return starlark.Float(value), nil
	case float64:
		return starlark.Float(value), nil
	case map[string]any:
		dict := starlark.NewDict(len(value))
		for key, item := range value {
			converted, err := toStarlarkValue(item)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			if err := dict.SetKey(starlark.String(key), converted); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case []any:
		items := make([]starlark.Value, 0, len(value))
		for index, item := range value {
			converted, err := toStarlarkValue(item)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", index, err)
			}
			items = append(items, converted)
		}
		return starlark.NewList(items), nil
	}

	return nil, fmt.Errorf("unsupported metadata type %T", value)
}
