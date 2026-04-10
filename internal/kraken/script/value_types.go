package script

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"

	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	"go.starlark.net/starlark"
)

type scriptObject struct {
	typeName string
	fields   starlark.StringDict
	names    []string
	mutable  bool
}

func newScriptObject(typeName string, mutable bool, fields starlark.StringDict) *scriptObject {
	cloned := make(starlark.StringDict, len(fields))
	for name, value := range fields {
		if value == nil {
			value = starlark.None
		}
		cloned[name] = value
	}

	names := cloned.Keys()
	sort.Strings(names)

	return &scriptObject{
		typeName: typeName,
		fields:   cloned,
		names:    names,
		mutable:  mutable,
	}
}

func (object *scriptObject) Attr(name string) (starlark.Value, error) {
	value, exists := object.fields[name]
	if !exists {
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", object.typeName, name))
	}
	return value, nil
}

func (object *scriptObject) AttrNames() []string {
	return append([]string(nil), object.names...)
}

func (object *scriptObject) SetField(name string, value starlark.Value) error {
	if !object.mutable {
		return fmt.Errorf("%s is read-only", object.typeName)
	}
	if _, exists := object.fields[name]; !exists {
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", object.typeName, name))
	}
	if value == nil {
		value = starlark.None
	}
	object.fields[name] = value
	return nil
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
	owned bool
}

func newByteBuffer(data []byte) *byteBuffer {
	return newBorrowedByteBuffer(data)
}

func newBorrowedByteBuffer(data []byte) *byteBuffer {
	if data == nil {
		data = []byte{}
	}
	return &byteBuffer{data: data}
}

func newOwnedByteBuffer(data []byte) *byteBuffer {
	if data == nil {
		data = []byte{}
	}
	return &byteBuffer{data: data, owned: true}
}

func (buffer *byteBuffer) Bytes() []byte {
	return buffer.data
}

func (buffer *byteBuffer) ensureOwned() {
	if buffer.owned {
		return
	}
	buffer.data = append([]byte(nil), buffer.data...)
	buffer.owned = true
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
		return newOwnedByteBuffer(append([]byte(nil), buffer.data[start:end]...))
	}

	sign := 1
	if step < 0 {
		sign = -1
	}

	sliced := make([]byte, 0, max(0, end-start))
	for index := start; sign*(end-index) > 0; index += step {
		sliced = append(sliced, buffer.data[index])
	}
	return newOwnedByteBuffer(sliced)
}

func (buffer *byteBuffer) Iterate() starlark.Iterator {
	return &byteBufferIterator{data: buffer.data}
}

func (buffer *byteBuffer) SetIndex(index int, value starlark.Value) error {
	converted, err := byteValueFromStarlark(value)
	if err != nil {
		return err
	}
	buffer.ensureOwned()
	buffer.data[index] = converted
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

func stringValue(value starlark.Value) string {
	if isNone(value) {
		return ""
	}
	if text, ok := starlark.AsString(value); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(value.String())
}

func integerValue(value starlark.Value) (int64, error) {
	switch value := value.(type) {
	case starlark.Int:
		var converted int64
		if err := starlark.AsInt(value, &converted); err != nil {
			return 0, err
		}
		return converted, nil
	case starlark.Float:
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return 0, fmt.Errorf("must be a finite number")
		}
		return int64(value), nil
	default:
		return 0, fmt.Errorf("must be a number")
	}
}

func byteValueFromStarlark(value starlark.Value) (byte, error) {
	number, err := integerValue(value)
	if err != nil {
		return 0, err
	}
	if number < 0 || number > math.MaxUint8 {
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
	case starlark.String:
		return []byte(value), nil
	}

	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("must be bytes, bytearray, or a sequence of byte values")
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
		return newOwnedByteBuffer(append([]byte(nil), value...)), nil
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

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		if reflected.Type().Elem().Kind() == reflect.Uint8 {
			payload := make([]byte, reflected.Len())
			reflect.Copy(reflect.ValueOf(payload), reflected)
			return newOwnedByteBuffer(payload), nil
		}

		items := make([]starlark.Value, 0, reflected.Len())
		for index := 0; index < reflected.Len(); index++ {
			converted, err := toStarlarkValue(reflected.Index(index).Interface())
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", index, err)
			}
			items = append(items, converted)
		}
		return starlark.NewList(items), nil
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("unsupported map key type %s", reflected.Type().Key())
		}

		dict := starlark.NewDict(reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			converted, err := toStarlarkValue(iterator.Value().Interface())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", iterator.Key().String(), err)
			}
			if err := dict.SetKey(starlark.String(iterator.Key().String()), converted); err != nil {
				return nil, err
			}
		}
		return dict, nil
	}

	return nil, fmt.Errorf("unsupported metadata type %T", value)
}

func formatByteBuffer(value []byte) string {
	if len(value) == 0 {
		return "b\"\""
	}
	return starlark.Bytes(string(value)).String()
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func formatPayloadForError(value starlark.Value) string {
	switch value := value.(type) {
	case *byteBuffer:
		return packetpkg.FormatPayloadHex(value.data)
	case starlark.Bytes:
		return packetpkg.FormatPayloadHex([]byte(value))
	default:
		return value.String()
	}
}
