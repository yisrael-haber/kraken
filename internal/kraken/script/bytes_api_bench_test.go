package script

import (
	"go.starlark.net/starlark"
	"testing"
)

func BenchmarkBytesModuleConcat(b *testing.B) {
	moduleValue, err := buildBytesModule()
	if err != nil {
		b.Fatalf("build bytes module: %v", err)
	}

	concat, err := attrValue(moduleValue, "concat")
	if err != nil {
		b.Fatalf("lookup bytes.concat: %v", err)
	}
	thread := &starlark.Thread{Name: "benchmark"}

	left := newOwnedByteBuffer([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	right := newOwnedByteBuffer([]byte{8, 9, 10, 11, 12, 13, 14, 15})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := starlark.Call(thread, concat.(starlark.Callable), starlark.Tuple{left, right}, nil); err != nil {
			b.Fatalf("concat: %v", err)
		}
	}
}

func BenchmarkBytesModuleToHex(b *testing.B) {
	moduleValue, err := buildBytesModule()
	if err != nil {
		b.Fatalf("build bytes module: %v", err)
	}

	toHex, err := attrValue(moduleValue, "toHex")
	if err != nil {
		b.Fatalf("lookup bytes.toHex: %v", err)
	}
	thread := &starlark.Thread{Name: "benchmark"}

	payload := make([]byte, 32)
	for index := range payload {
		payload[index] = byte(index)
	}

	payloadValue := newOwnedByteBuffer(payload)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := starlark.Call(thread, toHex.(starlark.Callable), starlark.Tuple{payloadValue}, nil); err != nil {
			b.Fatalf("toHex: %v", err)
		}
	}
}
