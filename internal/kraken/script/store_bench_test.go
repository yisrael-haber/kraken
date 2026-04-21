package script

import (
	"fmt"
	"testing"
)

func BenchmarkStoreLookup(b *testing.B) {
	store := NewStoreAtDir(b.TempDir())
	saved, err := store.Save(SaveStoredScriptRequest{
		Name:    "bench",
		Surface: SurfaceTransport,
		Source: `def main(packet, ctx):
    pass
`,
	})
	if err != nil {
		b.Fatalf("save script: %v", err)
	}

	ref := StoredScriptRef{Name: saved.Name, Surface: SurfaceTransport}
	if _, err := store.Lookup(ref); err != nil {
		b.Fatalf("prime lookup: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		script, err := store.Lookup(ref)
		if err != nil {
			b.Fatalf("lookup script: %v", err)
		}
		if script.Name != saved.Name {
			b.Fatalf("unexpected script %+v", script)
		}
	}
}

func BenchmarkStoreList(b *testing.B) {
	store := NewStoreAtDir(b.TempDir())
	for i := 0; i < 128; i++ {
		_, err := store.Save(SaveStoredScriptRequest{
			Name:    fmt.Sprintf("script-%03d", i),
			Surface: SurfaceTransport,
			Source: `def main(packet, ctx):
    pass
`,
		})
		if err != nil {
			b.Fatalf("save script: %v", err)
		}
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		items, err := store.List()
		if err != nil {
			b.Fatalf("list scripts: %v", err)
		}
		if len(items) != 128 {
			b.Fatalf("expected 128 scripts, got %d", len(items))
		}
	}
}
