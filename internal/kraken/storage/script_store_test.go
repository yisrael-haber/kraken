package storage

import (
	"errors"
	"testing"
)

func TestScriptStoreSaveListAndLookup(t *testing.T) {
	store := NewScriptStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "TTL Clamp",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 32
`,
	})
	if err != nil {
		t.Fatalf("save stored script: %v", err)
	}
	if !saved.Available || saved.Compiled == nil {
		t.Fatalf("expected compiled script, available=%v error=%q", saved.Available, saved.CompileError)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored scripts: %v", err)
	}
	if len(items) != 1 || items[0].Name != saved.Name {
		t.Fatalf("unexpected stored scripts: %+v", items)
	}

	loaded, err := store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceTransport})
	if err != nil {
		t.Fatalf("lookup stored script: %v", err)
	}
	if loaded.Compiled == nil {
		t.Fatal("expected lookup to return compiled script")
	}
}

func TestScriptStoreLookupRejectsInvalidScript(t *testing.T) {
	store := NewScriptStoreAtDir(t.TempDir())

	saved, err := store.Save(SaveStoredScriptRequest{
		Name: "Broken",
		Source: `def not_main(packet, ctx):
    pass
`,
	})
	if err != nil {
		t.Fatalf("save stored script: %v", err)
	}
	if saved.Available {
		t.Fatal("expected invalid script to be saved as unavailable")
	}

	_, err = store.Lookup(StoredScriptRef{Name: saved.Name, Surface: SurfaceTransport})
	if !errors.Is(err, ErrStoredScriptInvalid) {
		t.Fatalf("expected invalid script error, got %v", err)
	}
}
