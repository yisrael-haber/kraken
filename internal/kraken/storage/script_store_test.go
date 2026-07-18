package storage

import "testing"

func testScriptStore(t *testing.T) *ScriptStore {
	t.Helper()
	configDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configDir)
	t.Setenv("HOME", configDir)
	t.Setenv("APPDATA", configDir)
	store, err := NewScriptStore("Transport")
	if err != nil {
		t.Fatalf("create script store: %v", err)
	}
	return store
}

func TestScriptStoreSaveListAndGet(t *testing.T) {
	store := testScriptStore(t)

	saved, err := store.Save(StoredScript{
		Name: "TTL Clamp",
		Source: `def main(packet, ctx):
    packet.ipv4.ttl = 32
`,
	})
	if err != nil {
		t.Fatalf("save stored script: %v", err)
	}
	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored scripts: %v", err)
	}
	if len(items) != 1 || items[0].Name != saved.Name {
		t.Fatalf("unexpected stored scripts: %+v", items)
	}

	loaded, err := store.Get(saved.Name)
	if err != nil {
		t.Fatalf("get stored script: %v", err)
	}
	if loaded.Name != saved.Name || loaded.Source != saved.Source {
		t.Fatalf("unexpected stored script: %+v", loaded)
	}
}
