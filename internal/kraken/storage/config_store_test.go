package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testStoredAdoptionConfigurationStore(t *testing.T) *ConfigStore {
	t.Helper()
	configDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configDir)
	t.Setenv("HOME", configDir)
	t.Setenv("APPDATA", configDir)
	store, err := NewConfigStore()
	if err != nil {
		t.Fatalf("create config store: %v", err)
	}
	return store
}

func TestStoredAdoptionConfigurationStoreSaveAndList(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	saved, err := store.Save(StoredAdoptionConfiguration{
		Label:          "Lab SMB Node",
		InterfaceName:  "eth0",
		IP:             "192.168.56.50",
		MAC:            "02:00:00:00:00:50",
		DefaultGateway: "192.168.56.1",
		MTU:            1400,
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored configs: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 stored config, got %d", len(items))
	}
	if items[0] != saved {
		t.Fatalf("expected listed config %+v, got %+v", saved, items[0])
	}
}

func TestStoredAdoptionConfigurationStoreRejectsInvalidConfiguration(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	tests := []StoredAdoptionConfiguration{
		{
			Label:         "bad-mtu",
			InterfaceName: "eth0",
			IP:            "192.168.56.60",
			MTU:           67,
		},
		{
			Label:         "bad/label",
			InterfaceName: "eth0",
			IP:            "192.168.56.60",
		},
	}

	for _, config := range tests {
		if _, err := store.Save(config); err == nil {
			t.Fatalf("expected invalid configuration %+v to fail", config)
		}
	}
}

func TestStoredAdoptionConfigurationStoreDelete(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	_, err := store.Save(StoredAdoptionConfiguration{
		Label:          "Stale Config",
		InterfaceName:  "eth0",
		IP:             "192.168.56.61",
		DefaultGateway: "192.168.56.1",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	if err := store.Delete("Stale Config"); err != nil {
		t.Fatalf("delete stored config: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored configs after delete: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 stored configs after delete, got %d", len(items))
	}
}

func TestStoredAdoptionConfigurationStoreCopy(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)
	config, err := store.Save(StoredAdoptionConfiguration{
		Label:         "Original",
		InterfaceName: "eth0",
		IP:            "192.168.56.62",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	copied, err := store.Copy(config.Label, "Copy")
	if err != nil {
		t.Fatalf("copy stored config: %v", err)
	}
	if copied.Label != "Copy" {
		t.Fatalf("expected copied label Copy, got %s", copied.Label)
	}
	if original, err := store.Load("Original"); err != nil || original != config {
		t.Fatalf("source changed after copy: config=%+v err=%v", original, err)
	}
	if loaded, err := store.Load("Copy"); err != nil || loaded != copied {
		t.Fatalf("load copied config: config=%+v err=%v", loaded, err)
	}
}

func TestStoredAdoptionConfigurationStoreLoadSurfacesDecodeErrors(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	path := filepath.Join(store.files.dir, "Broken Config.json")
	if err := os.WriteFile(path, []byte("{not json}\n"), 0o644); err != nil {
		t.Fatalf("write broken config fixture: %v", err)
	}

	_, err := store.Load("Broken Config")
	if err == nil {
		t.Fatal("expected load with broken config file to fail")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected decode failure, got not found: %v", err)
	}
}
