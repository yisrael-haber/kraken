package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStoredAdoptionConfigurationStore(t *testing.T) *ConfigStore {
	t.Helper()
	configDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configDir)
	t.Setenv("HOME", configDir)
	t.Setenv("APPDATA", configDir)
	return NewConfigStore()
}

func TestStoredAdoptionConfigurationStoreReplaceAndList(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	saved, err := store.Replace("", StoredAdoptionConfiguration{
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

func TestStoredAdoptionConfigurationStoreLoadByLabel(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	_, err := store.Replace("", StoredAdoptionConfiguration{
		Label:          "HTTP Listener",
		InterfaceName:  "eth1",
		IP:             "10.10.10.20",
		MAC:            "",
		DefaultGateway: "10.10.10.1",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	loaded, err := store.Load("HTTP Listener")
	if err != nil {
		t.Fatalf("load stored config: %v", err)
	}

	if loaded.Label != "HTTP Listener" {
		t.Fatalf("expected loaded label HTTP Listener, got %s", loaded.Label)
	}
	if loaded.InterfaceName != "eth1" {
		t.Fatalf("expected loaded interface eth1, got %s", loaded.InterfaceName)
	}
	if loaded.IP != "10.10.10.20" {
		t.Fatalf("expected loaded IP 10.10.10.20, got %s", loaded.IP)
	}
	if loaded.DefaultGateway != "10.10.10.1" {
		t.Fatalf("expected loaded default gateway 10.10.10.1, got %s", loaded.DefaultGateway)
	}
}

func TestStoredAdoptionConfigurationStoreRejectsInvalidMTU(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	_, err := store.Replace("", StoredAdoptionConfiguration{
		Label:         "bad-mtu",
		InterfaceName: "eth0",
		IP:            "192.168.56.60",
		MTU:           67,
	})
	if err == nil {
		t.Fatal("expected invalid MTU save to fail")
	}
}

func TestStoredAdoptionConfigurationStoreRejectsInvalidLabel(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	_, err := store.Replace("", StoredAdoptionConfiguration{
		Label:         "bad/label",
		InterfaceName: "eth0",
		IP:            "192.168.56.60",
	})
	if err == nil {
		t.Fatal("expected invalid label save to fail")
	}
}

func TestStoredAdoptionConfigurationStoreDelete(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	_, err := store.Replace("", StoredAdoptionConfiguration{
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

func TestStoredAdoptionConfigurationStoreRename(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)
	config, err := store.Replace("", StoredAdoptionConfiguration{
		Label:         "Old Name",
		InterfaceName: "eth0",
		IP:            "192.168.56.62",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	config.Label = "New Name"
	if _, err := store.Replace("Old Name", config); err != nil {
		t.Fatalf("rename stored config: %v", err)
	}
	if _, err := store.Load("New Name"); err != nil {
		t.Fatalf("load renamed config: %v", err)
	}
}

func TestStoredAdoptionConfigurationStoreLoadSurfacesDecodeErrors(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	if err := store.files.ensureDir(); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
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
	if !strings.Contains(err.Error(), `decode stored adoption configuration "Broken Config.json"`) {
		t.Fatalf("expected decode error to mention the broken file, got %v", err)
	}
}
