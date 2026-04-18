package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStoredAdoptionConfigurationStore(t *testing.T) *Store {
	t.Helper()

	return NewStoreAtDir(t.TempDir())
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

	if _, err := os.Stat(filepath.Join(store.dir, "Lab SMB Node.json")); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
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

	_, err := store.Save(StoredAdoptionConfiguration{
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

	_, err := store.Save(StoredAdoptionConfiguration{
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

	_, err := store.Save(StoredAdoptionConfiguration{
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

	_, err := store.Save(StoredAdoptionConfiguration{
		Label:          "Stale Config",
		InterfaceName:  "eth0",
		IP:             "192.168.56.61",
		DefaultGateway: "192.168.56.1",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	path := filepath.Join(store.dir, "Stale Config.json")
	if err := store.Delete("Stale Config"); err != nil {
		t.Fatalf("delete stored config: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected config file to be removed, got err=%v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored configs after delete: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 stored configs after delete, got %d", len(items))
	}
}

func TestStoredAdoptionConfigurationStoreLoadSurfacesDecodeErrors(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	path := filepath.Join(store.dir, "Broken Config.json")
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

func TestStoredAdoptionConfigurationStoreListReflectsSaveAfterCaching(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	if _, err := store.Save(StoredAdoptionConfiguration{
		Label:         "alpha",
		InterfaceName: "eth0",
		IP:            "192.168.56.10",
	}); err != nil {
		t.Fatalf("save alpha config: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list configs: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 cached config, got %d", len(items))
	}

	if _, err := store.Save(StoredAdoptionConfiguration{
		Label:         "beta",
		InterfaceName: "eth0",
		IP:            "192.168.56.11",
	}); err != nil {
		t.Fatalf("save beta config: %v", err)
	}

	items, err = store.List()
	if err != nil {
		t.Fatalf("list configs after second save: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 configs after cache invalidation, got %d", len(items))
	}
}
