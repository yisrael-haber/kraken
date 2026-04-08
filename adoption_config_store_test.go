package main

import (
	"os"
	"path/filepath"
	"testing"
)

func testStoredAdoptionConfigurationStore(t *testing.T) *storedAdoptionConfigurationStore {
	t.Helper()

	return newStoredAdoptionConfigurationStoreAtDir(t.TempDir())
}

func TestStoredAdoptionConfigurationStoreSaveAndList(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	saved, err := store.save(StoredAdoptionConfiguration{
		Label:          "Lab SMB Node",
		InterfaceName:  "eth0",
		IP:             "192.168.56.50",
		MAC:            "02:00:00:00:00:50",
		DefaultGateway: "192.168.56.1",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	if _, err := os.Stat(filepath.Join(store.dir, "Lab SMB Node.json")); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	items, err := store.list()
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

	_, err := store.save(StoredAdoptionConfiguration{
		Label:          "HTTP Listener",
		InterfaceName:  "eth1",
		IP:             "10.10.10.20",
		MAC:            "",
		DefaultGateway: "10.10.10.1",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	loaded, err := store.load("HTTP Listener")
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

func TestStoredAdoptionConfigurationStoreRejectsInvalidLabel(t *testing.T) {
	store := testStoredAdoptionConfigurationStore(t)

	_, err := store.save(StoredAdoptionConfiguration{
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

	_, err := store.save(StoredAdoptionConfiguration{
		Label:          "Stale Config",
		InterfaceName:  "eth0",
		IP:             "192.168.56.61",
		DefaultGateway: "192.168.56.1",
	})
	if err != nil {
		t.Fatalf("save stored config: %v", err)
	}

	path := filepath.Join(store.dir, "Stale Config.json")
	if err := store.delete("Stale Config"); err != nil {
		t.Fatalf("delete stored config: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected config file to be removed, got err=%v", err)
	}

	items, err := store.list()
	if err != nil {
		t.Fatalf("list stored configs after delete: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 stored configs after delete, got %d", len(items))
	}
}
