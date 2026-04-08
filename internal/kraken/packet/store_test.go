package packet

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStoredPacketOverrideStore(t *testing.T) *Store {
	t.Helper()

	return NewStoreAtDir(t.TempDir())
}

func TestStoredPacketOverrideStoreSaveAndList(t *testing.T) {
	store := testStoredPacketOverrideStore(t)

	saved, err := store.Save(StoredPacketOverride{
		Name: "ICMP Lab Override",
		Layers: PacketOverrideLayers{
			IPv4: &PacketOverrideIPv4{
				TTL: intPointer(8),
			},
			ICMPv4: &PacketOverrideICMPv4{
				TypeCode: "EchoRequest",
			},
		},
	})
	if err != nil {
		t.Fatalf("save stored override: %v", err)
	}

	if _, err := os.Stat(filepath.Join(store.dir, "ICMP Lab Override.json")); err != nil {
		t.Fatalf("expected override file to exist: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored overrides: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 stored override, got %d", len(items))
	}
	if items[0].Name != saved.Name {
		t.Fatalf("expected listed override name %q, got %q", saved.Name, items[0].Name)
	}
	if items[0].Layers.IPv4 == nil || items[0].Layers.IPv4.TTL == nil || *items[0].Layers.IPv4.TTL != 8 {
		t.Fatalf("expected listed IPv4 TTL override to be preserved, got %+v", items[0].Layers.IPv4)
	}
}

func TestStoredPacketOverrideStoreLookupByName(t *testing.T) {
	store := testStoredPacketOverrideStore(t)

	_, err := store.Save(StoredPacketOverride{
		Name: "ARP Lab Override",
		Layers: PacketOverrideLayers{
			ARP: &PacketOverrideARP{
				Operation: intPointer(2),
			},
		},
	})
	if err != nil {
		t.Fatalf("save stored override: %v", err)
	}

	loaded, err := store.Lookup("ARP Lab Override")
	if err != nil {
		t.Fatalf("expected stored override lookup to succeed: %v", err)
	}

	if loaded.Name != "ARP Lab Override" {
		t.Fatalf("expected loaded name ARP Lab Override, got %q", loaded.Name)
	}
	if loaded.Layers.ARP == nil || loaded.Layers.ARP.Operation == nil || *loaded.Layers.ARP.Operation != 2 {
		t.Fatalf("expected loaded ARP operation override to equal 2, got %+v", loaded.Layers.ARP)
	}
}

func TestStoredPacketOverrideStoreDelete(t *testing.T) {
	store := testStoredPacketOverrideStore(t)

	_, err := store.Save(StoredPacketOverride{
		Name: "Stale Packet Override",
		Layers: PacketOverrideLayers{
			Ethernet: &PacketOverrideEthernet{
				DstMAC: "ff:ff:ff:ff:ff:ff",
			},
		},
	})
	if err != nil {
		t.Fatalf("save stored override: %v", err)
	}

	path := filepath.Join(store.dir, "Stale Packet Override.json")
	if err := store.Delete("Stale Packet Override"); err != nil {
		t.Fatalf("delete stored override: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected override file to be removed, got err=%v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored overrides after delete: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 stored overrides after delete, got %d", len(items))
	}
}

func TestStoredPacketOverrideStoreLookupSurfacesDecodeErrors(t *testing.T) {
	store := testStoredPacketOverrideStore(t)

	path := filepath.Join(store.dir, "Broken Override.json")
	if err := os.WriteFile(path, []byte("{not json}\n"), 0o644); err != nil {
		t.Fatalf("write broken override fixture: %v", err)
	}

	_, err := store.Lookup("Broken Override")
	if err == nil {
		t.Fatal("expected lookup with broken override file to fail")
	}
	if errors.Is(err, ErrStoredPacketOverrideNotFound) {
		t.Fatalf("expected decode failure, got not found: %v", err)
	}
	if !strings.Contains(err.Error(), `decode stored packet override "Broken Override.json"`) {
		t.Fatalf("expected decode error to mention the broken file, got %v", err)
	}
}

func intPointer(value int) *int {
	return &value
}
