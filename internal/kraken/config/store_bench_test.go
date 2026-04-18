package config

import (
	"fmt"
	"testing"
)

func BenchmarkStoreList(b *testing.B) {
	store := NewStoreAtDir(b.TempDir())
	for i := 0; i < 128; i++ {
		_, err := store.Save(StoredAdoptionConfiguration{
			Label:         fmt.Sprintf("host-%03d", i),
			InterfaceName: "eth0",
			IP:            fmt.Sprintf("192.168.56.%d", i+1),
		})
		if err != nil {
			b.Fatalf("save config: %v", err)
		}
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		items, err := store.List()
		if err != nil {
			b.Fatalf("list configs: %v", err)
		}
		if len(items) != 128 {
			b.Fatalf("expected 128 configs, got %d", len(items))
		}
	}
}

func BenchmarkStoreLoad(b *testing.B) {
	store := NewStoreAtDir(b.TempDir())
	if _, err := store.Save(StoredAdoptionConfiguration{
		Label:         "bench",
		InterfaceName: "eth0",
		IP:            "192.168.56.10",
	}); err != nil {
		b.Fatalf("save config: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		item, err := store.Load("bench")
		if err != nil {
			b.Fatalf("load config: %v", err)
		}
		if item.IP != "192.168.56.10" {
			b.Fatalf("unexpected config %+v", item)
		}
	}
}
