package routing

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStoredRouteStore(t *testing.T) *Store {
	t.Helper()
	return NewStoreAtDir(t.TempDir())
}

func TestStoredRouteStoreSaveAndList(t *testing.T) {
	store := testStoredRouteStore(t)

	saved, err := store.Save(StoredRoute{
		Label:               "Lab Segment",
		DestinationCIDR:     "192.168.56.0/24",
		ViaAdoptedIP:        "10.0.0.10",
		TransportScriptName: "forward-http",
	})
	if err != nil {
		t.Fatalf("save stored route: %v", err)
	}

	if _, err := os.Stat(filepath.Join(store.dir, "Lab Segment.json")); err != nil {
		t.Fatalf("expected route file to exist: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list stored routes: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 stored route, got %d", len(items))
	}
	if items[0] != saved {
		t.Fatalf("expected listed route %+v, got %+v", saved, items[0])
	}
}

func TestStoredRouteStoreMatchesMostSpecificCIDR(t *testing.T) {
	store := testStoredRouteStore(t)

	for _, route := range []StoredRoute{
		{Label: "broad", DestinationCIDR: "10.0.0.0/8", ViaAdoptedIP: "192.168.56.10"},
		{Label: "specific", DestinationCIDR: "10.1.2.0/24", ViaAdoptedIP: "192.168.56.11"},
		{Label: "narrowest", DestinationCIDR: "10.1.2.128/25", ViaAdoptedIP: "192.168.56.12"},
	} {
		if _, err := store.Save(route); err != nil {
			t.Fatalf("save route %q: %v", route.Label, err)
		}
	}

	matched, ok := store.MatchDestination(net.ParseIP("10.1.2.200").To4())
	if !ok {
		t.Fatal("expected destination to match a stored route")
	}
	if matched.Label != "narrowest" {
		t.Fatalf("expected most specific route, got %q", matched.Label)
	}
}

func TestStoredRouteStoreDelete(t *testing.T) {
	store := testStoredRouteStore(t)

	if _, err := store.Save(StoredRoute{
		Label:           "Stale Route",
		DestinationCIDR: "172.16.0.0/16",
		ViaAdoptedIP:    "192.168.56.50",
	}); err != nil {
		t.Fatalf("save stored route: %v", err)
	}

	path := filepath.Join(store.dir, "Stale Route.json")
	if err := store.Delete("Stale Route"); err != nil {
		t.Fatalf("delete stored route: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected route file to be removed, got err=%v", err)
	}
}

func TestStoredRouteStoreLoadSurfacesDecodeErrors(t *testing.T) {
	store := testStoredRouteStore(t)

	path := filepath.Join(store.dir, "Broken Route.json")
	if err := os.WriteFile(path, []byte("{not json}\n"), 0o644); err != nil {
		t.Fatalf("write broken route fixture: %v", err)
	}

	_, err := store.Load("Broken Route")
	if err == nil {
		t.Fatal("expected load with broken route file to fail")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected decode failure, got not found: %v", err)
	}
	if !strings.Contains(err.Error(), `decode stored routing rule "Broken Route.json"`) {
		t.Fatalf("expected decode error to mention the broken file, got %v", err)
	}
}

func TestStoredRouteStoreRejectsDuplicateLabelsOnDisk(t *testing.T) {
	store := testStoredRouteStore(t)

	for name, payload := range map[string]string{
		"Alpha.json": `{"label":"Alpha","destinationCIDR":"10.0.0.0/24","viaAdoptedIP":"192.168.56.10"}` + "\n",
		"Bravo.json": `{"label":"Alpha","destinationCIDR":"10.1.0.0/24","viaAdoptedIP":"192.168.56.11"}` + "\n",
	} {
		if err := os.WriteFile(filepath.Join(store.dir, name), []byte(payload), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	_, err := store.List()
	if err == nil {
		t.Fatal("expected duplicate on-disk labels to fail")
	}
	if !strings.Contains(err.Error(), `duplicate stored routing rule "Alpha"`) {
		t.Fatalf("expected duplicate-label error, got %v", err)
	}
}

func TestStoredRouteStoreRejectsInvalidCIDR(t *testing.T) {
	store := testStoredRouteStore(t)

	_, err := store.Save(StoredRoute{
		Label:           "bad",
		DestinationCIDR: "10.0.0.1",
		ViaAdoptedIP:    "192.168.56.10",
	})
	if err == nil {
		t.Fatal("expected invalid CIDR save to fail")
	}
}

func BenchmarkStoredRouteStoreMatchDestination(b *testing.B) {
	store := NewStoreAtDir(b.TempDir())
	for _, route := range []StoredRoute{
		{Label: "broad", DestinationCIDR: "10.0.0.0/8", ViaAdoptedIP: "192.168.56.10"},
		{Label: "specific", DestinationCIDR: "10.1.0.0/16", ViaAdoptedIP: "192.168.56.11"},
		{Label: "narrowest", DestinationCIDR: "10.1.2.0/24", ViaAdoptedIP: "192.168.56.12"},
		{Label: "unrelated", DestinationCIDR: "172.16.0.0/16", ViaAdoptedIP: "192.168.56.13"},
		{Label: "edge-route", DestinationCIDR: "10.1.2.128/25", ViaAdoptedIP: "192.168.56.14"},
	} {
		if _, err := store.Save(route); err != nil {
			b.Fatalf("save route %q: %v", route.Label, err)
		}
	}
	destinationIP := net.IPv4(10, 1, 2, 200)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		route, ok := store.MatchDestination(destinationIP)
		if !ok || route.Label != "edge-route" {
			b.Fatalf("expected edge-route match, got %+v ok=%v", route, ok)
		}
	}
}
