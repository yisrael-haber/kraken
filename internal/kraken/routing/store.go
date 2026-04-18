package routing

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
)

const storedRouteFolder = "routing"

type StoredRoute struct {
	Label           string `json:"label"`
	DestinationCIDR string `json:"destinationCIDR"`
	ViaAdoptedIP    string `json:"viaAdoptedIP"`
	ScriptName      string `json:"scriptName,omitempty"`
}

type Store struct {
	mu      sync.RWMutex
	dir     string
	initErr error
	loaded  bool
	cache   map[string]StoredRoute
	list    []StoredRoute
}

func NewStore() *Store {
	dir, err := storeutil.DefaultKrakenConfigDir(storedRouteFolder)
	return newStore(dir, err)
}

func NewStoreAtDir(dir string) *Store {
	return newStore(dir, nil)
}

func newStore(dir string, initErr error) *Store {
	return &Store{
		dir:     dir,
		initErr: initErr,
		cache:   make(map[string]StoredRoute),
	}
}

func (store *Store) List() ([]StoredRoute, error) {
	store.mu.RLock()
	if store.loaded && store.list != nil {
		items := append([]StoredRoute(nil), store.list...)
		store.mu.RUnlock()
		return items, nil
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	items, err := store.listLocked()
	if err != nil {
		return nil, err
	}

	return append([]StoredRoute(nil), items...), nil
}

func (store *Store) Load(label string) (StoredRoute, error) {
	key, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		return StoredRoute{}, err
	}

	store.mu.RLock()
	if store.loaded {
		item, exists := store.cache[key]
		store.mu.RUnlock()
		if !exists {
			return StoredRoute{}, fmt.Errorf("stored routing rule %q: %w", label, os.ErrNotExist)
		}
		return item, nil
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredRoute{}, err
	}

	item, exists := store.cache[key]
	if !exists {
		return StoredRoute{}, fmt.Errorf("stored routing rule %q: %w", label, os.ErrNotExist)
	}

	return item, nil
}

func (store *Store) Save(route StoredRoute) (StoredRoute, error) {
	route, err := normalizeStoredRoute(route)
	if err != nil {
		return StoredRoute{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredRoute{}, err
	}

	path, err := storeutil.PathForStoredItem(store.dir, route.Label)
	if err != nil {
		return StoredRoute{}, err
	}
	if err := storeutil.WriteStoredItem(path, "stored routing rule", route.Label, route); err != nil {
		return StoredRoute{}, err
	}

	store.cache[route.Label] = route
	store.list = nil
	return route, nil
}

func (store *Store) Delete(label string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	path, err := storeutil.PathForStoredItem(store.dir, label)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete stored routing rule %q: %w", label, err)
	}

	key, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		return err
	}

	delete(store.cache, key)
	store.list = nil
	return nil
}

func (store *Store) MatchDestination(destinationIP net.IP) (StoredRoute, bool) {
	destinationIP = common.NormalizeIPv4(destinationIP)
	if destinationIP == nil {
		return StoredRoute{}, false
	}

	store.mu.RLock()
	if store.loaded && store.list != nil {
		items := store.list
		store.mu.RUnlock()
		return matchRoute(items, destinationIP)
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	items, err := store.listLocked()
	if err != nil {
		return StoredRoute{}, false
	}

	return matchRoute(items, destinationIP)
}

func (store *Store) listLocked() ([]StoredRoute, error) {
	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}
	if store.list == nil {
		store.list = sortedRoutes(store.cache)
	}
	return store.list, nil
}

func (store *Store) ensureLoadedLocked() error {
	if store.loaded {
		return nil
	}

	items, err := loadStoredRoutes(store.dir, store.initErr)
	if err != nil {
		return err
	}

	store.cache = items
	store.list = nil
	store.loaded = true
	return nil
}

func loadStoredRoutes(dir string, initErr error) (map[string]StoredRoute, error) {
	return storeutil.LoadStoredJSONItems(
		dir,
		initErr,
		"stored routing rule",
		normalizeStoredRoute,
		func(item StoredRoute) string {
			return item.Label
		},
	)
}

func normalizeStoredRoute(route StoredRoute) (StoredRoute, error) {
	label, err := common.NormalizeAdoptionLabel(route.Label)
	if err != nil {
		return StoredRoute{}, err
	}

	cidrText := strings.TrimSpace(route.DestinationCIDR)
	if cidrText == "" {
		return StoredRoute{}, fmt.Errorf("destinationCIDR is required")
	}

	ip, network, err := net.ParseCIDR(cidrText)
	if err != nil {
		return StoredRoute{}, fmt.Errorf("destinationCIDR: %w", err)
	}
	ip = common.NormalizeIPv4(ip)
	if ip == nil || network == nil || len(network.Mask) != net.IPv4len {
		return StoredRoute{}, fmt.Errorf("destinationCIDR must be a valid IPv4 CIDR block")
	}
	network.IP = common.CloneIPv4(ip.Mask(network.Mask))

	viaIP, err := common.NormalizeAdoptionIP(route.ViaAdoptedIP)
	if err != nil {
		return StoredRoute{}, fmt.Errorf("viaAdoptedIP: %w", err)
	}

	return StoredRoute{
		Label:           label,
		DestinationCIDR: network.String(),
		ViaAdoptedIP:    viaIP.String(),
		ScriptName:      strings.TrimSpace(route.ScriptName),
	}, nil
}

func sortedRoutes(items map[string]StoredRoute) []StoredRoute {
	sorted := storeutil.SortedItems(items, func(left, right StoredRoute) bool {
		leftBits := routePrefixLength(left.DestinationCIDR)
		rightBits := routePrefixLength(right.DestinationCIDR)
		if leftBits != rightBits {
			return leftBits > rightBits
		}
		if left.DestinationCIDR != right.DestinationCIDR {
			return left.DestinationCIDR < right.DestinationCIDR
		}
		return strings.ToLower(left.Label) < strings.ToLower(right.Label)
	})

	return sorted
}

func matchRoute(items []StoredRoute, destinationIP net.IP) (StoredRoute, bool) {
	for _, item := range items {
		_, network, err := net.ParseCIDR(item.DestinationCIDR)
		if err != nil || network == nil {
			continue
		}
		if network.Contains(destinationIP) {
			return item, true
		}
	}

	return StoredRoute{}, false
}

func routePrefixLength(cidr string) int {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network == nil {
		return -1
	}

	ones, _ := network.Mask.Size()
	return ones
}
