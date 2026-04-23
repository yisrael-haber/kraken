package routing

import (
	"fmt"
	"net"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
)

const storedRouteFolder = "routing"

type StoredRoute struct {
	Label               string `json:"label"`
	DestinationCIDR     string `json:"destinationCIDR"`
	ViaAdoptedIP        string `json:"viaAdoptedIP"`
	TransportScriptName string `json:"transportScriptName,omitempty"`
}

type Store struct {
	dir   string
	store *storeutil.JSONStore[StoredRoute]
}

func NewStore() *Store {
	dir, err := storeutil.DefaultKrakenConfigDir(storedRouteFolder)
	return newStore(dir, err)
}

func NewStoreAtDir(dir string) *Store {
	return newStore(dir, nil)
}

func newStore(dir string, initErr error) *Store {
	itemStore := storeutil.NewJSONStore(
		dir,
		initErr,
		"stored routing rule",
		normalizeStoredRoute,
		func(item StoredRoute) string {
			return item.Label
		},
		sortedRoutes,
	)
	return &Store{
		dir:   dir,
		store: itemStore,
	}
}

func (store *Store) List() ([]StoredRoute, error) {
	return store.store.List()
}

func (store *Store) Load(label string) (StoredRoute, error) {
	return store.store.Load(label)
}

func (store *Store) Save(route StoredRoute) (StoredRoute, error) {
	return store.store.Save(route)
}

func (store *Store) Delete(label string) error {
	return store.store.Delete(label)
}

func (store *Store) MatchDestination(destinationIP net.IP) (StoredRoute, bool) {
	destinationIP = common.NormalizeIPv4(destinationIP)
	if destinationIP == nil {
		return StoredRoute{}, false
	}

	var matched StoredRoute
	var ok bool
	if err := store.store.WithList(func(items []StoredRoute) {
		matched, ok = matchRoute(items, destinationIP)
	}); err != nil {
		return StoredRoute{}, false
	}
	return matched, ok
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
		Label:               label,
		DestinationCIDR:     network.String(),
		ViaAdoptedIP:        viaIP.String(),
		TransportScriptName: strings.TrimSpace(route.TransportScriptName),
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
