package storage

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const storedRouteFolder = "routing"

type StoredRoute struct {
	Label           string `json:"label"`
	DestinationCIDR string `json:"destinationCIDR"`
	ViaAdoptedIP    string `json:"viaAdoptedIP"`
}

type RoutingStore struct {
	store *JSONStore[StoredRoute]
}

func NewRoutingStore() *RoutingStore {
	dir, err := DefaultKrakenConfigDir(storedRouteFolder)
	return newRoutingStore(dir, err)
}

func NewRoutingStoreAtDir(dir string) *RoutingStore {
	return newRoutingStore(dir, nil)
}

func newRoutingStore(dir string, initErr error) *RoutingStore {
	return &RoutingStore{store: NewJSONStore[StoredRoute](dir, initErr, "stored routing rule")}
}

func (store *RoutingStore) List() ([]StoredRoute, error) {
	files, err := store.store.List()
	if err != nil {
		return nil, err
	}

	items := make([]StoredRoute, 0, len(files))
	for name, value := range files {
		item, err := normalizeStoredRoute(value)
		if err != nil {
			return nil, fmt.Errorf("validate stored routing rule %q: %w", name+".json", err)
		}
		items = append(items, item)
	}

	return sortedRoutes(items), nil
}

func (store *RoutingStore) Save(route StoredRoute) (StoredRoute, error) {
	normalized, err := normalizeStoredRoute(route)
	if err != nil {
		return StoredRoute{}, err
	}
	if err := store.store.Save(normalized.Label, normalized); err != nil {
		return StoredRoute{}, err
	}
	return normalized, nil
}

func (store *RoutingStore) Delete(label string) error {
	return store.store.Delete(label)
}

func (store *RoutingStore) MatchDestination(destinationIP net.IP) (StoredRoute, bool) {
	destinationIP = destinationIP.To4()
	if destinationIP == nil {
		return StoredRoute{}, false
	}

	items, err := store.List()
	if err != nil {
		return StoredRoute{}, false
	}
	return matchRoute(items, destinationIP)
}

func normalizeStoredRoute(route StoredRoute) (StoredRoute, error) {
	if !common.ValidLabel(route.Label) {
		return StoredRoute{}, fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}

	cidrText := strings.TrimSpace(route.DestinationCIDR)
	if cidrText == "" {
		return StoredRoute{}, fmt.Errorf("destinationCIDR is required")
	}

	ip, network, err := net.ParseCIDR(cidrText)
	if err != nil {
		return StoredRoute{}, fmt.Errorf("destinationCIDR: %w", err)
	}
	ip = ip.To4()
	if ip == nil || network == nil || len(network.Mask) != net.IPv4len {
		return StoredRoute{}, fmt.Errorf("destinationCIDR must be a valid IPv4 CIDR block")
	}
	network.IP = ip.Mask(network.Mask)

	viaIP, err := common.NormalizeAdoptionIP(route.ViaAdoptedIP)
	if err != nil {
		return StoredRoute{}, fmt.Errorf("viaAdoptedIP: %w", err)
	}

	return StoredRoute{
		Label:           route.Label,
		DestinationCIDR: network.String(),
		ViaAdoptedIP:    viaIP.String(),
	}, nil
}

func sortedRoutes(items []StoredRoute) []StoredRoute {
	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		leftBits := cidrPrefixLength(left.DestinationCIDR)
		rightBits := cidrPrefixLength(right.DestinationCIDR)
		if leftBits != rightBits {
			return leftBits > rightBits
		}
		if left.DestinationCIDR != right.DestinationCIDR {
			return left.DestinationCIDR < right.DestinationCIDR
		}
		return strings.ToLower(left.Label) < strings.ToLower(right.Label)
	})
	return items
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

func cidrPrefixLength(cidr string) int {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network == nil {
		return -1
	}
	ones, _ := network.Mask.Size()
	return ones
}
