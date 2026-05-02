package storage

import (
	"fmt"
	"net"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const storedRouteFolder = "routing"

type StoredRoute struct {
	Label           string `json:"label"`
	DestinationCIDR string `json:"destinationCIDR"`
	ViaAdoptedIP    string `json:"viaAdoptedIP"`
}

type RoutingStore JSONStore[StoredRoute]

func NewRoutingStore() *RoutingStore {
	dir, err := DefaultKrakenConfigDir(storedRouteFolder)
	return newRoutingStore(dir, err)
}

func NewRoutingStoreAtDir(dir string) *RoutingStore {
	return newRoutingStore(dir, nil)
}

func newRoutingStore(dir string, initErr error) *RoutingStore {
	itemStore := NewJSONStore(
		dir,
		initErr,
		"stored routing rule",
		normalizeStoredRoute,
		func(item StoredRoute) string {
			return item.Label
		},
		sortedRoutes,
	)
	return (*RoutingStore)(itemStore)
}

func (store *RoutingStore) MatchDestination(destinationIP net.IP) (StoredRoute, bool) {
	destinationIP = destinationIP.To4()
	if destinationIP == nil {
		return StoredRoute{}, false
	}

	items, err := ((*JSONStore[StoredRoute])(store)).List()
	if err != nil {
		return StoredRoute{}, false
	}
	return matchRoute(items, destinationIP)
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
		Label:           label,
		DestinationCIDR: network.String(),
		ViaAdoptedIP:    viaIP.String(),
	}, nil
}

func sortedRoutes(items map[string]StoredRoute) []StoredRoute {
	sorted := SortedItems(items, func(left, right StoredRoute) bool {
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
