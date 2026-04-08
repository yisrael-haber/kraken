package kraken

import (
	adoptionpkg "github.com/yisrael-haber/kraken/internal/kraken/adoption"
	configpkg "github.com/yisrael-haber/kraken/internal/kraken/config"
	"github.com/yisrael-haber/kraken/internal/kraken/inventory"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

// Re-export the Wails-facing DTOs from the packages that own them so the
// runtime surface stays centralized without collapsing package boundaries.
type (
	AdoptIPAddressRequest                         = adoptionpkg.AdoptIPAddressRequest
	AdoptedIPAddress                              = adoptionpkg.AdoptedIPAddress
	UpdateAdoptedIPAddressRequest                 = adoptionpkg.UpdateAdoptedIPAddressRequest
	PingAdoptedIPAddressRequest                   = adoptionpkg.PingAdoptedIPAddressRequest
	AdoptedIPAddressOverrideBindings              = adoptionpkg.AdoptedIPAddressOverrideBindings
	UpdateAdoptedIPAddressOverrideBindingsRequest = adoptionpkg.UpdateAdoptedIPAddressOverrideBindingsRequest
	PingAdoptedIPAddressReply                     = adoptionpkg.PingAdoptedIPAddressReply
	PingAdoptedIPAddressResult                    = adoptionpkg.PingAdoptedIPAddressResult
	AdoptedIPAddressDetails                       = adoptionpkg.AdoptedIPAddressDetails
	ARPCacheItem                                  = adoptionpkg.ARPCacheItem
	ARPActivity                                   = adoptionpkg.ARPActivity
	ICMPActivity                                  = adoptionpkg.ICMPActivity
	StoredAdoptionConfiguration                   = configpkg.StoredAdoptionConfiguration
	InterfaceSnapshot                             = inventory.InterfaceSnapshot
	NetworkInterface                              = inventory.NetworkInterface
	InterfaceAddress                              = inventory.InterfaceAddress
	StoredPacketOverride                          = packetpkg.StoredPacketOverride
	PacketOverrideLayers                          = packetpkg.PacketOverrideLayers
	PacketOverrideEthernet                        = packetpkg.PacketOverrideEthernet
	PacketOverrideIPv4                            = packetpkg.PacketOverrideIPv4
	PacketOverrideARP                             = packetpkg.PacketOverrideARP
	PacketOverrideICMPv4                          = packetpkg.PacketOverrideICMPv4
)
