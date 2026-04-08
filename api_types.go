package main

import backend "github.com/yisrael-haber/kraken/internal/kraken"

// Keep the Wails-facing type surface in package main while backend ownership
// stays with the feature packages under internal/kraken.
type (
	AdoptIPAddressRequest                         = backend.AdoptIPAddressRequest
	AdoptedIPAddress                              = backend.AdoptedIPAddress
	UpdateAdoptedIPAddressRequest                 = backend.UpdateAdoptedIPAddressRequest
	PingAdoptedIPAddressRequest                   = backend.PingAdoptedIPAddressRequest
	AdoptedIPAddressOverrideBindings              = backend.AdoptedIPAddressOverrideBindings
	UpdateAdoptedIPAddressOverrideBindingsRequest = backend.UpdateAdoptedIPAddressOverrideBindingsRequest
	PingAdoptedIPAddressReply                     = backend.PingAdoptedIPAddressReply
	PingAdoptedIPAddressResult                    = backend.PingAdoptedIPAddressResult
	StoredAdoptionConfiguration                   = backend.StoredAdoptionConfiguration
	AdoptedIPAddressDetails                       = backend.AdoptedIPAddressDetails
	ARPCacheItem                                  = backend.ARPCacheItem
	ARPActivity                                   = backend.ARPActivity
	ICMPActivity                                  = backend.ICMPActivity
	InterfaceSnapshot                             = backend.InterfaceSnapshot
	NetworkInterface                              = backend.NetworkInterface
	InterfaceAddress                              = backend.InterfaceAddress
	StoredPacketOverride                          = backend.StoredPacketOverride
	PacketOverrideLayers                          = backend.PacketOverrideLayers
	PacketOverrideEthernet                        = backend.PacketOverrideEthernet
	PacketOverrideIPv4                            = backend.PacketOverrideIPv4
	PacketOverrideARP                             = backend.PacketOverrideARP
	PacketOverrideICMPv4                          = backend.PacketOverrideICMPv4
)
