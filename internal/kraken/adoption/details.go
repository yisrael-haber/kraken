package adoption

type AdoptedIPAddressDetails struct {
	Label           string                 `json:"label"`
	IP              string                 `json:"ip"`
	InterfaceName   string                 `json:"interfaceName"`
	MAC             string                 `json:"mac"`
	DefaultGateway  string                 `json:"defaultGateway,omitempty"`
	MTU             int                    `json:"mtu,omitempty"`
	ScriptName      string                 `json:"scriptName,omitempty"`
	Recording       *PacketRecordingStatus `json:"recording,omitempty"`
	Services        []ServiceStatus        `json:"services,omitempty"`
	ARPCacheEntries []ARPCacheItem         `json:"arpCacheEntries,omitempty"`
}

type ARPCacheItem struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	UpdatedAt string `json:"updatedAt"`
}
