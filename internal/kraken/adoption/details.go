package adoption

type AdoptedIPAddressDetails struct {
	Label                 string                 `json:"label"`
	IP                    string                 `json:"ip"`
	InterfaceName         string                 `json:"interfaceName"`
	MAC                   string                 `json:"mac"`
	DefaultGateway        string                 `json:"defaultGateway,omitempty"`
	MTU                   int                    `json:"mtu,omitempty"`
	TransportScriptName   string                 `json:"transportScriptName,omitempty"`
	ApplicationScriptName string                 `json:"applicationScriptName,omitempty"`
	Capture               *CaptureStatus         `json:"capture,omitempty"`
	ScriptError           *ScriptRuntimeError    `json:"scriptError,omitempty"`
	Recording             *PacketRecordingStatus `json:"recording,omitempty"`
	Services              []ServiceStatus        `json:"services,omitempty"`
	ARPCacheEntries       []ARPCacheItem         `json:"arpCacheEntries,omitempty"`
}

type ListenerStatus struct {
	Capture     *CaptureStatus      `json:"capture,omitempty"`
	ScriptError *ScriptRuntimeError `json:"scriptError,omitempty"`
}

type CaptureStatus struct {
	ActiveFilter  string `json:"activeFilter,omitempty"`
	PendingFilter string `json:"pendingFilter,omitempty"`
	LastError     string `json:"lastError,omitempty"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

type ScriptRuntimeError struct {
	ScriptName string `json:"scriptName,omitempty"`
	Surface    string `json:"surface,omitempty"`
	Stage      string `json:"stage,omitempty"`
	Direction  string `json:"direction,omitempty"`
	LastError  string `json:"lastError,omitempty"`
	UpdatedAt  string `json:"updatedAt,omitempty"`
}

type ARPCacheItem struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	UpdatedAt string `json:"updatedAt"`
}
