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
	Metrics               *AdoptedIPMetrics      `json:"metrics,omitempty"`
	ScriptError           *ScriptRuntimeError    `json:"scriptError,omitempty"`
	Recording             *PacketRecordingStatus `json:"recording,omitempty"`
	Services              []ServiceStatus        `json:"services,omitempty"`
	ARPCacheEntries       []ARPCacheItem         `json:"arpCacheEntries,omitempty"`
}

type ListenerStatus struct {
	Capture     *CaptureStatus      `json:"capture,omitempty"`
	Metrics     *AdoptedIPMetrics   `json:"metrics,omitempty"`
	ScriptError *ScriptRuntimeError `json:"scriptError,omitempty"`
}

type CaptureStatus struct {
	ActiveFilter  string `json:"activeFilter,omitempty"`
	PendingFilter string `json:"pendingFilter,omitempty"`
	LastError     string `json:"lastError,omitempty"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

type AdoptedIPMetrics struct {
	FramesRead              uint64 `json:"framesRead,omitempty"`
	LocalFrames             uint64 `json:"localFrames,omitempty"`
	ForwardedFrames         uint64 `json:"forwardedFrames,omitempty"`
	RouteHits               uint64 `json:"routeHits,omitempty"`
	InboundFrames           uint64 `json:"inboundFrames,omitempty"`
	RoutedFrames            uint64 `json:"routedFrames,omitempty"`
	OutboundFrames          uint64 `json:"outboundFrames,omitempty"`
	OutboundWriteErrors     uint64 `json:"outboundWriteErrors,omitempty"`
	TransportScriptErrors   uint64 `json:"transportScriptErrors,omitempty"`
	ApplicationScriptErrors uint64 `json:"applicationScriptErrors,omitempty"`
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
