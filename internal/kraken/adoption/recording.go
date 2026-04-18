package adoption

type StartAdoptedIPAddressRecordingRequest struct {
	IP         string `json:"ip"`
	OutputPath string `json:"outputPath,omitempty"`
}

type PacketRecordingStatus struct {
	Active      bool   `json:"active"`
	OutputPath  string `json:"outputPath,omitempty"`
	StartedAt   string `json:"startedAt,omitempty"`
	PacketCount int64  `json:"packetCount,omitempty"`
	ByteCount   int64  `json:"byteCount,omitempty"`
	LastError   string `json:"lastError,omitempty"`
}
