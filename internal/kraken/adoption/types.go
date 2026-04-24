package adoption

const (
	ServiceFieldTypePort      = "port"
	ServiceFieldTypeText      = "text"
	ServiceFieldTypeSecret    = "secret"
	ServiceFieldTypeSelect    = "select"
	ServiceFieldTypeDirectory = "directory"
)

type AdoptIPAddressRequest struct {
	Label          string `json:"label"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type AdoptedIPAddress struct {
	Label          string `json:"label"`
	IP             string `json:"ip"`
	InterfaceName  string `json:"interfaceName"`
	MAC            string `json:"mac"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type UpdateAdoptedIPAddressRequest struct {
	Label          string `json:"label"`
	CurrentIP      string `json:"currentIP"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type PingAdoptedIPAddressRequest struct {
	SourceIP   string `json:"sourceIP"`
	TargetIP   string `json:"targetIP"`
	Count      int    `json:"count,omitempty"`
	PayloadHex string `json:"payloadHex,omitempty"`
}

type ResolveDNSAdoptedIPAddressRequest struct {
	SourceIP      string `json:"sourceIP"`
	Server        string `json:"server"`
	Name          string `json:"name"`
	Type          string `json:"type,omitempty"`
	Transport     string `json:"transport,omitempty"`
	TimeoutMillis int    `json:"timeoutMillis,omitempty"`
}

type UpdateAdoptedIPAddressScriptsRequest struct {
	IP                    string `json:"ip"`
	TransportScriptName   string `json:"transportScriptName"`
	ApplicationScriptName string `json:"applicationScriptName"`
}

type StartAdoptedIPAddressServiceRequest struct {
	IP      string            `json:"ip"`
	Service string            `json:"service"`
	Config  map[string]string `json:"config,omitempty"`
}

type StopAdoptedIPAddressServiceRequest struct {
	IP      string `json:"ip"`
	Service string `json:"service"`
}

type PingAdoptedIPAddressReply struct {
	Sequence  int     `json:"sequence"`
	Success   bool    `json:"success"`
	RTTMillis float64 `json:"rttMillis,omitempty"`
}

type PingAdoptedIPAddressResult struct {
	SourceIP string                      `json:"sourceIP"`
	TargetIP string                      `json:"targetIP"`
	Sent     int                         `json:"sent"`
	Received int                         `json:"received"`
	Replies  []PingAdoptedIPAddressReply `json:"replies"`
}

type ResolveDNSAdoptedIPAddressResult struct {
	SourceIP     string   `json:"sourceIP"`
	Server       string   `json:"server"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Transport    string   `json:"transport"`
	RTTMillis    float64  `json:"rttMillis,omitempty"`
	ResponseID   int      `json:"responseID,omitempty"`
	ResponseCode string   `json:"responseCode,omitempty"`
	Records      []string `json:"records,omitempty"`
}

type ServiceFieldOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type ServiceFieldDefinition struct {
	Name          string               `json:"name"`
	Label         string               `json:"label"`
	Type          string               `json:"type"`
	Required      bool                 `json:"required,omitempty"`
	DefaultValue  string               `json:"defaultValue,omitempty"`
	Placeholder   string               `json:"placeholder,omitempty"`
	ScriptSurface string               `json:"scriptSurface,omitempty"`
	Options       []ServiceFieldOption `json:"options,omitempty"`
}

type ServiceDefinition struct {
	Service     string                   `json:"service"`
	Label       string                   `json:"label"`
	DefaultPort int                      `json:"defaultPort,omitempty"`
	Fields      []ServiceFieldDefinition `json:"fields,omitempty"`
}

type ServiceSummaryItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Code  bool   `json:"code,omitempty"`
}

type ServiceStatus struct {
	Service     string               `json:"service"`
	Active      bool                 `json:"active"`
	Port        int                  `json:"port"`
	Config      map[string]string    `json:"config,omitempty"`
	Summary     []ServiceSummaryItem `json:"summary,omitempty"`
	StartedAt   string               `json:"startedAt,omitempty"`
	LastError   string               `json:"lastError,omitempty"`
	ScriptError *ScriptRuntimeError  `json:"scriptError,omitempty"`
}
