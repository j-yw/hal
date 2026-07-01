package cmd

import "time"

const SandboxRuntimeListContractType = "sandbox-runtime-list"
const SandboxRuntimeListContractVersion = "sandbox-runtime-list-v1"

const (
	SandboxRuntimeSourceCached          = "cached"
	SandboxRuntimeSourceLiveRefreshed   = "live-refreshed"
	SandboxRuntimeSourceUnsupportedLive = "unsupported-live"
)

// SandboxRuntimeListResponse is the machine-readable JSON output for
// hal sandbox runtime list <host-id> --json.
type SandboxRuntimeListResponse struct {
	ContractType    string                        `json:"contractType"`
	ContractVersion string                        `json:"contractVersion"`
	Host            SandboxRuntimeHost            `json:"host"`
	Source          SandboxRuntimeSource          `json:"source"`
	Runtimes        []SandboxRuntimeListEntry     `json:"runtimes"`
	Capacity        SandboxRuntimeCapacitySummary `json:"capacity"`
	Security        SandboxRuntimeSecuritySummary `json:"security"`
	Diagnostics     []SandboxRuntimeDiagnostic    `json:"diagnostics"`
	Errors          []SandboxRuntimeError         `json:"errors"`
}

// SandboxRuntimeHost identifies the inspected host without exposing raw
// endpoint values.
type SandboxRuntimeHost struct {
	ID       string                        `json:"id"`
	Name     string                        `json:"name"`
	Kind     string                        `json:"kind"`
	Endpoint SandboxRuntimeEndpointSummary `json:"endpoint"`
}

// SandboxRuntimeEndpointSummary summarizes an endpoint without raw socket
// paths, hostnames, credentials, query strings, or temp paths.
type SandboxRuntimeEndpointSummary struct {
	Type    string  `json:"type"`
	Summary string  `json:"summary"`
	Scheme  *string `json:"scheme"`
}

// SandboxRuntimeSource identifies where runtime metadata came from.
type SandboxRuntimeSource struct {
	Mode          string     `json:"mode"`
	RequestedLive bool       `json:"requestedLive"`
	CacheUpdated  bool       `json:"cacheUpdated"`
	RefreshedAt   *time.Time `json:"refreshedAt"`
	Summary       string     `json:"summary"`
}

// SandboxRuntimeListEntry summarizes a runtime driver available on a host.
type SandboxRuntimeListEntry struct {
	ID                  string                        `json:"id"`
	HostKind            *string                       `json:"hostKind"`
	IsolationLevel      *string                       `json:"isolationLevel"`
	SupportedOperations []string                      `json:"supportedOperations"`
	Security            SandboxRuntimeSecuritySummary `json:"security"`
	Diagnostics         []SandboxRuntimeDiagnostic    `json:"diagnostics"`
}

// SandboxRuntimeCapacitySummary is a safe host capacity summary.
type SandboxRuntimeCapacitySummary struct {
	Summary                string `json:"summary"`
	CPUCores               *int   `json:"cpuCores"`
	MemoryMB               *int   `json:"memoryMb"`
	DiskGB                 *int   `json:"diskGb"`
	MaxConcurrentSandboxes *int   `json:"maxConcurrentSandboxes"`
	ActiveSandboxes        *int   `json:"activeSandboxes"`
}

// SandboxRuntimeSecuritySummary separates requested controls from controls
// actually enforced by durable metadata or live worker capabilities.
type SandboxRuntimeSecuritySummary struct {
	Requested SandboxRuntimeSecurityControls `json:"requested"`
	Enforced  SandboxRuntimeSecurityControls `json:"enforced"`
}

// SandboxRuntimeSecurityControls captures safe security posture metadata.
type SandboxRuntimeSecurityControls struct {
	NetworkPolicy       *string  `json:"networkPolicy,omitempty"`
	NetworkEnforcement  *string  `json:"networkEnforcement,omitempty"`
	CredentialModes     []string `json:"credentialModes,omitempty"`
	CredentialProxyMode *bool    `json:"credentialProxyMode,omitempty"`
	IsolationLevel      *string  `json:"isolationLevel,omitempty"`
}

// SandboxRuntimeDiagnostic is a non-fatal runtime inspection diagnostic.
type SandboxRuntimeDiagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// SandboxRuntimeError is a safe fatal runtime inspection error entry.
type SandboxRuntimeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
