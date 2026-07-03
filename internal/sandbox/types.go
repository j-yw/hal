package sandbox

import "time"

const (
	StatusRunning = "running"
	StatusStopped = "stopped"
	StatusUnknown = "unknown"
)

// Sandbox Runtime v2 metadata constants are stable durable values used by
// persisted metadata contracts.
const (
	SandboxHostKindLocal  = "local"
	SandboxHostKindSSH    = "ssh"
	SandboxHostKindWorker = "worker"
	SandboxHostKindK8s    = "k8s"

	SandboxRuntimeDriverSSHMachine     = "ssh_machine"
	SandboxRuntimeDriverRootlessPodman = "rootless_podman"
	SandboxRuntimeDriverMicroVM        = "microvm"

	SandboxIsolationLevelHost      = "host"
	SandboxIsolationLevelContainer = "container"
	SandboxIsolationLevelVM        = "vm"

	SandboxWorkspaceModeClone  = "clone"
	SandboxWorkspaceModeCopy   = "copy"
	SandboxWorkspaceModeDirect = "direct"

	SandboxWorkspaceInputSourceRemoteRef = "remote_ref"
	SandboxWorkspaceInputSourceGitBundle = "git_bundle"
	SandboxWorkspaceInputSourceCopy      = "copy"

	SandboxNetworkEnforcementModeNone          = "none"
	SandboxNetworkEnforcementModeBestEffort    = "best_effort"
	SandboxNetworkEnforcementModeProxy         = "proxy"
	SandboxNetworkEnforcementModeFirewall      = "firewall"
	SandboxNetworkEnforcementModeRuntime       = "runtime"
	SandboxNetworkEnforcementModeProxyFirewall = "proxy_firewall"

	SandboxNetworkPolicyDenyByDefault = "deny_by_default"
	SandboxNetworkPolicyBestEffort    = "best_effort"

	SandboxSecretModeEnv            = "env"
	SandboxSecretModeFileTmpfs      = "file_tmpfs"
	SandboxSecretModeSSHAgent       = "ssh_agent"
	SandboxSecretModeHTTPProxy      = "http_proxy"
	SandboxSecretModeLegacyAuthSync = "legacy_auth_sync"
)

const (
	SandboxLeaseStatusActive   = "active"
	SandboxLeaseStatusReleased = "released"
	SandboxLeaseStatusExpired  = "expired"

	SandboxLeasePurposeRun     = "run"
	SandboxLeasePurposeAuto    = "auto"
	SandboxLeasePurposeFactory = "factory"
)

// SandboxHost represents durable Sandbox Runtime v2 host metadata.
type SandboxHost struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Kind              string            `json:"kind"`
	Endpoint          string            `json:"endpoint,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	SupportedRuntimes []string          `json:"supportedRuntimes,omitempty"`
	Capacity          *HostCapacity     `json:"capacity,omitempty"`
	Health            *HostHealth       `json:"health,omitempty"`
	Security          *SandboxSecurity  `json:"security,omitempty"`
	Cost              *HostCost         `json:"cost,omitempty"`
}

// SandboxHostRef identifies a sandbox host without embedding full host metadata.
type SandboxHostRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// HostCapacity describes durable host resource capacity metadata.
type HostCapacity struct {
	CPUCores               int `json:"cpuCores"`
	MemoryMB               int `json:"memoryMb"`
	DiskGB                 int `json:"diskGb"`
	MaxConcurrentSandboxes int `json:"maxConcurrentSandboxes"`
}

// HostHealth describes durable host health metadata.
type HostHealth struct {
	Status          string     `json:"status"`
	CheckedAt       time.Time  `json:"checkedAt"`
	LastHeartbeatAt *time.Time `json:"lastHeartbeatAt,omitempty"`
	Message         string     `json:"message,omitempty"`
}

// HostCost describes durable host cost estimate metadata.
type HostCost struct {
	Currency       string  `json:"currency"`
	HourlyEstimate float64 `json:"hourlyEstimate"`
	BillingScope   string  `json:"billingScope,omitempty"`
}

// SandboxRuntimeState represents durable Sandbox Runtime v2 runtime metadata.
type SandboxRuntimeState struct {
	Driver         string                       `json:"driver"`
	IsolationLevel string                       `json:"isolationLevel"`
	RuntimeID      string                       `json:"runtimeId"`
	Image          string                       `json:"image"`
	WorkerID       string                       `json:"workerId"`
	TemplateLock   *SandboxTemplateLockMetadata `json:"templateLock,omitempty"`
}

// SandboxWorkspace represents durable Sandbox Runtime v2 workspace metadata.
type SandboxWorkspace struct {
	Mode        string `json:"mode"`
	InputSource string `json:"inputSource"`
	Repo        string `json:"repo"`
	Branch      string `json:"branch"`
	SyncRef     string `json:"syncRef"`
}

// SandboxSecurity represents durable Sandbox Runtime v2 security metadata.
type SandboxSecurity struct {
	Network                        *SandboxNetworkSecurity                              `json:"network,omitempty"`
	Secrets                        *SandboxSecretSecurity                               `json:"secrets,omitempty"`
	CapabilityReadiness            *SandboxSecurityCapabilityReadinessOutput            `json:"capabilityReadiness,omitempty"`
	CapabilityReadinessDiagnostics *SandboxSecurityCapabilityReadinessDiagnosticSummary `json:"capabilityReadinessDiagnostics,omitempty"`
}

// SandboxNetworkSecurity describes network policy metadata for a sandbox.
type SandboxNetworkSecurity struct {
	PolicyRequested string                      `json:"policyRequested,omitempty"`
	PolicyEnforced  string                      `json:"policyEnforced,omitempty"`
	EnforcementMode string                      `json:"enforcementMode,omitempty"`
	PolicyResult    *SandboxNetworkPolicyResult `json:"policyResult,omitempty"`
}

// SandboxSecretSecurity describes secret delivery mode metadata for a sandbox.
type SandboxSecretSecurity struct {
	RequestedModes []string `json:"requestedModes,omitempty"`
	ActiveModes    []string `json:"activeModes,omitempty"`
}

// WorkerRoutingMetadata captures the redaction-safe worker-backed execution
// route selected for a sandbox execution record.
type WorkerRoutingMetadata struct {
	SelectedWorkerHostID   string `json:"selectedWorkerHostId"`
	SelectedWorkerHostName string `json:"selectedWorkerHostName"`
	RuntimeDriverID        string `json:"runtimeDriverId"`
	IsolationLevel         string `json:"isolationLevel"`
	EndpointSummary        string `json:"endpointSummary"`
}

// SandboxLeaseRef identifies a lease associated with a sandbox using only
// redaction-safe scheduling metadata.
type SandboxLeaseRef struct {
	ID            string    `json:"id"`
	HostID        string    `json:"hostId"`
	HostName      string    `json:"hostName"`
	RuntimeDriver string    `json:"runtimeDriver"`
	ResourceKey   string    `json:"resourceKey"`
	Holder        string    `json:"-"`
	Purpose       string    `json:"purpose"`
	RunID         string    `json:"runId"`
	AcquiredAt    time.Time `json:"acquiredAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// SandboxLease represents a durable local resource lease record.
type SandboxLease struct {
	ID          string    `json:"id"`
	SandboxID   string    `json:"sandboxId,omitempty"`
	SandboxName string    `json:"sandboxName,omitempty"`
	ResourceKey string    `json:"resourceKey"`
	Holder      string    `json:"holder"`
	Purpose     string    `json:"purpose"`
	RunID       string    `json:"runId,omitempty"`
	AcquiredAt  time.Time `json:"acquiredAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	HeartbeatAt time.Time `json:"heartbeatAt"`
	Status      string    `json:"status"`
}

// SandboxState represents the persisted state of a sandbox.
type SandboxState struct {
	// Identity
	ID   string `json:"id"`
	Name string `json:"name"`

	// Provider
	Provider    string `json:"provider"`
	WorkspaceID string `json:"workspaceId,omitempty"`

	// Networking
	IP                string `json:"ip"`
	TailscaleIP       string `json:"tailscaleIp,omitempty"`
	TailscaleHostname string `json:"tailscaleHostname,omitempty"`
	TailscaleLockdown bool   `json:"tailscaleLockdown,omitempty"`

	// Lifecycle
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"createdAt"`
	StoppedAt *time.Time `json:"stoppedAt,omitempty"`

	// Config
	AutoShutdown bool   `json:"autoShutdown"`
	IdleHours    int    `json:"idleHours,omitempty"`
	Size         string `json:"size,omitempty"`

	// Labels
	Repo       string `json:"repo,omitempty"`
	SnapshotID string `json:"snapshotId,omitempty"`

	// Sandbox Runtime v2 metadata
	Host      *SandboxHost         `json:"host,omitempty"`
	Runtime   *SandboxRuntimeState `json:"runtime,omitempty"`
	Workspace *SandboxWorkspace    `json:"workspace,omitempty"`
	Security  *SandboxSecurity     `json:"security,omitempty"`
	Lease     *SandboxLeaseRef     `json:"lease,omitempty"`
}
