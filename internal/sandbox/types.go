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

	SandboxSecretModeEnv            = "env"
	SandboxSecretModeFileTmpfs      = "file_tmpfs"
	SandboxSecretModeSSHAgent       = "ssh_agent"
	SandboxSecretModeHTTPProxy      = "http_proxy"
	SandboxSecretModeLegacyAuthSync = "legacy_auth_sync"
)

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
}
