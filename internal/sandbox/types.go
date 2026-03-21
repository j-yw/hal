package sandbox

import "time"

const (
	StatusRunning = "running"
	StatusStopped = "stopped"
	StatusUnknown = "unknown"
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
