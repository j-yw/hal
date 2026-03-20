package sandbox

import "time"

// SandboxState represents the persisted state of a sandbox.
type SandboxState struct {
	Name        string    `json:"name"`
	Provider    string    `json:"provider"`
	IP          string    `json:"ip"`
	TailscaleIP string    `json:"tailscaleIp"`
	SnapshotID  string    `json:"snapshotId"`
	WorkspaceID string    `json:"workspaceId"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
}
