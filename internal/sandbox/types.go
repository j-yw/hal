package sandbox

import "time"

// SandboxState represents the persisted state of a Daytona sandbox.
type SandboxState struct {
	Name        string    `json:"name"`
	SnapshotID  string    `json:"snapshotId"`
	WorkspaceID string    `json:"workspaceId"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
}
