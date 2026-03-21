package sandbox

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSandboxStateJSONTags(t *testing.T) {
	createdAt := time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC)
	stoppedAt := createdAt.Add(2 * time.Hour)

	tests := []struct {
		name        string
		state       SandboxState
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name: "minimal state omits optional fields",
			state: SandboxState{
				ID:           "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
				Name:         "api-backend",
				Provider:     "daytona",
				IP:           "",
				Status:       StatusRunning,
				CreatedAt:    createdAt,
				AutoShutdown: false,
			},
			wantPresent: []string{"id", "name", "provider", "ip", "status", "createdAt", "autoShutdown"},
			wantAbsent:  []string{"workspaceId", "tailscaleIp", "tailscaleHostname", "stoppedAt", "idleHours", "size", "repo", "snapshotId"},
		},
		{
			name: "full state includes optional fields with camelCase keys",
			state: SandboxState{
				ID:                "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
				Name:              "api-backend",
				Provider:          "digitalocean",
				WorkspaceID:       "123456789",
				IP:                "104.131.5.22",
				TailscaleIP:       "100.64.1.10",
				TailscaleHostname: "hal-api-backend",
				Status:            StatusStopped,
				CreatedAt:         createdAt,
				StoppedAt:         &stoppedAt,
				AutoShutdown:      true,
				IdleHours:         48,
				Size:              "s-2vcpu-4gb",
				Repo:              "api",
				SnapshotID:        "snap-123",
			},
			wantPresent: []string{
				"id", "name", "provider", "workspaceId", "ip", "tailscaleIp", "tailscaleHostname",
				"status", "createdAt", "stoppedAt", "autoShutdown", "idleHours", "size", "repo", "snapshotId",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.state)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}

			for _, key := range tt.wantPresent {
				if _, ok := got[key]; !ok {
					t.Errorf("missing expected key %q in %s", key, string(data))
				}
			}
			for _, key := range tt.wantAbsent {
				if _, ok := got[key]; ok {
					t.Errorf("unexpected key %q in %s", key, string(data))
				}
			}
		})
	}
}

func TestSandboxStatusConstants(t *testing.T) {
	if StatusRunning != "running" {
		t.Fatalf("StatusRunning = %q, want %q", StatusRunning, "running")
	}
	if StatusStopped != "stopped" {
		t.Fatalf("StatusStopped = %q, want %q", StatusStopped, "stopped")
	}
	if StatusUnknown != "unknown" {
		t.Fatalf("StatusUnknown = %q, want %q", StatusUnknown, "unknown")
	}
}
