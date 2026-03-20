package sandbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/template"
)

func TestSaveState(t *testing.T) {
	tests := []struct {
		name    string
		state   *SandboxState
		wantErr string
	}{
		{
			name: "saves valid state",
			state: &SandboxState{
				Name:        "hal-sandbox-implementation",
				SnapshotID:  "snap-123",
				WorkspaceID: "ws-456",
				Status:      "running",
				CreatedAt:   time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "saves minimal state",
			state: &SandboxState{
				Name:   "test",
				Status: "stopped",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := t.TempDir()

			err := SaveState(halDir, tt.state)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify file exists
			path := filepath.Join(halDir, template.SandboxFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read saved state: %v", err)
			}
			if !strings.Contains(string(data), tt.state.Name) {
				t.Errorf("saved state does not contain name %q", tt.state.Name)
			}
		})
	}
}

func TestLoadState(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, halDir string)
		wantErr      string
		wantName     string
		wantStatus   string
		wantNotExist bool
	}{
		{
			name: "loads valid state",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				content := `{
  "name": "my-sandbox",
  "snapshotId": "snap-abc",
  "workspaceId": "ws-def",
  "status": "running",
  "createdAt": "2026-02-14T12:00:00Z"
}`
				os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte(content), 0644)
			},
			wantName:   "my-sandbox",
			wantStatus: "running",
		},
		{
			name:         "returns descriptive error when file does not exist",
			setup:        func(t *testing.T, halDir string) {},
			wantErr:      "no active sandbox",
			wantNotExist: true,
		},
		{
			name: "returns error for invalid JSON",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte("{invalid"), 0644)
			},
			wantErr: "failed to parse sandbox state",
		},
		{
			name: "returns error when required name field is missing",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte("{}"), 0644)
			},
			wantErr: `invalid sandbox state: required field "name" is empty`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, halDir)
			}

			state, err := LoadState(halDir)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				if tt.wantNotExist && !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("expected error to wrap fs.ErrNotExist, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if state.Name != tt.wantName {
				t.Errorf("got name %q, want %q", state.Name, tt.wantName)
			}
			if state.Status != tt.wantStatus {
				t.Errorf("got status %q, want %q", state.Status, tt.wantStatus)
			}
		})
	}
}

func TestRemoveState(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, halDir string)
		wantErr string
	}{
		{
			name: "removes existing file",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte("{}"), 0644)
			},
		},
		{
			name:  "no error when file does not exist",
			setup: func(t *testing.T, halDir string) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, halDir)
			}

			err := RemoveState(halDir)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify file is gone
			path := filepath.Join(halDir, template.SandboxFile)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("sandbox state file should not exist after removal")
			}
		})
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	halDir := t.TempDir()
	created := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)

	original := &SandboxState{
		Name:        "hal-sandbox-implementation",
		Provider:    "daytona",
		IP:          "10.0.0.1",
		SnapshotID:  "snap-123",
		WorkspaceID: "ws-456",
		Status:      "running",
		CreatedAt:   created,
	}

	if err := SaveState(halDir, original); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	loaded, err := LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	if loaded.Name != original.Name {
		t.Errorf("Name: got %q, want %q", loaded.Name, original.Name)
	}
	if loaded.Provider != original.Provider {
		t.Errorf("Provider: got %q, want %q", loaded.Provider, original.Provider)
	}
	if loaded.IP != original.IP {
		t.Errorf("IP: got %q, want %q", loaded.IP, original.IP)
	}
	if loaded.SnapshotID != original.SnapshotID {
		t.Errorf("SnapshotID: got %q, want %q", loaded.SnapshotID, original.SnapshotID)
	}
	if loaded.WorkspaceID != original.WorkspaceID {
		t.Errorf("WorkspaceID: got %q, want %q", loaded.WorkspaceID, original.WorkspaceID)
	}
	if loaded.Status != original.Status {
		t.Errorf("Status: got %q, want %q", loaded.Status, original.Status)
	}
	if !loaded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", loaded.CreatedAt, original.CreatedAt)
	}
}

func TestLoadState_LegacyWithoutProvider(t *testing.T) {
	halDir := t.TempDir()
	// Legacy sandbox.json without provider or ip fields
	content := `{
  "name": "legacy-sandbox",
  "snapshotId": "snap-old",
  "workspaceId": "ws-old",
  "status": "running",
  "createdAt": "2026-02-14T12:00:00Z"
}`
	os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte(content), 0644)

	state, err := LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if state.Name != "legacy-sandbox" {
		t.Errorf("Name: got %q, want %q", state.Name, "legacy-sandbox")
	}
	// Provider should be auto-migrated to "daytona" for legacy files
	if state.Provider != "daytona" {
		t.Errorf("Provider: got %q, want %q", state.Provider, "daytona")
	}
	if state.IP != "" {
		t.Errorf("IP: got %q, want empty for legacy state", state.IP)
	}

	// Verify the state was re-saved with provider field
	reloaded, err := LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState (re-read) failed: %v", err)
	}
	if reloaded.Provider != "daytona" {
		t.Errorf("Re-read Provider: got %q, want %q", reloaded.Provider, "daytona")
	}
}

func TestLoadState_ExplicitProviderNotOverwritten(t *testing.T) {
	halDir := t.TempDir()
	// State with explicit provider: "hetzner" — migration must NOT overwrite
	content := `{
  "name": "hetzner-box",
  "provider": "hetzner",
  "ip": "203.0.113.10",
  "status": "running",
  "createdAt": "2026-03-20T10:00:00Z"
}`
	os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte(content), 0644)

	state, err := LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if state.Provider != "hetzner" {
		t.Errorf("Provider: got %q, want %q", state.Provider, "hetzner")
	}
	if state.IP != "203.0.113.10" {
		t.Errorf("IP: got %q, want %q", state.IP, "203.0.113.10")
	}

	// Verify state file was NOT re-written (read raw JSON to check)
	data, err := os.ReadFile(filepath.Join(halDir, template.SandboxFile))
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}
	// Original content should be preserved as-is (no re-save occurred)
	if !strings.Contains(string(data), `"hetzner-box"`) {
		t.Error("state file content was unexpectedly modified")
	}
}

func TestSaveAndLoadRoundTrip_Hetzner(t *testing.T) {
	halDir := t.TempDir()
	created := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)

	original := &SandboxState{
		Name:      "hetzner-sandbox",
		Provider:  "hetzner",
		IP:        "192.168.1.100",
		Status:    "running",
		CreatedAt: created,
	}

	if err := SaveState(halDir, original); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	loaded, err := LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	if loaded.Provider != "hetzner" {
		t.Errorf("Provider: got %q, want %q", loaded.Provider, "hetzner")
	}
	if loaded.IP != "192.168.1.100" {
		t.Errorf("IP: got %q, want %q", loaded.IP, "192.168.1.100")
	}
	// SnapshotID and WorkspaceID should be empty for Hetzner
	if loaded.SnapshotID != "" {
		t.Errorf("SnapshotID: got %q, want empty", loaded.SnapshotID)
	}
	if loaded.WorkspaceID != "" {
		t.Errorf("WorkspaceID: got %q, want empty", loaded.WorkspaceID)
	}
}
