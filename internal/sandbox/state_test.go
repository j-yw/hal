package sandbox

import (
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
		name       string
		setup      func(t *testing.T, halDir string)
		wantErr    string
		wantName   string
		wantStatus string
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
			name:    "returns descriptive error when file does not exist",
			setup:   func(t *testing.T, halDir string) {},
			wantErr: "no active sandbox",
		},
		{
			name: "returns error for invalid JSON",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte("{invalid"), 0644)
			},
			wantErr: "failed to parse sandbox state",
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
