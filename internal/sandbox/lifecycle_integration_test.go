//go:build integration

package sandbox

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestIntegrationSandboxStartStatus(t *testing.T) {
	client := newIntegrationClient(t)
	halDir := integrationHalDir(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create a snapshot to start a sandbox from
	var snapOut bytes.Buffer
	snapshotID, err := CreateSnapshot(ctx, client, "inttest-start-status", "ubuntu:22.04", &snapOut)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	t.Logf("Created snapshot: %s", snapshotID)

	// Cleanup: delete sandbox + snapshot regardless of outcome
	var sandboxName string
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if sandboxName != "" {
			_ = DeleteSandbox(cleanupCtx, client, sandboxName, &bytes.Buffer{})
		}
		if snapshotID != "" {
			_ = DeleteSnapshot(cleanupCtx, client, snapshotID)
		}
	})

	// Start a sandbox from the snapshot
	var startOut bytes.Buffer
	result, err := CreateSandbox(ctx, client, "inttest-start-status", snapshotID, &startOut)
	if err != nil {
		t.Fatalf("CreateSandbox failed: %v", err)
	}
	sandboxName = result.Name
	t.Logf("Created sandbox: name=%s id=%s status=%s", result.Name, result.ID, result.Status)

	// Save state and verify sandbox.json is created with correct fields
	state := &SandboxState{
		Name:        result.Name,
		SnapshotID:  snapshotID,
		WorkspaceID: result.ID,
		Status:      result.Status,
		CreatedAt:   time.Now(),
	}
	if err := SaveState(halDir, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Verify the saved fields
	if state.Name == "" {
		t.Error("state Name is empty")
	}
	if state.SnapshotID != snapshotID {
		t.Errorf("state SnapshotID = %q, want %q", state.SnapshotID, snapshotID)
	}
	if state.WorkspaceID == "" {
		t.Error("state WorkspaceID is empty")
	}
	if state.Status == "" {
		t.Error("state Status is empty")
	}

	// Get live status from the API
	status, err := GetSandboxStatus(ctx, client, sandboxName)
	if err != nil {
		t.Fatalf("GetSandboxStatus failed: %v", err)
	}
	if status.Status == "" {
		t.Error("GetSandboxStatus returned empty status")
	}
	t.Logf("Live sandbox status: %s", status.Status)

	// Load state and verify it matches what was saved
	loaded, err := LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if loaded.Name != state.Name {
		t.Errorf("loaded Name = %q, want %q", loaded.Name, state.Name)
	}
	if loaded.SnapshotID != state.SnapshotID {
		t.Errorf("loaded SnapshotID = %q, want %q", loaded.SnapshotID, state.SnapshotID)
	}
	if loaded.WorkspaceID != state.WorkspaceID {
		t.Errorf("loaded WorkspaceID = %q, want %q", loaded.WorkspaceID, state.WorkspaceID)
	}
	if loaded.Status != state.Status {
		t.Errorf("loaded Status = %q, want %q", loaded.Status, state.Status)
	}
}
