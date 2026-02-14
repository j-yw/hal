//go:build integration

package sandbox

import (
	"bytes"
	"context"
	"strings"
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

func TestIntegrationSandboxStopState(t *testing.T) {
	client := newIntegrationClient(t)
	halDir := integrationHalDir(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create a snapshot to start a sandbox from
	var snapOut bytes.Buffer
	snapshotID, err := CreateSnapshot(ctx, client, "inttest-stop-state", "ubuntu:22.04", &snapOut)
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
	result, err := CreateSandbox(ctx, client, "inttest-stop-state", snapshotID, &startOut)
	if err != nil {
		t.Fatalf("CreateSandbox failed: %v", err)
	}
	sandboxName = result.Name
	t.Logf("Created sandbox: name=%s id=%s status=%s", result.Name, result.ID, result.Status)

	// Stop the sandbox
	var stopOut bytes.Buffer
	if err := StopSandbox(ctx, client, sandboxName, &stopOut); err != nil {
		t.Fatalf("StopSandbox failed: %v", err)
	}
	t.Log("Stopped sandbox successfully")

	// Get status after stop and verify it reflects stopped state
	status, err := GetSandboxStatus(ctx, client, sandboxName)
	if err != nil {
		t.Fatalf("GetSandboxStatus after stop failed: %v", err)
	}
	if status.Status != "stopped" {
		t.Errorf("status after stop = %q, want %q", status.Status, "stopped")
	}
	t.Logf("Status after stop: %s", status.Status)

	// Update state via SaveState with the new status
	state := &SandboxState{
		Name:        result.Name,
		SnapshotID:  snapshotID,
		WorkspaceID: result.ID,
		Status:      status.Status,
		CreatedAt:   time.Now(),
	}
	if err := SaveState(halDir, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Verify LoadState returns the updated status
	loaded, err := LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if loaded.Status != status.Status {
		t.Errorf("loaded Status = %q, want %q", loaded.Status, status.Status)
	}
	if loaded.Name != result.Name {
		t.Errorf("loaded Name = %q, want %q", loaded.Name, result.Name)
	}
	if loaded.SnapshotID != snapshotID {
		t.Errorf("loaded SnapshotID = %q, want %q", loaded.SnapshotID, snapshotID)
	}
	if loaded.WorkspaceID != result.ID {
		t.Errorf("loaded WorkspaceID = %q, want %q", loaded.WorkspaceID, result.ID)
	}
	t.Logf("State round-trip verified: status=%s", loaded.Status)
}

func TestIntegrationSandboxExec(t *testing.T) {
	client := newIntegrationClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create a snapshot to start a sandbox from
	var snapOut bytes.Buffer
	snapshotID, err := CreateSnapshot(ctx, client, "inttest-exec", "ubuntu:22.04", &snapOut)
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
	result, err := CreateSandbox(ctx, client, "inttest-exec", snapshotID, &startOut)
	if err != nil {
		t.Fatalf("CreateSandbox failed: %v", err)
	}
	sandboxName = result.Name
	t.Logf("Created sandbox: name=%s id=%s status=%s", result.Name, result.ID, result.Status)

	// Test 1: Execute a valid command and verify output
	execResult, err := ExecCommand(ctx, client, sandboxName, "echo hello")
	if err != nil {
		t.Fatalf("ExecCommand('echo hello') failed: %v", err)
	}
	if !strings.Contains(execResult.Output, "hello") {
		t.Errorf("ExecCommand output = %q, want it to contain %q", execResult.Output, "hello")
	}
	if execResult.ExitCode != 0 {
		t.Errorf("ExecCommand('echo hello') ExitCode = %d, want 0", execResult.ExitCode)
	}
	t.Logf("Exec 'echo hello': exitCode=%d output=%q", execResult.ExitCode, execResult.Output)

	// Test 2: Execute a failing command and verify non-zero exit code
	failResult, err := ExecCommand(ctx, client, sandboxName, "false")
	if err != nil {
		// Some SDKs return an error for non-zero exit codes; that's acceptable
		t.Logf("ExecCommand('false') returned error (acceptable): %v", err)
	} else {
		if failResult.ExitCode == 0 {
			t.Error("ExecCommand('false') ExitCode = 0, want non-zero")
		}
		t.Logf("Exec 'false': exitCode=%d output=%q", failResult.ExitCode, failResult.Output)
	}
}
