package sandbox

import (
	"testing"
	"time"
)

func TestNewClientMissingKey(t *testing.T) {
	// SDK requires a non-empty API key at client creation time.
	_, err := NewClient("", "")
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}

func TestNewClientWithServerURL(t *testing.T) {
	client, err := NewClient("test-key", "https://custom.example.com/api")
	if err != nil {
		t.Fatalf("NewClient returned unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestSandboxStateFields(t *testing.T) {
	now := time.Now()
	state := SandboxState{
		Name:        "test-sandbox",
		SnapshotID:  "snap-123",
		WorkspaceID: "ws-456",
		Status:      "running",
		CreatedAt:   now,
	}

	if state.Name != "test-sandbox" {
		t.Errorf("Name = %q, want %q", state.Name, "test-sandbox")
	}
	if state.SnapshotID != "snap-123" {
		t.Errorf("SnapshotID = %q, want %q", state.SnapshotID, "snap-123")
	}
	if state.WorkspaceID != "ws-456" {
		t.Errorf("WorkspaceID = %q, want %q", state.WorkspaceID, "ws-456")
	}
	if state.Status != "running" {
		t.Errorf("Status = %q, want %q", state.Status, "running")
	}
	if !state.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", state.CreatedAt, now)
	}
}
