package cmd

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

type mockCreatePendingRemoval struct {
	alreadyStaged bool
	commitCalls   int
	rollbackCalls int
}

func (m *mockCreatePendingRemoval) Commit() error {
	m.commitCalls++
	return nil
}

func (m *mockCreatePendingRemoval) Rollback() error {
	m.rollbackCalls++
	return nil
}

func (m *mockCreatePendingRemoval) AlreadyStaged() bool {
	return m.alreadyStaged
}

func TestReplaceExistingSandbox_CommitsInterruptedDeleteRetry(t *testing.T) {
	t.Chdir(t.TempDir())

	pending := &mockCreatePendingRemoval{alreadyStaged: true}
	originalStage := sandboxCreateStageInstanceRemoval
	sandboxCreateStageInstanceRemoval = func(name string) (sandboxCreatePendingRemoval, error) {
		if name != "frontend" {
			t.Fatalf("staged removal name = %q, want %q", name, "frontend")
		}
		return pending, nil
	}
	t.Cleanup(func() {
		sandboxCreateStageInstanceRemoval = originalStage
	})

	provider := &mockProvider{deleteErr: errors.New("API error: sandbox not found")}
	out := new(bytes.Buffer)

	err := replaceExistingSandbox(&sandbox.SandboxState{
		ID:          "ws-123",
		Name:        "frontend",
		Provider:    "daytona",
		WorkspaceID: "ws-123",
	}, provider, "daytona", "", "", out)
	if err != nil {
		t.Fatalf("replaceExistingSandbox() unexpected error: %v", err)
	}
	if pending.commitCalls != 1 {
		t.Fatalf("Commit() calls = %d, want 1", pending.commitCalls)
	}
	if pending.rollbackCalls != 0 {
		t.Fatalf("Rollback() calls = %d, want 0", pending.rollbackCalls)
	}
	if len(provider.deleteCalls) != 1 {
		t.Fatalf("Delete() calls = %d, want 1", len(provider.deleteCalls))
	}
}
