package cmd

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

type stubDeleteProvider struct {
	deleteFn func(context.Context, *sandbox.ConnectInfo, io.Writer) error
}

func (p *stubDeleteProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, errors.New("unexpected Create call")
}

func (p *stubDeleteProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return errors.New("unexpected Stop call")
}

func (p *stubDeleteProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	if p.deleteFn != nil {
		return p.deleteFn(ctx, info, out)
	}
	return nil
}

func (p *stubDeleteProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, errors.New("unexpected SSH call")
}

func (p *stubDeleteProvider) Exec(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
	return nil, errors.New("unexpected Exec call")
}

func (p *stubDeleteProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return errors.New("unexpected Status call")
}

func TestReplaceExistingSandbox_RemovesMatchingLocalState(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(t.TempDir())
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(projectDir, "config"))

	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	existing := &sandbox.SandboxState{
		ID:          "sandbox-id",
		Name:        "test-box",
		Provider:    "hetzner",
		WorkspaceID: "ws-123",
		Status:      sandbox.StatusRunning,
		CreatedAt:   time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("SaveInstance: %v", err)
	}
	if err := sandbox.SaveState(halDir, existing); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	provider := &stubDeleteProvider{
		deleteFn: func(_ context.Context, info *sandbox.ConnectInfo, _ io.Writer) error {
			if info == nil {
				t.Fatal("Delete info = nil")
			}
			if info.Name != existing.Name {
				t.Fatalf("Delete info.Name = %q, want %q", info.Name, existing.Name)
			}
			if info.WorkspaceID != existing.WorkspaceID {
				t.Fatalf("Delete info.WorkspaceID = %q, want %q", info.WorkspaceID, existing.WorkspaceID)
			}
			return nil
		},
	}

	if err := replaceExistingSandbox(existing, provider, existing.Provider, halDir, io.Discard); err != nil {
		t.Fatalf("replaceExistingSandbox() unexpected error: %v", err)
	}

	if _, err := sandbox.LoadInstance(existing.Name); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadInstance() err = %v, want fs.ErrNotExist", err)
	}
	if _, err := os.Stat(filepath.Join(halDir, template.SandboxFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("sandbox.json stat err = %v, want fs.ErrNotExist", err)
	}
}

func TestReplaceExistingSandbox_ContinuesWhenLocalCleanupFails(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(projectDir, "config"))

	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(filepath.Join(halDir, template.SandboxFile), 0o755); err != nil {
		t.Fatalf("MkdirAll sandbox path: %v", err)
	}

	existing := &sandbox.SandboxState{
		ID:          "sandbox-id",
		Name:        "test-box",
		Provider:    "hetzner",
		WorkspaceID: "ws-123",
		Status:      sandbox.StatusRunning,
		CreatedAt:   time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("SaveInstance: %v", err)
	}

	provider := &stubDeleteProvider{
		deleteFn: func(_ context.Context, info *sandbox.ConnectInfo, _ io.Writer) error {
			if info == nil {
				t.Fatal("Delete info = nil")
			}
			if info.Name != existing.Name {
				t.Fatalf("Delete info.Name = %q, want %q", info.Name, existing.Name)
			}
			return nil
		},
	}

	if err := replaceExistingSandbox(existing, provider, existing.Provider, halDir, io.Discard); err != nil {
		t.Fatalf("replaceExistingSandbox() unexpected error: %v", err)
	}

	if _, err := sandbox.LoadInstance(existing.Name); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadInstance() err = %v, want fs.ErrNotExist", err)
	}
}

func TestReplaceExistingSandbox_RestoresRegistryWhenDeleteFails(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(projectDir, "config"))

	existing := &sandbox.SandboxState{
		ID:          "sandbox-id",
		Name:        "test-box",
		Provider:    "hetzner",
		WorkspaceID: "ws-123",
		Status:      sandbox.StatusRunning,
		CreatedAt:   time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("SaveInstance: %v", err)
	}

	provider := &stubDeleteProvider{
		deleteFn: func(_ context.Context, _ *sandbox.ConnectInfo, _ io.Writer) error {
			return errors.New("provider delete failed")
		},
	}

	err := replaceExistingSandbox(existing, provider, existing.Provider, filepath.Join(projectDir, template.HalDir), io.Discard)
	if err == nil {
		t.Fatal("replaceExistingSandbox() error = nil, want error")
	}

	loaded, loadErr := sandbox.LoadInstance(existing.Name)
	if loadErr != nil {
		t.Fatalf("LoadInstance() unexpected error after rollback: %v", loadErr)
	}
	if loaded.Name != existing.Name {
		t.Fatalf("loaded Name = %q, want %q", loaded.Name, existing.Name)
	}
}

func TestReplaceExistingSandbox_FailsWhenCommitFails(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(projectDir, "config"))

	existing := &sandbox.SandboxState{
		ID:          "sandbox-id",
		Name:        "test-box",
		Provider:    "hetzner",
		WorkspaceID: "ws-123",
		Status:      sandbox.StatusRunning,
		CreatedAt:   time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("SaveInstance: %v", err)
	}

	origStage := sandboxStartStageInstanceRemoval
	sandboxStartStageInstanceRemoval = func(name string) (sandboxStartPendingRemoval, error) {
		inner, err := sandbox.StageInstanceRemoval(name)
		if err != nil {
			return nil, err
		}
		return &mockDeletePendingRemoval{
			inner:     inner,
			commitErr: errors.New("registry unavailable"),
		}, nil
	}
	t.Cleanup(func() {
		sandboxStartStageInstanceRemoval = origStage
	})

	err := replaceExistingSandbox(existing, &stubDeleteProvider{}, existing.Provider, filepath.Join(projectDir, template.HalDir), io.Discard)
	if err == nil {
		t.Fatal("replaceExistingSandbox() error = nil, want error")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "failed to finalize registry cleanup") {
		t.Fatalf("error %q should include finalize failure", got)
	}
}

func TestUpdateStoppedState_SyncsMatchingLocalState(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)

	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	stoppedAt := time.Date(2026, 3, 26, 13, 0, 0, 0, time.UTC)
	target := &sandbox.SandboxState{
		ID:          "sandbox-id",
		Name:        "test-box",
		Provider:    "hetzner",
		WorkspaceID: "ws-123",
		Status:      sandbox.StatusRunning,
		CreatedAt:   stoppedAt.Add(-time.Hour),
	}
	if err := sandbox.SaveState(halDir, target); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	origNow := sandboxStopNow
	origWrite := sandboxStopForceWrite
	sandboxStopNow = func() time.Time { return stoppedAt }
	sandboxStopForceWrite = func(*sandbox.SandboxState) error { return nil }
	t.Cleanup(func() {
		sandboxStopNow = origNow
		sandboxStopForceWrite = origWrite
	})

	if err := updateStoppedState(target); err != nil {
		t.Fatalf("updateStoppedState() unexpected error: %v", err)
	}

	local, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if local.Status != sandbox.StatusStopped {
		t.Fatalf("local Status = %q, want %q", local.Status, sandbox.StatusStopped)
	}
	if local.StoppedAt == nil || !local.StoppedAt.Equal(stoppedAt) {
		t.Fatalf("local StoppedAt = %v, want %v", local.StoppedAt, stoppedAt)
	}
}

func TestPersistLiveStatus_SyncsMatchingLocalState(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)

	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	now := time.Date(2026, 3, 26, 14, 0, 0, 0, time.UTC)
	inst := &sandbox.SandboxState{
		ID:          "sandbox-id",
		Name:        "dev-box",
		Provider:    "daytona",
		WorkspaceID: "ws-456",
		Status:      sandbox.StatusRunning,
		CreatedAt:   now.Add(-2 * time.Hour),
	}
	if err := sandbox.SaveState(halDir, inst); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	writeCalls := 0
	if err := persistLiveStatus(inst, sandbox.StatusStopped, now, func(*sandbox.SandboxState) error {
		writeCalls++
		return nil
	}); err != nil {
		t.Fatalf("persistLiveStatus() unexpected error: %v", err)
	}
	if writeCalls != 1 {
		t.Fatalf("writeCalls = %d, want 1", writeCalls)
	}

	local, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if local.Status != sandbox.StatusStopped {
		t.Fatalf("local Status = %q, want %q", local.Status, sandbox.StatusStopped)
	}
	if local.StoppedAt == nil || !local.StoppedAt.Equal(now) {
		t.Fatalf("local StoppedAt = %v, want %v", local.StoppedAt, now)
	}
}
