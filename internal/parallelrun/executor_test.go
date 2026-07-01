package parallelrun

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
)

func TestEngineWorkerExecutorAcceptsValidManifestWithoutTerminalSuccessEvent(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), ".hal", "parallel", "test-run", "T-004", "worker-manifest.json")
	want := loop.WorkerManifest{
		TaskID:        "T-004",
		Status:        loop.WorkerManifestStatusReadyForIntegration,
		Branch:        "hal/parallel-worker-T-004",
		Commit:        "abc123",
		Checks:        []string{"go test ./..."},
		FilesChanged:  []string{"real-auto-ui.txt"},
		ProgressEntry: "- T-004 complete",
		Notes:         "ready",
	}

	executor := EngineWorkerExecutor{
		NewEngine: func(_ string, cfg *engine.EngineConfig) (engine.Engine, error) {
			if cfg.WorkDir != "/tmp/worker" {
				t.Fatalf("WorkDir = %q, want worker worktree", cfg.WorkDir)
			}
			return fakeWorkerEngine{
				execute: func(context.Context, string, *engine.Display) engine.Result {
					if err := loop.WriteWorkerManifest(manifestPath, want); err != nil {
						t.Fatalf("WriteWorkerManifest() error = %v", err)
					}
					return engine.Result{}
				},
			}, nil
		},
	}

	got := executor.ExecuteWorker(context.Background(), WorkerExecutionRequest{
		Assignment: loop.WorkerAssignment{
			TaskID:     "T-004",
			BranchName: "hal/parallel-worker-T-004",
		},
		WorktreePath: "/tmp/worker",
		ManifestPath: manifestPath,
		Engine:       "fake",
	})

	if got.Error != nil {
		t.Fatalf("ExecuteWorker() error = %v", got.Error)
	}
	if got.Manifest == nil {
		t.Fatal("ExecuteWorker() manifest = nil")
	}
	if got.Manifest.TaskID != want.TaskID || got.Manifest.Branch != want.Branch || got.Manifest.FilesChanged[0] != want.FilesChanged[0] {
		t.Fatalf("manifest = %+v, want %+v", got.Manifest, want)
	}
	if got.EngineResult.Success || got.EngineResult.Complete {
		t.Fatalf("engine result success/complete = %v/%v, want false/false", got.EngineResult.Success, got.EngineResult.Complete)
	}
}

type fakeWorkerEngine struct {
	execute func(context.Context, string, *engine.Display) engine.Result
}

func (e fakeWorkerEngine) Name() string {
	return "fake"
}

func (e fakeWorkerEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return e.execute(ctx, prompt, display)
}

func (e fakeWorkerEngine) Prompt(context.Context, string) (string, error) {
	return "", nil
}

func (e fakeWorkerEngine) StreamPrompt(context.Context, string, *engine.Display) (string, error) {
	return "", nil
}
