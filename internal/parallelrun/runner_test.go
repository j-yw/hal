package parallelrun

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/template"
	"github.com/jywlabs/hal/internal/worktree"
)

func TestRunnerRunsParallelWorkersFromIgnoredHalStateAndIntegratesSerially(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Add first file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds an independent file"
    },
    {
      "id": "T-002",
      "title": "Two",
      "description": "Add second file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 2,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds another independent file"
    }
  ]
}`)

	executor := &gitCommittingWorkerExecutor{delay: 50 * time.Millisecond}
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 2,
		Parallelism:   2,
		Engine:        "fake",
		Logger:        os.Stdout,
	}, Deps{Executor: executor}).Run(context.Background())

	if result.Error != nil {
		t.Fatalf("Run() error = %v", result.Error)
	}
	if !result.Success || !result.Complete {
		t.Fatalf("result success/complete = %v/%v, want true/true", result.Success, result.Complete)
	}
	if result.Iterations != 2 {
		t.Fatalf("iterations = %d, want 2", result.Iterations)
	}
	if result.Parallel.Batches != 1 || result.Parallel.Started != 2 || result.Parallel.Integrated != 2 {
		t.Fatalf("parallel summary = %+v, want one batch with two integrated workers", result.Parallel)
	}
	if executor.maxActive < 2 {
		t.Fatalf("workers did not overlap; max active = %d, want >= 2", executor.maxActive)
	}

	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-001", true)
	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-002", true)
	if got := readFile(t, filepath.Join(repo, template.HalDir, template.ProgressFile)); !strings.Contains(got, "T-001 complete") || !strings.Contains(got, "T-002 complete") {
		t.Fatalf("progress missing worker entries:\n%s", got)
	}
	if got := readFile(t, filepath.Join(repo, "T-001.txt")); !strings.Contains(got, "T-001") {
		t.Fatalf("T-001 implementation file = %q", got)
	}
	if got := readFile(t, filepath.Join(repo, "T-002.txt")); !strings.Contains(got, "T-002") {
		t.Fatalf("T-002 implementation file = %q", got)
	}
	if got := strings.TrimSpace(git(t, repo, "status", "--short", "--untracked-files=all")); got != "" {
		t.Fatalf("git status = %q, want clean", got)
	}
}

func TestRunnerRespectsDependenciesAcrossBatches(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Add first file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "First dependency"
    },
    {
      "id": "T-002",
      "title": "Two",
      "description": "Add second file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 2,
      "passes": false,
      "notes": "",
      "dependsOn": ["T-001"],
      "parallelSafe": true,
      "parallelReason": "Runs after T-001"
    }
  ]
}`)

	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 2,
		Parallelism:   2,
		Engine:        "fake",
		Logger:        os.Stdout,
	}, Deps{Executor: &gitCommittingWorkerExecutor{}}).Run(context.Background())

	if result.Error != nil {
		t.Fatalf("Run() error = %v", result.Error)
	}
	if !result.Complete {
		t.Fatalf("complete = false, summary = %+v", result.Parallel)
	}
	if result.Parallel.Batches != 2 {
		t.Fatalf("batches = %d, want 2 for dependency chain", result.Parallel.Batches)
	}
}

func TestRunnerRejectsInvalidSchedulingMetadataBeforeWorkersStart(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Invalid dependency",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "dependsOn": ["T-999"],
      "parallelSafe": true,
      "parallelReason": "Invalid"
    }
  ]
}`)

	executor := &gitCommittingWorkerExecutor{}
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 1,
		Parallelism:   2,
		Engine:        "fake",
	}, Deps{Executor: executor}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), "invalid PRD scheduling metadata") {
		t.Fatalf("error = %v, want invalid scheduling metadata", result.Error)
	}
	if executor.started != 0 {
		t.Fatalf("workers started = %d, want 0", executor.started)
	}
}

func TestRunnerRejectsMismatchedPRDBranchBeforeWorkersStart(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Add first file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds an independent file"
    }
  ]
}`)
	git(t, repo, "switch", "main")

	executor := &gitCommittingWorkerExecutor{}
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 1,
		Parallelism:   1,
		Engine:        "fake",
	}, Deps{Executor: executor}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), `canonical branch "main" does not match .hal/prd.json branchName "hal/parallel"`) {
		t.Fatalf("error = %v, want branch mismatch", result.Error)
	}
	if executor.started != 0 {
		t.Fatalf("workers started = %d, want 0", executor.started)
	}
	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-001", false)
}

func TestRunnerDryRunDoesNotCreateMissingProgressFile(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Preview first file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds an independent file"
    }
  ]
}`)
	progressPath := filepath.Join(repo, template.HalDir, template.ProgressFile)
	if err := os.Remove(progressPath); err != nil {
		t.Fatalf("remove progress fixture: %v", err)
	}

	executor := &gitCommittingWorkerExecutor{}
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 1,
		Parallelism:   1,
		DryRun:        true,
		Engine:        "fake",
	}, Deps{Executor: executor}).Run(context.Background())

	if result.Error != nil {
		t.Fatalf("Run() error = %v", result.Error)
	}
	if !result.Success || result.Complete {
		t.Fatalf("success/complete = %v/%v, want true/false", result.Success, result.Complete)
	}
	if executor.started != 0 {
		t.Fatalf("workers started = %d, want 0", executor.started)
	}
	if _, err := os.Stat(progressPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("progress stat err = %v, want not exist", err)
	}
}

func TestRunnerSetupFailureDoesNotCountWorkersAsStarted(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Add first file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds an independent file"
    },
    {
      "id": "T-002",
      "title": "Two",
      "description": "Add second file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 2,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds another independent file"
    }
  ]
}`)

	executor := &gitCommittingWorkerExecutor{}
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 2,
		Parallelism:   2,
		Engine:        "fake",
	}, Deps{
		Worktrees: failingWorktreeManager{err: errors.New("worker path collision")},
		Executor:  executor,
	}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), "worker path collision") {
		t.Fatalf("error = %v, want worker path collision", result.Error)
	}
	if result.Iterations != 0 {
		t.Fatalf("iterations = %d, want 0", result.Iterations)
	}
	if result.Parallel.Started != 0 || result.Parallel.Failed != 1 || result.Parallel.Integrated != 0 {
		t.Fatalf("parallel summary = %+v, want started=0 failed=1 integrated=0", result.Parallel)
	}
	if executor.started != 0 {
		t.Fatalf("executor starts = %d, want 0", executor.started)
	}
}

func TestRunnerSetupFailureAfterPreparedWorktreeReturnsErrorBeforeManifestRead(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Add first file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds an independent file"
    },
    {
      "id": "T-002",
      "title": "Two",
      "description": "Add second file",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 2,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Adds another independent file"
    }
  ]
}`)

	executor := &gitCommittingWorkerExecutor{}
	manager := &failOnCreateWorktreeManager{
		delegate: worktree.NewManager(worktree.Config{RepoPath: repo}),
		failAt:   2,
		err:      errors.New("second worker path collision"),
	}
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 2,
		Parallelism:   2,
		Engine:        "fake",
	}, Deps{
		Worktrees: manager,
		Executor:  executor,
	}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), "second worker path collision") {
		t.Fatalf("error = %v, want second worker setup failure", result.Error)
	}
	if result.LastStoryID != "T-002" {
		t.Fatalf("last story ID = %q, want T-002", result.LastStoryID)
	}
	if result.Iterations != 0 {
		t.Fatalf("iterations = %d, want 0", result.Iterations)
	}
	if result.Parallel.Started != 0 || result.Parallel.Failed != 1 || result.Parallel.Integrated != 0 {
		t.Fatalf("parallel summary = %+v, want started=0 failed=1 integrated=0", result.Parallel)
	}
	if executor.started != 0 {
		t.Fatalf("executor starts = %d, want 0", executor.started)
	}
	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-001", false)
	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-002", false)
	if got := strings.TrimSpace(git(t, repo, "status", "--short", "--untracked-files=all")); got != "" {
		t.Fatalf("canonical git status = %q, want clean", got)
	}
}

func TestRunnerRejectsWorkerFileWithoutManifest(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Create an implementation file without a manifest",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Independent file"
    }
  ]
}`)

	var workerPath string
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 1,
		Parallelism:   1,
		Engine:        "fake",
	}, Deps{
		Executor: workerExecutorFunc(func(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult {
			workerPath = req.WorktreePath
			if err := os.WriteFile(filepath.Join(req.WorktreePath, "T-001.txt"), []byte("implemented\n"), 0o644); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			return WorkerExecutionResult{EngineResult: engine.Result{Success: true}}
		}),
	}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), "read worker manifest for T-001") {
		t.Fatalf("error = %v, want missing worker manifest", result.Error)
	}
	if result.Parallel.Started != 1 || result.Parallel.Integrated != 0 || result.Parallel.Failed != 1 {
		t.Fatalf("parallel summary = %+v, want started=1 integrated=0 failed=1", result.Parallel)
	}
	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-001", false)
	if got := strings.TrimSpace(git(t, repo, "status", "--short", "--untracked-files=all")); got != "" {
		t.Fatalf("canonical git status = %q, want clean", got)
	}
	if workerPath == "" {
		t.Fatal("worker path was not captured")
	}
	if _, err := os.Stat(workerPath); err != nil {
		t.Fatalf("failed worker worktree stat err = %v, want preserved", err)
	}
	if got := readFile(t, filepath.Join(workerPath, "T-001.txt")); !strings.Contains(got, "implemented") {
		t.Fatalf("failed worker file = %q, want preserved implementation", got)
	}
}

func TestRunnerRejectsManifestCommitThatIsNotWorkerBranchTip(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Create two commits but report the stale one",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Independent file"
    }
  ]
}`)

	var workerPath string
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 1,
		Parallelism:   1,
		Engine:        "fake",
	}, Deps{
		Executor: workerExecutorFunc(func(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult {
			workerPath = req.WorktreePath
			first := filepath.Join(req.WorktreePath, "T-001-first.txt")
			if err := os.WriteFile(first, []byte("first\n"), 0o644); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			if _, err := gitOutputForTest(req.WorktreePath, "add", "T-001-first.txt"); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			if _, err := gitOutputForTest(req.WorktreePath, "commit", "-m", "feat: stale T-001"); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			staleCommit, err := gitOutputForTest(req.WorktreePath, "rev-parse", "HEAD")
			if err != nil {
				return WorkerExecutionResult{Error: err}
			}
			staleCommit = strings.TrimSpace(staleCommit)

			second := filepath.Join(req.WorktreePath, "T-001-final.txt")
			if err := os.WriteFile(second, []byte("final\n"), 0o644); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			if _, err := gitOutputForTest(req.WorktreePath, "add", "T-001-final.txt"); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			if _, err := gitOutputForTest(req.WorktreePath, "commit", "-m", "feat: final T-001"); err != nil {
				return WorkerExecutionResult{Error: err}
			}

			manifest := loop.WorkerManifest{
				TaskID:        req.Task.ID,
				Status:        loop.WorkerManifestStatusReadyForIntegration,
				Branch:        req.Assignment.BranchName,
				Commit:        staleCommit,
				Checks:        []string{"fake check"},
				FilesChanged:  []string{"T-001-first.txt", "T-001-final.txt"},
				ProgressEntry: "- " + req.Task.ID + " complete",
				Notes:         "stale manifest commit",
			}
			if err := loop.WriteWorkerManifest(req.ManifestPath, manifest); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			return WorkerExecutionResult{
				EngineResult: engine.Result{Success: true},
				Manifest:     &manifest,
			}
		}),
	}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), "manifest commit") || !strings.Contains(result.Error.Error(), "want worker branch") {
		t.Fatalf("error = %v, want stale manifest commit rejection", result.Error)
	}
	if result.Parallel.Started != 1 || result.Parallel.Integrated != 0 || result.Parallel.Failed != 1 {
		t.Fatalf("parallel summary = %+v, want started=1 integrated=0 failed=1", result.Parallel)
	}
	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-001", false)
	if got := strings.TrimSpace(git(t, repo, "status", "--short", "--untracked-files=all")); got != "" {
		t.Fatalf("canonical git status = %q, want clean", got)
	}
	if workerPath == "" {
		t.Fatal("worker path was not captured")
	}
	if _, err := os.Stat(workerPath); err != nil {
		t.Fatalf("failed worker worktree stat err = %v, want preserved", err)
	}
}

func TestRunnerRejectsDirtyWorkerWorktreeBeforeIntegration(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Leave uncommitted worker edits behind",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Independent file"
    }
  ]
}`)

	var workerPath string
	result := New(Config{
		RepoDir:       repo,
		RunID:         "test-run",
		MaxIterations: 1,
		Parallelism:   1,
		Engine:        "fake",
	}, Deps{
		Executor: workerExecutorFunc(func(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult {
			workerPath = req.WorktreePath
			committed := filepath.Join(req.WorktreePath, "T-001.txt")
			if err := os.WriteFile(committed, []byte("committed\n"), 0o644); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			if _, err := gitOutputForTest(req.WorktreePath, "add", "T-001.txt"); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			if _, err := gitOutputForTest(req.WorktreePath, "commit", "-m", "feat: T-001 committed"); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			commit, err := gitOutputForTest(req.WorktreePath, "rev-parse", "HEAD")
			if err != nil {
				return WorkerExecutionResult{Error: err}
			}
			commit = strings.TrimSpace(commit)

			if err := os.WriteFile(filepath.Join(req.WorktreePath, "left-behind.txt"), []byte("uncommitted\n"), 0o644); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			manifest := loop.WorkerManifest{
				TaskID:        req.Task.ID,
				Status:        loop.WorkerManifestStatusReadyForIntegration,
				Branch:        req.Assignment.BranchName,
				Commit:        commit,
				Checks:        []string{"fake check"},
				FilesChanged:  []string{"T-001.txt", "left-behind.txt"},
				ProgressEntry: "- " + req.Task.ID + " complete",
				Notes:         "ready with dirty worktree",
			}
			if err := loop.WriteWorkerManifest(req.ManifestPath, manifest); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			return WorkerExecutionResult{
				EngineResult: engine.Result{Success: true},
				Manifest:     &manifest,
			}
		}),
	}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), "worktree has uncommitted changes") {
		t.Fatalf("error = %v, want dirty worktree rejection", result.Error)
	}
	if result.Parallel.Started != 1 || result.Parallel.Integrated != 0 || result.Parallel.Failed != 1 {
		t.Fatalf("parallel summary = %+v, want started=1 integrated=0 failed=1", result.Parallel)
	}
	requireTaskPasses(t, filepath.Join(repo, template.HalDir, template.PRDFile), "T-001", false)
	if got := strings.TrimSpace(git(t, repo, "status", "--short", "--untracked-files=all")); got != "" {
		t.Fatalf("canonical git status = %q, want clean", got)
	}
	if workerPath == "" {
		t.Fatal("worker path was not captured")
	}
	if got := strings.TrimSpace(git(t, workerPath, "status", "--short", "--untracked-files=all")); !strings.Contains(got, "left-behind.txt") {
		t.Fatalf("worker git status = %q, want left-behind.txt", got)
	}
}

func TestRunnerExplicitCleanupRemovesFailedWorkerWorktree(t *testing.T) {
	repo := initParallelRunRepo(t)
	writeParallelRuntime(t, repo, `{
  "project": "parallel",
  "branchName": "hal/parallel",
  "description": "parallel test",
  "tasks": [
    {
      "id": "T-001",
      "title": "One",
      "description": "Create an implementation file without a manifest",
      "acceptanceCriteria": ["Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": "",
      "parallelSafe": true,
      "parallelReason": "Independent file"
    }
  ]
}`)

	var workerPath string
	result := New(Config{
		RepoDir:                repo,
		RunID:                  "test-run",
		MaxIterations:          1,
		Parallelism:            1,
		Engine:                 "fake",
		CleanupFailedWorktrees: true,
	}, Deps{
		Executor: workerExecutorFunc(func(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult {
			workerPath = req.WorktreePath
			if err := os.WriteFile(filepath.Join(req.WorktreePath, "T-001.txt"), []byte("implemented\n"), 0o644); err != nil {
				return WorkerExecutionResult{Error: err}
			}
			return WorkerExecutionResult{EngineResult: engine.Result{Success: true}}
		}),
	}).Run(context.Background())

	if result.Error == nil || !strings.Contains(result.Error.Error(), "read worker manifest for T-001") {
		t.Fatalf("error = %v, want missing worker manifest", result.Error)
	}
	if workerPath == "" {
		t.Fatal("worker path was not captured")
	}
	if _, err := os.Stat(workerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed worker worktree stat err = %v, want removed", err)
	}
}

func TestCleanupFailedBatchPreservesByDefaultWithoutForce(t *testing.T) {
	manager := &recordingCleanupManager{}
	cleanupFailedBatch(context.Background(), Config{}, manager, []batchWorkerResult{
		{
			worktree: worktree.CreateResult{
				WorktreePath: "/tmp/hal-worker",
				BranchName:   "hal/runs/test/T-001",
			},
			err: errors.New("worker failed"),
		},
	})

	if len(manager.requests) != 1 {
		t.Fatalf("cleanup requests = %d, want 1", len(manager.requests))
	}
	got := manager.requests[0]
	if !got.Failed || !got.PreserveFailed || got.Force {
		t.Fatalf("cleanup request = %+v, want failed preserved without force", got)
	}
}

func TestCleanupFailedBatchExplicitCleanupUsesForce(t *testing.T) {
	manager := &recordingCleanupManager{}
	cleanupFailedBatch(context.Background(), Config{CleanupFailedWorktrees: true}, manager, []batchWorkerResult{
		{
			worktree: worktree.CreateResult{
				WorktreePath: "/tmp/hal-worker",
				BranchName:   "hal/runs/test/T-001",
			},
			err: errors.New("worker failed"),
		},
	})

	if len(manager.requests) != 1 {
		t.Fatalf("cleanup requests = %d, want 1", len(manager.requests))
	}
	got := manager.requests[0]
	if !got.Failed || got.PreserveFailed || !got.Force {
		t.Fatalf("cleanup request = %+v, want explicit cleanup with force", got)
	}
}

func TestValidateWorkerManifestGatesIntegration(t *testing.T) {
	valid := func() *loop.WorkerManifest {
		return &loop.WorkerManifest{
			TaskID:        "T-001",
			Status:        loop.WorkerManifestStatusReadyForIntegration,
			Branch:        "hal/runs/test/T-001",
			Commit:        "abc123",
			ProgressEntry: "- T-001 complete",
		}
	}

	tests := []struct {
		name    string
		edit    func(*loop.WorkerManifest) *loop.WorkerManifest
		wantErr string
	}{
		{
			name: "nil manifest",
			edit: func(*loop.WorkerManifest) *loop.WorkerManifest {
				return nil
			},
			wantErr: "worker manifest is required",
		},
		{
			name: "in progress status",
			edit: func(m *loop.WorkerManifest) *loop.WorkerManifest {
				m.Status = "in_progress"
				return m
			},
			wantErr: `manifest status = "in_progress"`,
		},
		{
			name: "branch mismatch",
			edit: func(m *loop.WorkerManifest) *loop.WorkerManifest {
				m.Branch = "hal/runs/test/other"
				return m
			},
			wantErr: `manifest branch = "hal/runs/test/other"`,
		},
		{
			name: "missing commit",
			edit: func(m *loop.WorkerManifest) *loop.WorkerManifest {
				m.Commit = ""
				return m
			},
			wantErr: "manifest commit is required",
		},
		{
			name: "missing progress entry",
			edit: func(m *loop.WorkerManifest) *loop.WorkerManifest {
				m.ProgressEntry = ""
				return m
			},
			wantErr: "manifest progressEntry is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkerManifest(tt.edit(valid()), "T-001", "hal/runs/test/T-001")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

type failingWorktreeManager struct {
	err error
}

func (m failingWorktreeManager) Create(context.Context, worktree.CreateRequest) (worktree.CreateResult, error) {
	return worktree.CreateResult{}, m.err
}

func (m failingWorktreeManager) Cleanup(context.Context, worktree.CleanupRequest) (worktree.CleanupResult, error) {
	return worktree.CleanupResult{}, nil
}

type failOnCreateWorktreeManager struct {
	delegate worktreeManager
	failAt   int
	err      error
	calls    int
}

func (m *failOnCreateWorktreeManager) Create(ctx context.Context, request worktree.CreateRequest) (worktree.CreateResult, error) {
	m.calls++
	if m.calls == m.failAt {
		return worktree.CreateResult{}, m.err
	}
	return m.delegate.Create(ctx, request)
}

func (m *failOnCreateWorktreeManager) Cleanup(ctx context.Context, request worktree.CleanupRequest) (worktree.CleanupResult, error) {
	return m.delegate.Cleanup(ctx, request)
}

type recordingCleanupManager struct {
	requests []worktree.CleanupRequest
}

func (m *recordingCleanupManager) Create(context.Context, worktree.CreateRequest) (worktree.CreateResult, error) {
	return worktree.CreateResult{}, errors.New("unexpected create")
}

func (m *recordingCleanupManager) Cleanup(_ context.Context, request worktree.CleanupRequest) (worktree.CleanupResult, error) {
	m.requests = append(m.requests, request)
	return worktree.CleanupResult{}, nil
}

type gitCommittingWorkerExecutor struct {
	delay     time.Duration
	mu        sync.Mutex
	active    int
	maxActive int
	started   int
}

func (e *gitCommittingWorkerExecutor) ExecuteWorker(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult {
	e.mu.Lock()
	e.started++
	e.active++
	if e.active > e.maxActive {
		e.maxActive = e.active
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.active--
		e.mu.Unlock()
	}()

	if _, err := os.Stat(filepath.Join(req.WorktreePath, template.HalDir, template.PRDFile)); err != nil {
		return WorkerExecutionResult{Error: err}
	}
	if _, err := os.Stat(filepath.Join(req.WorktreePath, template.HalDir, template.PromptFile)); err != nil {
		return WorkerExecutionResult{Error: err}
	}
	if req.Assignment.ManifestFile == "" {
		return WorkerExecutionResult{Error: os.ErrInvalid}
	}
	if e.delay > 0 {
		select {
		case <-ctx.Done():
			return WorkerExecutionResult{Error: ctx.Err()}
		case <-time.After(e.delay):
		}
	}

	filename := req.Task.ID + ".txt"
	if err := os.WriteFile(filepath.Join(req.WorktreePath, filename), []byte(req.Task.ID+"\n"), 0o644); err != nil {
		return WorkerExecutionResult{Error: err}
	}
	if _, err := gitOutputForTest(req.WorktreePath, "add", filename); err != nil {
		return WorkerExecutionResult{Error: err}
	}
	if _, err := gitOutputForTest(req.WorktreePath, "commit", "-m", "feat: "+req.Task.ID); err != nil {
		return WorkerExecutionResult{Error: err}
	}
	commit, err := gitOutputForTest(req.WorktreePath, "rev-parse", "HEAD")
	if err != nil {
		return WorkerExecutionResult{Error: err}
	}
	commit = strings.TrimSpace(commit)

	manifest := loop.WorkerManifest{
		TaskID:        req.Task.ID,
		Status:        loop.WorkerManifestStatusReadyForIntegration,
		Branch:        req.Assignment.BranchName,
		Commit:        commit,
		Checks:        []string{"fake check"},
		FilesChanged:  []string{filename},
		ProgressEntry: "- " + req.Task.ID + " complete",
		Notes:         "ready",
	}
	if err := loop.WriteWorkerManifest(req.ManifestPath, manifest); err != nil {
		return WorkerExecutionResult{Error: err}
	}
	return WorkerExecutionResult{
		EngineResult: engine.Result{Success: true},
		Manifest:     &manifest,
	}
}

func initParallelRunRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init", "-b", "main")
	git(t, repo, "config", "user.name", "Hal Test")
	git(t, repo, "config", "user.email", "hal-test@example.com")
	writeFile(t, filepath.Join(repo, ".gitignore"), ".hal/*\n.worktrees/\n")
	writeFile(t, filepath.Join(repo, "README.md"), "seed\n")
	git(t, repo, "add", ".gitignore", "README.md")
	git(t, repo, "commit", "-m", "initial")
	git(t, repo, "switch", "-c", "hal/parallel")
	return repo
}

func writeParallelRuntime(t *testing.T, repo, prdJSON string) {
	t.Helper()
	halDir := filepath.Join(repo, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(t, filepath.Join(halDir, template.PRDFile), prdJSON+"\n")
	writeFile(t, filepath.Join(halDir, template.ProgressFile), "## Progress\n")
	writeFile(t, filepath.Join(halDir, template.PromptFile), "Prompt {{PRD_FILE}} {{PROGRESS_FILE}}\n")
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func gitOutputForTest(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func requireTaskPasses(t *testing.T, path, taskID string, want bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read PRD: %v", err)
	}
	var doc struct {
		Tasks []struct {
			ID     string `json:"id"`
			Passes bool   `json:"passes"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse PRD: %v\n%s", err, string(data))
	}
	for _, task := range doc.Tasks {
		if task.ID == taskID {
			if task.Passes != want {
				t.Fatalf("%s passes = %v, want %v", taskID, task.Passes, want)
			}
			return
		}
	}
	t.Fatalf("task %s not found", taskID)
}
