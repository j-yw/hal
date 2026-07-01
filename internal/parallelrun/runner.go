package parallelrun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/integrator"
	"github.com/jywlabs/hal/internal/loop"
	prdvalidator "github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/taskgraph"
	"github.com/jywlabs/hal/internal/template"
	"github.com/jywlabs/hal/internal/worktree"
)

const defaultRunIDTimeFormat = "20060102-150405.000000000"

// Config controls one parallel run against a canonical Hal workspace.
type Config struct {
	RepoDir         string
	HalDir          string
	PRDFile         string
	ProgressFile    string
	BaseBranch      string
	CanonicalBranch string

	MaxIterations int
	Parallelism   int
	DryRun        bool

	Engine       string
	EngineConfig *engine.EngineConfig
	Logger       io.Writer
	RetryDelay   time.Duration
	MaxRetries   int

	RunID             string
	WorktreeRoot      string
	BranchPrefix      string
	CheckCommands     []integrator.CheckCommand
	CommitBookkeeping bool

	PreserveFailedWorktrees bool
	RemoveWorkerBranches    bool
}

// Summary is safe aggregate telemetry for a parallel run.
type Summary struct {
	RunID                string
	RequestedParallelism int
	Batches              int
	Started              int
	Integrated           int
	Failed               int
	SerialCandidates     int
	Blocked              int
}

// Result describes a parallel run and can be adapted to loop.Result for
// existing command and auto pipeline contracts.
type Result struct {
	Iterations       int
	Complete         bool
	Success          bool
	Error            error
	Duration         time.Duration
	CompletedStories int
	TotalStories     int
	LastStoryID      string
	LastStoryTitle   string
	Parallel         Summary
}

// LoopResult converts the parallel result into the legacy loop result shape.
func (r Result) LoopResult() loop.Result {
	return loop.Result{
		Iterations:       r.Iterations,
		Complete:         r.Complete,
		Success:          r.Success,
		Error:            r.Error,
		Duration:         r.Duration,
		CompletedStories: r.CompletedStories,
		TotalStories:     r.TotalStories,
		LastStoryID:      r.LastStoryID,
		LastStoryTitle:   r.LastStoryTitle,
	}
}

// WorkerExecutionRequest is the worker executor boundary.
type WorkerExecutionRequest struct {
	Task         engine.UserStory
	Assignment   loop.WorkerAssignment
	WorktreePath string
	ManifestPath string
	Engine       string
	EngineConfig *engine.EngineConfig
	Logger       io.Writer
}

// WorkerExecutionResult is returned by a worker executor.
type WorkerExecutionResult struct {
	EngineResult engine.Result
	Manifest     *loop.WorkerManifest
	Error        error
}

// WorkerExecutor runs one assigned worker task inside an isolated worktree.
type WorkerExecutor interface {
	ExecuteWorker(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult
}

type workerExecutorFunc func(context.Context, WorkerExecutionRequest) WorkerExecutionResult

func (f workerExecutorFunc) ExecuteWorker(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult {
	return f(ctx, req)
}

type runIntegrator interface {
	Integrate(context.Context, integrator.Request) (integrator.Result, error)
}

type worktreeManager interface {
	Create(context.Context, worktree.CreateRequest) (worktree.CreateResult, error)
	Cleanup(context.Context, worktree.CleanupRequest) (worktree.CleanupResult, error)
}

// Deps contains test seams for git worktrees, worker execution, integration,
// and time.
type Deps struct {
	Worktrees  worktreeManager
	Executor   WorkerExecutor
	Integrator runIntegrator
	Now        func() time.Time
}

// Runner coordinates safe parallel worker execution and serial integration.
type Runner struct {
	config Config
	deps   Deps
}

// New creates a parallel runner.
func New(config Config, deps Deps) *Runner {
	return &Runner{config: config, deps: deps}
}

// Run executes pending PRD tasks with isolated worker worktrees.
func (r *Runner) Run(ctx context.Context) (result Result) {
	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
		r.captureProgress(&result)
	}()

	cfg, err := r.normalizedConfig()
	if err != nil {
		result.Error = err
		return result
	}
	result.Parallel.RunID = cfg.RunID
	result.Parallel.RequestedParallelism = cfg.Parallelism

	canonicalBranch := ""

	manager := r.deps.Worktrees
	if manager == nil {
		manager = worktree.NewManager(worktree.Config{
			RepoPath:     cfg.RepoDir,
			WorktreeRoot: cfg.WorktreeRoot,
			BranchPrefix: cfg.BranchPrefix,
		})
	}
	executor := r.deps.Executor
	if executor == nil {
		executor = NewEngineWorkerExecutor(cfg.MaxRetries, cfg.RetryDelay)
	}
	integratorRunner := r.deps.Integrator
	if integratorRunner == nil {
		integratorRunner = integrator.New()
	}

	for result.Iterations < cfg.MaxIterations {
		prd, err := engine.LoadPRDFile(filepath.Join(cfg.RepoDir, cfg.HalDir), cfg.PRDFile)
		if err != nil {
			result.Error = fmt.Errorf("load PRD: %w", err)
			return result
		}
		if canonicalBranch == "" {
			canonicalBranch, err = resolveCanonicalBranch(ctx, cfg, prd)
			if err != nil {
				result.Error = err
				return result
			}
		}
		completed, total := prd.Progress()
		result.CompletedStories = completed
		result.TotalStories = total
		if completed == total {
			result.Success = true
			result.Complete = true
			return result
		}

		if issues := prdvalidator.ValidateSchedulingDependencies(prd); len(issues) > 0 {
			result.Error = fmt.Errorf("invalid PRD scheduling metadata: %s", schedulingIssueSummary(issues))
			return result
		}

		scheduled := taskgraph.Schedule(tasksFromPRD(prd), taskgraph.Options{Parallelism: cfg.Parallelism})
		result.Parallel.SerialCandidates += len(scheduled.Serial)
		result.Parallel.Blocked += len(scheduled.Blocked)
		if len(scheduled.Ready) == 0 {
			result.Error = errors.New("no schedulable pending tasks; check dependencies and conflict metadata")
			return result
		}

		remaining := cfg.MaxIterations - result.Iterations
		ready := scheduled.Ready
		if len(ready) > remaining {
			ready = ready[:remaining]
		}

		if cfg.DryRun {
			result.Success = true
			result.Complete = false
			if len(ready) > 0 {
				result.LastStoryID = ready[0].ID
				if story := prd.FindStoryByID(ready[0].ID); story != nil {
					result.LastStoryTitle = story.Title
				}
			}
			return result
		}

		if err := ensureProgressFile(filepath.Join(cfg.RepoDir, cfg.HalDir), cfg.ProgressFile); err != nil {
			result.Error = err
			return result
		}

		result.Parallel.Batches++
		batchResults := r.runBatch(ctx, cfg, manager, executor, ready, prd)
		started := countStartedWorkers(batchResults)
		result.Iterations += started
		result.Parallel.Started += started

		for _, workerResult := range batchResults {
			if workerResult.err != nil {
				result.Parallel.Failed++
				result.Error = workerResult.err
				result.Success = false
				return result
			}

			manifest := workerResult.manifest
			result.LastStoryID = manifest.TaskID
			if story := prd.FindStoryByID(manifest.TaskID); story != nil {
				result.LastStoryTitle = story.Title
			}

			_, err := integratorRunner.Integrate(ctx, integrator.Request{
				RepoDir:         cfg.RepoDir,
				TaskID:          manifest.TaskID,
				WorkerBranch:    manifest.Branch,
				WorkerCommit:    manifest.Commit,
				CanonicalBranch: canonicalBranch,
				PRDPath:         filepath.Join(cfg.HalDir, cfg.PRDFile),
				ProgressPath:    filepath.Join(cfg.HalDir, cfg.ProgressFile),
				ProgressEntry:   manifest.ProgressEntry,
				CheckCommands:   cfg.CheckCommands,
				Bookkeeping: integrator.BookkeepingConfig{
					Commit:  cfg.CommitBookkeeping,
					Message: fmt.Sprintf("chore: integrate %s bookkeeping", manifest.TaskID),
				},
			})
			if err != nil {
				result.Parallel.Failed++
				result.Error = err
				result.Success = false
				return result
			}
			result.Parallel.Integrated++
			_, _ = manager.Cleanup(ctx, worktree.CleanupRequest{
				WorktreePath: workerResult.worktree.WorktreePath,
				BranchName:   workerResult.worktree.BranchName,
				RemoveBranch: cfg.RemoveWorkerBranches,
				Force:        false,
			})
		}
		if prd, err := engine.LoadPRDFile(filepath.Join(cfg.RepoDir, cfg.HalDir), cfg.PRDFile); err == nil {
			completed, total := prd.Progress()
			result.CompletedStories = completed
			result.TotalStories = total
			if completed == total {
				result.Success = true
				result.Complete = true
				return result
			}
		}
	}

	result.Success = true
	result.Complete = false
	return result
}

type batchWorkerResult struct {
	task         taskgraph.Task
	story        engine.UserStory
	assignment   loop.WorkerAssignment
	manifestPath string
	worktree     worktree.CreateResult
	manifest     *loop.WorkerManifest
	started      bool
	err          error
}

func (r *Runner) runBatch(ctx context.Context, cfg Config, manager worktreeManager, executor WorkerExecutor, tasks []taskgraph.Task, prd *engine.PRD) []batchWorkerResult {
	results := make([]batchWorkerResult, len(tasks))

	for i, scheduledTask := range tasks {
		results[i].task = scheduledTask
		story := prd.FindStoryByID(scheduledTask.ID)
		if story == nil {
			results[i].err = fmt.Errorf("scheduled task %s not found in PRD", scheduledTask.ID)
			cleanupCreatedBatch(ctx, cfg, manager, results)
			return results
		}

		created, err := manager.Create(ctx, worktree.CreateRequest{
			RunID:   cfg.RunID,
			TaskID:  scheduledTask.ID,
			BaseRef: "HEAD",
		})
		if err != nil {
			results[i].err = err
			cleanupCreatedBatch(ctx, cfg, manager, results)
			return results
		}
		results[i].worktree = created

		if err := copyWorkerRuntimeContext(cfg.RepoDir, created.WorktreePath, cfg); err != nil {
			results[i].err = err
			cleanupCreatedBatch(ctx, cfg, manager, results)
			return results
		}

		manifestRelPath := filepath.ToSlash(filepath.Join(cfg.HalDir, "parallel", cfg.RunID, sanitizePathSegment(scheduledTask.ID), "worker-manifest.json"))
		results[i].story = *story
		results[i].manifestPath = filepath.Join(created.WorktreePath, filepath.FromSlash(manifestRelPath))
		index, total := taskIndex(prd, scheduledTask.ID)
		results[i].assignment = workerAssignment(*story, created.BranchName, cfg, manifestRelPath, index, total)
	}

	var wg sync.WaitGroup
	for i := range results {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i].started = true
			execResult := executor.ExecuteWorker(ctx, WorkerExecutionRequest{
				Task:         results[i].story,
				Assignment:   results[i].assignment,
				WorktreePath: results[i].worktree.WorktreePath,
				ManifestPath: results[i].manifestPath,
				Engine:       cfg.Engine,
				EngineConfig: cfg.EngineConfig,
				Logger:       cfg.Logger,
			})
			if execResult.Error != nil {
				results[i].err = execResult.Error
				return
			}
			if execResult.EngineResult.Error != nil {
				results[i].err = execResult.EngineResult.Error
				return
			}
			manifest := execResult.Manifest
			if manifest == nil {
				var err error
				manifest, err = loop.ReadWorkerManifest(results[i].manifestPath)
				if err != nil {
					results[i].err = fmt.Errorf("read worker manifest for %s: %w", results[i].task.ID, err)
					return
				}
			}
			if err := validateWorkerManifest(manifest, results[i].task.ID, results[i].worktree.BranchName); err != nil {
				results[i].err = err
				return
			}
			results[i].manifest = manifest
		}()
	}

	wg.Wait()
	cleanupFailedBatch(ctx, cfg, manager, results)
	return results
}

func countStartedWorkers(results []batchWorkerResult) int {
	started := 0
	for _, result := range results {
		if result.started {
			started++
		}
	}
	return started
}

func cleanupFailedBatch(ctx context.Context, cfg Config, manager worktreeManager, results []batchWorkerResult) {
	for _, result := range results {
		if result.err == nil {
			continue
		}
		if result.worktree.WorktreePath != "" {
			_, _ = manager.Cleanup(ctx, worktree.CleanupRequest{
				WorktreePath:   result.worktree.WorktreePath,
				BranchName:     result.worktree.BranchName,
				Failed:         true,
				PreserveFailed: cfg.PreserveFailedWorktrees,
				RemoveBranch:   cfg.RemoveWorkerBranches,
				Force:          !cfg.PreserveFailedWorktrees,
			})
		}
	}
}

func cleanupCreatedBatch(ctx context.Context, cfg Config, manager worktreeManager, results []batchWorkerResult) {
	for _, result := range results {
		if result.worktree.WorktreePath == "" {
			continue
		}
		_, _ = manager.Cleanup(ctx, worktree.CleanupRequest{
			WorktreePath:   result.worktree.WorktreePath,
			BranchName:     result.worktree.BranchName,
			Failed:         true,
			PreserveFailed: cfg.PreserveFailedWorktrees,
			RemoveBranch:   cfg.RemoveWorkerBranches,
			Force:          !cfg.PreserveFailedWorktrees,
		})
	}
}

func (r *Runner) normalizedConfig() (Config, error) {
	cfg := r.config
	if strings.TrimSpace(cfg.RepoDir) == "" {
		cfg.RepoDir = "."
	}
	repoDir, err := filepath.Abs(cfg.RepoDir)
	if err != nil {
		return Config{}, fmt.Errorf("resolve repo dir: %w", err)
	}
	cfg.RepoDir = repoDir
	if cfg.HalDir == "" {
		cfg.HalDir = template.HalDir
	}
	if cfg.PRDFile == "" {
		cfg.PRDFile = template.PRDFile
	}
	if cfg.ProgressFile == "" {
		cfg.ProgressFile = template.ProgressFile
	}
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 10
	}
	if cfg.Parallelism <= 0 {
		cfg.Parallelism = 1
	}
	if cfg.Engine == "" {
		cfg.Engine = "codex"
	}
	if cfg.Logger == nil {
		cfg.Logger = io.Discard
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 5 * time.Second
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.RunID == "" {
		now := time.Now
		if r.deps.Now != nil {
			now = r.deps.Now
		}
		cfg.RunID = "run-" + now().UTC().Format(defaultRunIDTimeFormat)
	}
	if cfg.WorktreeRoot == "" {
		cfg.WorktreeRoot = worktree.DefaultRoot
	}
	if cfg.BranchPrefix == "" {
		cfg.BranchPrefix = worktree.DefaultBranchPrefix
	}
	return cfg, nil
}

func (r *Runner) captureProgress(result *Result) {
	if result == nil {
		return
	}
	cfg := r.config
	if cfg.RepoDir == "" {
		cfg.RepoDir = "."
	}
	if cfg.HalDir == "" {
		cfg.HalDir = template.HalDir
	}
	if cfg.PRDFile == "" {
		cfg.PRDFile = template.PRDFile
	}
	if repoDir, err := filepath.Abs(cfg.RepoDir); err == nil {
		if prd, err := engine.LoadPRDFile(filepath.Join(repoDir, cfg.HalDir), cfg.PRDFile); err == nil {
			result.CompletedStories, result.TotalStories = prd.Progress()
		}
	}
}

func tasksFromPRD(prd *engine.PRD) []taskgraph.Task {
	if prd == nil {
		return nil
	}
	stories := append([]engine.UserStory{}, prd.UserStories...)
	stories = append(stories, prd.Tasks...)
	tasks := make([]taskgraph.Task, 0, len(stories))
	for _, story := range stories {
		status := taskgraph.TaskStatusPending
		if story.Passes {
			status = taskgraph.TaskStatusComplete
		}
		parallelSafe := false
		confidence := taskgraph.MetadataConfidenceLow
		if story.ParallelSafe != nil {
			parallelSafe = *story.ParallelSafe
			confidence = taskgraph.MetadataConfidenceHigh
		}
		tasks = append(tasks, taskgraph.Task{
			ID:                 strings.TrimSpace(story.ID),
			Priority:           story.Priority,
			DependsOn:          append([]string(nil), story.DependsOn...),
			ConflictDomains:    append([]string(nil), story.ConflictDomains...),
			ParallelSafe:       parallelSafe,
			Barrier:            story.Barrier,
			Status:             status,
			MetadataConfidence: confidence,
		})
	}
	return tasks
}

func workerAssignment(story engine.UserStory, branchName string, cfg Config, manifestRelPath string, index, total int) loop.WorkerAssignment {
	return loop.WorkerAssignment{
		TaskID:             story.ID,
		Title:              story.Title,
		Description:        story.Description,
		AcceptanceCriteria: append([]string(nil), story.AcceptanceCriteria...),
		PRDFile:            filepath.ToSlash(filepath.Join(cfg.HalDir, cfg.PRDFile)),
		ProgressFile:       filepath.ToSlash(filepath.Join(cfg.HalDir, cfg.ProgressFile)),
		ManifestFile:       manifestRelPath,
		BaseBranch:         cfg.BaseBranch,
		BranchName:         branchName,
		Scheduling: &loop.WorkerSchedulingMetadata{
			Priority:        story.Priority,
			Index:           index,
			Total:           total,
			DependsOn:       append([]string(nil), story.DependsOn...),
			ConflictDomains: append([]string(nil), story.ConflictDomains...),
			ParallelSafe:    story.ParallelSafe,
			Barrier:         story.Barrier,
			ParallelReason:  story.ParallelReason,
		},
	}
}

func taskIndex(prd *engine.PRD, id string) (int, int) {
	stories := append([]engine.UserStory{}, prd.UserStories...)
	stories = append(stories, prd.Tasks...)
	for i, story := range stories {
		if story.ID == id {
			return i + 1, len(stories)
		}
	}
	return 0, len(stories)
}

func validateWorkerManifest(manifest *loop.WorkerManifest, taskID, branchName string) error {
	if manifest == nil {
		return errors.New("worker manifest is required")
	}
	if manifest.TaskID != taskID {
		return fmt.Errorf("worker manifest taskId = %q, want %q", manifest.TaskID, taskID)
	}
	if manifest.Status != loop.WorkerManifestStatusReadyForIntegration {
		if manifest.Error != "" {
			return fmt.Errorf("worker %s failed: %s", taskID, manifest.Error)
		}
		return fmt.Errorf("worker %s manifest status = %q, want %q", taskID, manifest.Status, loop.WorkerManifestStatusReadyForIntegration)
	}
	if strings.TrimSpace(manifest.Branch) == "" {
		return fmt.Errorf("worker %s manifest branch is required", taskID)
	}
	if manifest.Branch != branchName {
		return fmt.Errorf("worker %s manifest branch = %q, want %q", taskID, manifest.Branch, branchName)
	}
	if strings.TrimSpace(manifest.Commit) == "" {
		return fmt.Errorf("worker %s manifest commit is required", taskID)
	}
	if strings.TrimSpace(manifest.ProgressEntry) == "" {
		return fmt.Errorf("worker %s manifest progressEntry is required", taskID)
	}
	return nil
}

func resolveCanonicalBranch(ctx context.Context, cfg Config, prd *engine.PRD) (string, error) {
	current, err := currentBranch(ctx, cfg.RepoDir)
	if err != nil {
		return "", err
	}

	canonical := strings.TrimSpace(cfg.CanonicalBranch)
	if canonical == "" {
		canonical = current
	}

	prdBranch := ""
	if prd != nil {
		prdBranch = strings.TrimSpace(prd.BranchName)
	}
	if prdBranch != "" && canonical != prdBranch {
		return "", fmt.Errorf("parallel run branch mismatch: canonical branch %q does not match %s branchName %q; switch to %q before running parallel mode", canonical, filepath.ToSlash(filepath.Join(cfg.HalDir, cfg.PRDFile)), prdBranch, prdBranch)
	}
	if current != canonical {
		return "", fmt.Errorf("parallel run branch mismatch: current branch %q does not match canonical branch %q; switch to %q before running parallel mode", current, canonical, canonical)
	}

	return canonical, nil
}

func schedulingIssueSummary(issues []prdvalidator.Issue) string {
	if len(issues) == 0 {
		return ""
	}
	issue := issues[0]
	if issue.StoryID != "" && issue.Field != "" {
		return fmt.Sprintf("[%s] %s: %s", issue.StoryID, issue.Field, issue.Message)
	}
	if issue.StoryID != "" {
		return fmt.Sprintf("[%s] %s", issue.StoryID, issue.Message)
	}
	if issue.Field != "" {
		return fmt.Sprintf("%s: %s", issue.Field, issue.Message)
	}
	return issue.Message
}

func currentBranch(ctx context.Context, repoDir string) (string, error) {
	out, err := gitOutput(ctx, repoDir, "branch", "--show-current")
	if err != nil {
		return "", fmt.Errorf("resolve current branch: %w", err)
	}
	branch := strings.TrimSpace(out)
	if branch == "" {
		return "", errors.New("parallel run requires a named current branch")
	}
	return branch, nil
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func ensureProgressFile(halDir, progressFile string) error {
	path := filepath.Join(halDir, progressFile)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat progress file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create progress directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(template.DefaultProgress), 0o644); err != nil {
		return fmt.Errorf("write default progress file: %w", err)
	}
	return nil
}

func sanitizePathSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "task"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
