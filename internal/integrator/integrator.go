package integrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Stage identifies the integration phase that failed.
type Stage string

const (
	StageValidate    Stage = "validate"
	StageCheckout    Stage = "checkout"
	StageCherryPick  Stage = "cherry_pick"
	StageCheck       Stage = "check"
	StagePRD         Stage = "prd"
	StageProgress    Stage = "progress"
	StageBookkeeping Stage = "bookkeeping"
	StageRollback    Stage = "rollback"
)

// Command describes a command executed by the integrator.
type Command struct {
	Name string
	Args []string
	Env  []string
	Dir  string
}

// CommandResult captures command output.
type CommandResult struct {
	Stdout string
	Stderr string
}

// CommandRunner executes commands. Tests can inject this to avoid spawning
// processes or to assert the exact git flow.
type CommandRunner interface {
	Run(ctx context.Context, command Command) (CommandResult, error)
}

// LocalRunner executes commands on the local machine.
type LocalRunner struct{}

// Run executes command and captures stdout/stderr.
func (LocalRunner) Run(ctx context.Context, command Command) (CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(command.Name) == "" {
		return CommandResult{}, errors.New("command name is required")
	}

	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	if strings.TrimSpace(command.Dir) != "" {
		cmd.Dir = command.Dir
	}
	if len(command.Env) > 0 {
		cmd.Env = append(os.Environ(), command.Env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}, err
}

// CheckCommand describes a post-cherry-pick verification command.
type CheckCommand struct {
	Name string
	Args []string
	Env  []string
	Dir  string
}

// BookkeepingConfig controls whether PRD/progress updates are committed.
type BookkeepingConfig struct {
	Commit  bool
	Message string
}

// Request is the full input needed to integrate one worker result.
type Request struct {
	RepoDir         string
	TaskID          string
	WorkerBranch    string
	WorkerCommit    string
	CanonicalBranch string
	PRDPath         string
	ProgressPath    string
	ProgressEntry   string
	CheckCommands   []CheckCommand
	Bookkeeping     BookkeepingConfig
}

// CheckResult records a successful check command.
type CheckResult struct {
	Command Command
	Stdout  string
	Stderr  string
}

// Result describes a completed integration.
type Result struct {
	TaskID             string
	WorkerBranch       string
	WorkerCommit       string
	CanonicalBranch    string
	OriginalHead       string
	IntegratedCommit   string
	BookkeepingCommit  string
	BookkeepingCreated bool
	Checks             []CheckResult
}

// IntegrationError is a structured integration failure.
type IntegrationError struct {
	Stage       Stage
	Command     *Command
	Err         error
	Rollback    *Command
	RollbackErr error
}

func (e *IntegrationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "integration failed at %s", e.Stage)
	if e.Command != nil {
		fmt.Fprintf(&b, " while running %s", commandString(*e.Command))
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	if e.RollbackErr != nil {
		fmt.Fprintf(&b, " (rollback failed")
		if e.Rollback != nil {
			fmt.Fprintf(&b, " while running %s", commandString(*e.Rollback))
		}
		fmt.Fprintf(&b, ": %v)", e.RollbackErr)
	}
	return b.String()
}

// Unwrap returns the primary failure cause.
func (e *IntegrationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Integrator serially integrates worker results into a canonical branch.
type Integrator struct {
	Runner CommandRunner
}

// New creates an Integrator that uses the local command runner.
func New() *Integrator {
	return &Integrator{Runner: LocalRunner{}}
}

// Integrate applies one worker commit to the canonical branch, verifies it,
// and updates canonical PRD/progress state only after checks pass.
func (i *Integrator) Integrate(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runner := i.Runner
	if runner == nil {
		runner = LocalRunner{}
	}
	req.RepoDir = strings.TrimSpace(req.RepoDir)
	if req.RepoDir == "" {
		req.RepoDir = "."
	}
	repoDir, err := filepath.Abs(req.RepoDir)
	if err != nil {
		return Result{}, &IntegrationError{Stage: StageValidate, Err: fmt.Errorf("resolve repository directory: %w", err)}
	}
	req.RepoDir = repoDir
	if err := validateRequest(req); err != nil {
		return Result{}, &IntegrationError{Stage: StageValidate, Err: err}
	}

	result := Result{
		TaskID:          req.TaskID,
		WorkerBranch:    req.WorkerBranch,
		WorkerCommit:    req.WorkerCommit,
		CanonicalBranch: req.CanonicalBranch,
	}
	if err := validateSingleWorkerCommit(ctx, runner, req); err != nil {
		return result, &IntegrationError{Stage: StageValidate, Err: err}
	}
	if err := validateWorkerCommitPaths(ctx, runner, req); err != nil {
		return result, &IntegrationError{Stage: StageValidate, Err: err}
	}

	if _, err := runGit(ctx, runner, req.RepoDir, "checkout", req.CanonicalBranch); err != nil {
		cmd := gitCommand(req.RepoDir, "checkout", req.CanonicalBranch)
		return result, &IntegrationError{Stage: StageCheckout, Command: &cmd, Err: err}
	}

	originalHead, err := runGit(ctx, runner, req.RepoDir, "rev-parse", "HEAD")
	if err != nil {
		cmd := gitCommand(req.RepoDir, "rev-parse", "HEAD")
		return result, &IntegrationError{Stage: StageCheckout, Command: &cmd, Err: err}
	}
	result.OriginalHead = strings.TrimSpace(originalHead.Stdout)

	if _, err := runGit(ctx, runner, req.RepoDir, "cherry-pick", req.WorkerCommit); err != nil {
		cmd := gitCommand(req.RepoDir, "cherry-pick", req.WorkerCommit)
		abortCmd, abortErr := abortCherryPick(ctx, runner, req.RepoDir)
		return result, &IntegrationError{
			Stage:       StageCherryPick,
			Command:     &cmd,
			Err:         err,
			Rollback:    abortCmd,
			RollbackErr: abortErr,
		}
	}

	cherryHead, err := runGit(ctx, runner, req.RepoDir, "rev-parse", "HEAD")
	if err != nil {
		cmd := gitCommand(req.RepoDir, "rev-parse", "HEAD")
		rollbackCmd, rollbackErr := resetHard(ctx, runner, req.RepoDir, result.OriginalHead)
		return result, &IntegrationError{
			Stage:       StageCherryPick,
			Command:     &cmd,
			Err:         err,
			Rollback:    rollbackCmd,
			RollbackErr: rollbackErr,
		}
	}
	result.IntegratedCommit = strings.TrimSpace(cherryHead.Stdout)

	for _, check := range req.CheckCommands {
		command := Command{Name: check.Name, Args: append([]string(nil), check.Args...), Env: append([]string(nil), check.Env...), Dir: commandDir(req.RepoDir, check.Dir)}
		checkResult, err := runner.Run(ctx, command)
		if err != nil {
			rollbackCmd, rollbackErr := resetHard(ctx, runner, req.RepoDir, result.OriginalHead)
			return result, &IntegrationError{
				Stage:       StageCheck,
				Command:     &command,
				Err:         err,
				Rollback:    rollbackCmd,
				RollbackErr: rollbackErr,
			}
		}
		result.Checks = append(result.Checks, CheckResult{Command: command, Stdout: checkResult.Stdout, Stderr: checkResult.Stderr})
	}

	prdPath, err := repoPath(req.RepoDir, req.PRDPath)
	if err != nil {
		rollbackCmd, rollbackErr := resetHard(ctx, runner, req.RepoDir, result.OriginalHead)
		return result, &IntegrationError{Stage: StagePRD, Err: err, Rollback: rollbackCmd, RollbackErr: rollbackErr}
	}
	prdSnapshot, err := snapshotFile(prdPath)
	if err != nil {
		rollbackCmd, rollbackErr := resetHard(ctx, runner, req.RepoDir, result.OriginalHead)
		return result, &IntegrationError{Stage: StagePRD, Err: err, Rollback: rollbackCmd, RollbackErr: rollbackErr}
	}
	if err := markPRDPasses(prdPath, req.TaskID); err != nil {
		rollbackCmd, rollbackErr := resetHardAndRestore(ctx, runner, req.RepoDir, result.OriginalHead, prdSnapshot)
		return result, &IntegrationError{Stage: StagePRD, Err: err, Rollback: rollbackCmd, RollbackErr: rollbackErr}
	}

	progressPath, err := repoPath(req.RepoDir, req.ProgressPath)
	if err != nil {
		rollbackCmd, rollbackErr := resetHardAndRestore(ctx, runner, req.RepoDir, result.OriginalHead, prdSnapshot)
		return result, &IntegrationError{Stage: StageProgress, Err: err, Rollback: rollbackCmd, RollbackErr: rollbackErr}
	}
	progressSnapshot, err := snapshotFile(progressPath)
	if err != nil {
		rollbackCmd, rollbackErr := resetHardAndRestore(ctx, runner, req.RepoDir, result.OriginalHead, prdSnapshot)
		return result, &IntegrationError{Stage: StageProgress, Err: err, Rollback: rollbackCmd, RollbackErr: rollbackErr}
	}
	if err := appendProgress(progressPath, req.ProgressEntry); err != nil {
		rollbackCmd, rollbackErr := resetHardAndRestore(ctx, runner, req.RepoDir, result.OriginalHead, prdSnapshot, progressSnapshot)
		return result, &IntegrationError{Stage: StageProgress, Err: err, Rollback: rollbackCmd, RollbackErr: rollbackErr}
	}

	if req.Bookkeeping.Commit {
		if err := commitBookkeeping(ctx, runner, req, prdPath, progressPath); err != nil {
			rollbackCmd, rollbackErr := resetHardAndRestore(ctx, runner, req.RepoDir, result.OriginalHead, prdSnapshot, progressSnapshot)
			return result, &IntegrationError{Stage: StageBookkeeping, Err: err, Rollback: rollbackCmd, RollbackErr: rollbackErr}
		}
		head, err := runGit(ctx, runner, req.RepoDir, "rev-parse", "HEAD")
		if err != nil {
			cmd := gitCommand(req.RepoDir, "rev-parse", "HEAD")
			return result, &IntegrationError{Stage: StageBookkeeping, Command: &cmd, Err: err}
		}
		result.BookkeepingCommit = strings.TrimSpace(head.Stdout)
		result.BookkeepingCreated = true
	}

	return result, nil
}

func validateRequest(req Request) error {
	missing := make([]string, 0, 8)
	if strings.TrimSpace(req.TaskID) == "" {
		missing = append(missing, "task ID")
	}
	if strings.TrimSpace(req.WorkerBranch) == "" {
		missing = append(missing, "worker branch")
	}
	if strings.TrimSpace(req.WorkerCommit) == "" {
		missing = append(missing, "worker commit")
	}
	if strings.TrimSpace(req.CanonicalBranch) == "" {
		missing = append(missing, "canonical branch")
	}
	if strings.TrimSpace(req.PRDPath) == "" {
		missing = append(missing, "PRD path")
	}
	if strings.TrimSpace(req.ProgressPath) == "" {
		missing = append(missing, "progress path")
	}
	if strings.TrimSpace(req.ProgressEntry) == "" {
		missing = append(missing, "progress entry")
	}
	for i, check := range req.CheckCommands {
		if strings.TrimSpace(check.Name) == "" {
			missing = append(missing, fmt.Sprintf("check command %d name", i))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required integration input: %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateSingleWorkerCommit(ctx context.Context, runner CommandRunner, req Request) error {
	revisionRange := req.CanonicalBranch + ".." + req.WorkerCommit
	result, err := runGit(ctx, runner, req.RepoDir, "rev-list", "--count", revisionRange)
	if err != nil {
		return fmt.Errorf("count worker branch commits: %w", err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(result.Stdout))
	if err != nil {
		return fmt.Errorf("parse worker branch commit count %q: %w", strings.TrimSpace(result.Stdout), err)
	}
	if count > 1 {
		return fmt.Errorf("worker branch %s has %d commits beyond %s; parallel integration requires a single worker commit", req.WorkerBranch, count, req.CanonicalBranch)
	}
	return nil
}

func validateWorkerCommitPaths(ctx context.Context, runner CommandRunner, req Request) error {
	protected, err := protectedStatePaths(req.RepoDir, req.PRDPath, req.ProgressPath)
	if err != nil {
		return err
	}
	changed, err := workerCommitChangedPaths(ctx, runner, req.RepoDir, req.WorkerCommit)
	if err != nil {
		return err
	}
	blocked := make([]string, 0, len(protected))
	for _, path := range changed {
		if _, ok := protected[normalizeRepoPath(path)]; ok {
			blocked = append(blocked, normalizeRepoPath(path))
		}
	}
	if len(blocked) > 0 {
		return fmt.Errorf("worker commit %s touches canonical Hal state: %s", req.WorkerCommit, strings.Join(blocked, ", "))
	}
	return nil
}

func protectedStatePaths(repoDir, prdPath, progressPath string) (map[string]struct{}, error) {
	protected := make(map[string]struct{}, 2)
	for _, path := range []string{prdPath, progressPath} {
		fullPath, err := repoPath(repoDir, path)
		if err != nil {
			return nil, err
		}
		relPath, err := repoRelativePath(repoDir, fullPath)
		if err != nil {
			return nil, err
		}
		protected[normalizeRepoPath(relPath)] = struct{}{}
	}
	return protected, nil
}

func workerCommitChangedPaths(ctx context.Context, runner CommandRunner, repoDir, commit string) ([]string, error) {
	result, err := runGit(ctx, runner, repoDir, "diff-tree", "--no-commit-id", "--name-only", "-r", commit, "--")
	if err != nil {
		return nil, fmt.Errorf("list worker commit changed paths: %w", err)
	}
	paths := make([]string, 0)
	for _, line := range strings.Split(result.Stdout, "\n") {
		path := normalizeRepoPath(line)
		if path != "" && path != "." {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func normalizeRepoPath(path string) string {
	path = strings.TrimSpace(filepath.ToSlash(path))
	if path == "" {
		return ""
	}
	path = filepath.ToSlash(filepath.Clean(path))
	return strings.TrimPrefix(path, "./")
}

func runGit(ctx context.Context, runner CommandRunner, repoDir string, args ...string) (CommandResult, error) {
	return runner.Run(ctx, gitCommand(repoDir, args...))
}

func gitCommand(repoDir string, args ...string) Command {
	return Command{Name: "git", Args: append([]string(nil), args...), Dir: repoDir}
}

func abortCherryPick(ctx context.Context, runner CommandRunner, repoDir string) (*Command, error) {
	cmd := gitCommand(repoDir, "cherry-pick", "--abort")
	_, err := runner.Run(ctx, cmd)
	return &cmd, err
}

func resetHard(ctx context.Context, runner CommandRunner, repoDir, ref string) (*Command, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, errors.New("cannot roll back without original HEAD")
	}
	cmd := gitCommand(repoDir, "reset", "--hard", ref)
	_, err := runner.Run(ctx, cmd)
	return &cmd, err
}

type fileSnapshot struct {
	path   string
	data   []byte
	mode   fs.FileMode
	exists bool
}

func snapshotFile(path string) (fileSnapshot, error) {
	snapshot := fileSnapshot{path: path}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return snapshot, nil
		}
		return snapshot, fmt.Errorf("stat snapshot file: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, fmt.Errorf("read snapshot file: %w", err)
	}
	snapshot.data = append([]byte(nil), data...)
	snapshot.mode = info.Mode().Perm()
	snapshot.exists = true
	return snapshot, nil
}

func resetHardAndRestore(ctx context.Context, runner CommandRunner, repoDir, ref string, snapshots ...fileSnapshot) (*Command, error) {
	cmd, resetErr := resetHard(ctx, runner, repoDir, ref)
	restoreErr := restoreFileSnapshots(snapshots...)
	return cmd, errors.Join(resetErr, restoreErr)
}

func restoreFileSnapshots(snapshots ...fileSnapshot) error {
	var errs []error
	for _, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.path) == "" {
			continue
		}
		if !snapshot.exists {
			if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove restored absent file: %w", err))
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(snapshot.path), 0o755); err != nil {
			errs = append(errs, fmt.Errorf("create restored file directory: %w", err))
			continue
		}
		if err := os.WriteFile(snapshot.path, snapshot.data, snapshot.mode); err != nil {
			errs = append(errs, fmt.Errorf("restore file snapshot: %w", err))
		}
	}
	return errors.Join(errs...)
}

func commandDir(repoDir, dir string) string {
	if strings.TrimSpace(dir) == "" {
		return repoDir
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(repoDir, dir)
}

func commandString(command Command) string {
	parts := append([]string{command.Name}, command.Args...)
	return strings.Join(parts, " ")
}

func repoPath(repoDir, path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", errors.New("path is required")
	}
	if filepath.IsAbs(cleanPath) {
		rel, err := filepath.Rel(repoDir, cleanPath)
		if err != nil {
			return "", fmt.Errorf("resolve %s relative to repo: %w", cleanPath, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("path %s is outside repository %s", cleanPath, repoDir)
		}
		return cleanPath, nil
	}
	return filepath.Join(repoDir, cleanPath), nil
}

func repoRelativePath(repoDir, path string) (string, error) {
	if filepath.IsAbs(path) {
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			return "", err
		}
		return filepath.ToSlash(rel), nil
	}
	return filepath.ToSlash(path), nil
}

func markPRDPasses(path, taskID string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat PRD: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read PRD: %w", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse PRD JSON: %w", err)
	}

	updated := false
	for _, field := range []string{"userStories", "tasks"} {
		raw, ok := doc[field]
		if !ok || len(raw) == 0 || string(raw) == "null" {
			continue
		}
		next, found, err := markCollectionPasses(raw, taskID)
		if err != nil {
			return fmt.Errorf("update PRD %s: %w", field, err)
		}
		if found {
			doc[field] = next
			updated = true
			break
		}
	}
	if !updated {
		return fmt.Errorf("task %s not found in PRD userStories or tasks", taskID)
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode PRD JSON: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write PRD: %w", err)
	}
	return nil
}

func markCollectionPasses(raw json.RawMessage, taskID string) (json.RawMessage, bool, error) {
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false, err
	}
	for i := range items {
		var id string
		if err := json.Unmarshal(items[i]["id"], &id); err != nil {
			continue
		}
		if id != taskID {
			continue
		}
		items[i]["passes"] = json.RawMessage("true")
		next, err := json.Marshal(items)
		return next, true, err
	}
	return raw, false, nil
}

func appendProgress(path, entry string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat progress: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read progress: %w", err)
	}

	var out []byte
	out = append(out, data...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, strings.TrimRight(entry, "\r\n")...)
	out = append(out, '\n')

	if err := os.WriteFile(path, out, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}
	return nil
}

func commitBookkeeping(ctx context.Context, runner CommandRunner, req Request, prdPath, progressPath string) error {
	prdRel, err := repoRelativePath(req.RepoDir, prdPath)
	if err != nil {
		return fmt.Errorf("resolve PRD path for git add: %w", err)
	}
	progressRel, err := repoRelativePath(req.RepoDir, progressPath)
	if err != nil {
		return fmt.Errorf("resolve progress path for git add: %w", err)
	}
	if _, err := runGit(ctx, runner, req.RepoDir, "add", "--", prdRel, progressRel); err != nil {
		return err
	}
	message := strings.TrimSpace(req.Bookkeeping.Message)
	if message == "" {
		message = fmt.Sprintf("chore: integrate %s bookkeeping", req.TaskID)
	}
	if _, err := runGit(ctx, runner, req.RepoDir, "commit", "-m", message); err != nil {
		return err
	}
	return nil
}
