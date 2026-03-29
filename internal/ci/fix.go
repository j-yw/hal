package ci

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
)

var (
	// ErrFixRequiresFailingStatus is returned when FixWithEngine is called without failing aggregated status.
	ErrFixRequiresFailingStatus = errors.New("ci fix requires failing status")

	// ErrFixRequiresEngine is returned when FixWithEngine is called without an engine.
	ErrFixRequiresEngine = errors.New("ci fix requires a non-nil engine")

	// ErrFixDirtyWorkingTree is returned when fix starts with local git changes.
	ErrFixDirtyWorkingTree = errors.New("ci fix requires a clean working tree (including untracked files)")

	// ErrFixNoChanges is returned when the engine run produced no file changes.
	ErrFixNoChanges = errors.New("ci fix engine run produced no file changes")
)

// FixOptions configures a single CI fix attempt.
type FixOptions struct {
	Engine      engine.Engine
	Display     *engine.Display
	Attempt     int
	MaxAttempts int
	AllowDirty  bool
	Prompt      string
}

type fixDeps struct {
	currentBranch      func(context.Context) (string, error)
	workingTreeChanges func(context.Context) ([]string, error)
	streamPrompt       func(context.Context, engine.Engine, string, *engine.Display) (string, error)
	addAll             func(context.Context) error
	commit             func(context.Context, string) error
	currentHeadSHA     func(context.Context) (string, error)
	pushBranch         func(context.Context, string) error
}

// FixWithEngine applies a single engine-driven fix attempt and pushes the resulting commit.
func FixWithEngine(ctx context.Context, status StatusResult, opts FixOptions) (FixResult, error) {
	return fixWithEngineWithDeps(ctx, status, opts, fixDeps{})
}

func fixWithEngineWithDeps(ctx context.Context, status StatusResult, opts FixOptions, deps fixDeps) (FixResult, error) {
	if status.Status != StatusFailing {
		return FixResult{}, fmt.Errorf("%w: got %q", ErrFixRequiresFailingStatus, status.Status)
	}
	if opts.Engine == nil {
		return FixResult{}, ErrFixRequiresEngine
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if deps.currentBranch == nil {
		deps.currentBranch = gitCurrentBranch
	}
	if deps.workingTreeChanges == nil {
		deps.workingTreeChanges = gitWorkingTreeChanges
	}
	if deps.streamPrompt == nil {
		deps.streamPrompt = streamFixPrompt
	}
	if deps.addAll == nil {
		deps.addAll = gitAddAll
	}
	if deps.commit == nil {
		deps.commit = gitCommit
	}
	if deps.currentHeadSHA == nil {
		deps.currentHeadSHA = gitCurrentHEADSHA
	}
	if deps.pushBranch == nil {
		deps.pushBranch = gitPushBranch
	}

	attempt := opts.Attempt
	if attempt <= 0 {
		attempt = 1
	}

	if !opts.AllowDirty {
		changes, err := deps.workingTreeChanges(ctx)
		if err != nil {
			return FixResult{}, err
		}
		if len(changes) > 0 {
			return FixResult{}, fmt.Errorf("%w: %s", ErrFixDirtyWorkingTree, strings.Join(changes, ", "))
		}
	}

	branch, err := deps.currentBranch(ctx)
	if err != nil {
		return FixResult{}, err
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return FixResult{}, fmt.Errorf("get current branch: empty branch name")
	}

	failing := failingChecks(status)
	prompt := strings.TrimSpace(opts.Prompt)
	if prompt == "" {
		prompt = buildFixPrompt(status, branch, attempt, failing)
	}
	if _, err := deps.streamPrompt(ctx, opts.Engine, prompt, opts.Display); err != nil {
		return FixResult{}, fmt.Errorf("run ci fix prompt: %w", err)
	}

	changedFiles, err := deps.workingTreeChanges(ctx)
	if err != nil {
		return FixResult{}, err
	}
	changedFiles = uniqueSortedPaths(changedFiles)
	if len(changedFiles) == 0 {
		return FixResult{}, ErrFixNoChanges
	}

	if err := deps.addAll(ctx); err != nil {
		return FixResult{}, err
	}

	commitMessage := defaultFixCommitMessage(attempt, failing)
	if err := deps.commit(ctx, commitMessage); err != nil {
		return FixResult{}, err
	}

	commitSHA, err := deps.currentHeadSHA(ctx)
	if err != nil {
		return FixResult{}, err
	}

	if err := deps.pushBranch(ctx, branch); err != nil {
		return FixResult{}, err
	}

	return FixResult{
		ContractVersion: FixContractVersion,
		Attempt:         attempt,
		MaxAttempts:     opts.MaxAttempts,
		Applied:         true,
		Branch:          branch,
		CommitSHA:       strings.TrimSpace(commitSHA),
		Pushed:          true,
		FilesChanged:    changedFiles,
		Summary:         fixSummary(branch, attempt, len(changedFiles)),
	}, nil
}

func failingChecks(status StatusResult) []StatusCheck {
	failing := make([]StatusCheck, 0)
	for _, check := range status.Checks {
		if check.Status == StatusFailing {
			failing = append(failing, check)
		}
	}
	return failing
}

func buildFixPrompt(status StatusResult, branch string, attempt int, failing []StatusCheck) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "CI status is failing for branch %q.\n", branch)
	fmt.Fprintf(&sb, "This is fix attempt %d.\n\n", attempt)
	fmt.Fprintf(&sb, "Summary: %s\n\n", strings.TrimSpace(status.Summary))

	sb.WriteString("Failed CI contexts:\n")
	if len(failing) == 0 {
		sb.WriteString("- (none reported by aggregator; inspect failures from repository context)\n")
	} else {
		for _, check := range failing {
			line := "- " + strings.TrimSpace(check.Name)
			if strings.TrimSpace(check.Source) != "" {
				line += " [" + strings.TrimSpace(check.Source) + "]"
			}
			if strings.TrimSpace(check.URL) != "" {
				line += " " + strings.TrimSpace(check.URL)
			}
			sb.WriteString(line + "\n")
		}
	}

	sb.WriteString("\nInstructions:\n")
	sb.WriteString("1. Investigate the failing contexts and identify root causes.\n")
	sb.WriteString("2. Apply the smallest safe code changes to resolve the failures.\n")
	sb.WriteString("3. Do not disable, skip, or weaken tests/linters.\n")
	sb.WriteString("4. Leave CI configuration unchanged unless it is clearly the root cause.\n")
	sb.WriteString("5. Stop after applying fixes; commit/push is handled by the caller.\n")

	return sb.String()
}

func defaultFixCommitMessage(attempt int, failing []StatusCheck) string {
	primary := "failures"
	if len(failing) > 0 {
		primary = strings.TrimSpace(failing[0].Name)
		if primary == "" {
			primary = "failures"
		}
	}
	return fmt.Sprintf("fix: ci %s (attempt %d)", primary, attempt)
}

func fixSummary(branch string, attempt int, changedFileCount int) string {
	return fmt.Sprintf("applied ci fix attempt %d on branch %s and pushed %d files", attempt, branch, changedFileCount)
}

func streamFixPrompt(ctx context.Context, eng engine.Engine, prompt string, display *engine.Display) (string, error) {
	return eng.StreamPrompt(ctx, prompt, display)
}

func gitWorkingTreeChanges(ctx context.Context) ([]string, error) {
	out, err := runGit(ctx, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return nil, fmt.Errorf("read git working tree status: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}

	lines := strings.Split(out, "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		if path := parsePorcelainPath(line); path != "" {
			paths = append(paths, path)
		}
	}
	return uniqueSortedPaths(paths), nil
}

func parsePorcelainPath(line string) string {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" || len(line) < 3 {
		return ""
	}

	path := strings.TrimSpace(line[3:])
	if path == "" {
		return ""
	}
	if strings.Contains(path, " -> ") {
		parts := strings.SplitN(path, " -> ", 2)
		path = strings.TrimSpace(parts[1])
	}
	return strings.Trim(path, "\"")
}

func uniqueSortedPaths(paths []string) []string {
	set := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		set[path] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for path := range set {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func gitAddAll(ctx context.Context) error {
	if _, err := runGit(ctx, "add", "-A"); err != nil {
		return fmt.Errorf("stage fix changes: %w", err)
	}
	return nil
}

func gitCommit(ctx context.Context, message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		return fmt.Errorf("commit fix changes: empty commit message")
	}
	if _, err := runGit(ctx, "commit", "-m", message); err != nil {
		return fmt.Errorf("commit fix changes: %w", err)
	}
	return nil
}
