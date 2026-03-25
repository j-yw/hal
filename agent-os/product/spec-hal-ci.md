# Spec: `hal ci`

> Push, check CI, auto-fix failures, and merge — the missing last mile.

---

## 1. Problem Statement

hal develops features (plan → convert → run → review) but can't ship them. The loop is open-ended: code lives on a local branch with no path to production. Users must manually push, create PRs, check CI, fix failures, and merge. The `hal auto` pipeline has a rudimentary `pr` step that shells out to `gh` but has no CI awareness, no fix loop, and no merge capability.

### Current State

```
hal run → hal review → ??? → manually push → manually create PR → manually check CI → manually fix → manually merge
```

`internal/compound/git.go` has `PushBranch()` and `CreatePR()` that shell out to `git push` and `gh pr create`. No abstraction, no CI checking, no error handling beyond stderr capture.

### Target State

```
hal ci push   → push + draft PR
hal ci status → check CI results (with polling)
hal ci fix    → parse failures + engine fix + push
hal ci merge  → merge when green
```

Both standalone CLI commands AND callable as Go functions from `internal/compound/pipeline.go`.

---

## 2. Architecture

```
cmd/
  ci.go              ← Cobra parent: hal ci
  ci_push.go         ← hal ci push
  ci_status.go       ← hal ci status
  ci_fix.go          ← hal ci fix
  ci_merge.go        ← hal ci merge

internal/ci/
  github.go          ← GitHub API client (go-github/v68)
  gh_fallback.go     ← gh CLI fallback for auth + operations
  auth.go            ← Token resolution ($GITHUB_TOKEN → gh auth token)
  push.go            ← PushAndCreatePR core logic
  status.go          ← GetCheckStatus / WaitForChecks
  fix.go             ← ParseFailures / FixWithEngine
  merge.go           ← MergePR core logic
  types.go           ← All shared types
```

### Design Principles

1. **`internal/ci/` exports Go functions** — `cmd/ci_*.go` and `internal/compound/pipeline.go` both call them. No shelling out to self.
2. **GitHub-first, gh-fallback** — Use `go-github` for API operations. Fall back to `gh` CLI when `GITHUB_TOKEN` is not set (gh handles its own auth).
3. **Every subcommand has `--json`** — Machine-readable output for agent/skill consumption.
4. **`hal ci` works without hal state** — `push`, `status`, and `merge` work on any git branch. Only `fix` requires an engine. Only PR body generation benefits from `prd.json`.

---

## 3. Auth Resolution

```go
// internal/ci/auth.go

// ResolveToken returns a GitHub API token from the environment or gh CLI.
// Priority: $GITHUB_TOKEN → $GH_TOKEN → gh auth token
func ResolveToken() (string, error) {
    if token := os.Getenv("GITHUB_TOKEN"); token != "" {
        return token, nil
    }
    if token := os.Getenv("GH_TOKEN"); token != "" {
        return token, nil
    }
    // Fallback: ask gh CLI
    cmd := exec.Command("gh", "auth", "token")
    out, err := cmd.Output()
    if err != nil {
        return "", fmt.Errorf("no GitHub token found: set $GITHUB_TOKEN or run 'gh auth login'")
    }
    return strings.TrimSpace(string(out)), nil
}

// ResolveRemote extracts owner/repo from the git remote.
func ResolveRemote() (owner, repo string, err error) {
    cmd := exec.Command("git", "remote", "get-url", "origin")
    out, err := cmd.Output()
    if err != nil {
        return "", "", fmt.Errorf("no git remote 'origin' found")
    }
    return parseGitHubRemote(strings.TrimSpace(string(out)))
}

// parseGitHubRemote handles:
//   https://github.com/owner/repo.git
//   git@github.com:owner/repo.git
//   ssh://git@github.com/owner/repo.git
func parseGitHubRemote(remote string) (string, string, error) { ... }
```

### `hal doctor` Integration

Add a new check to `internal/doctor/`:

```go
{
    Name:        "github_auth",
    Scope:       ScopeEngineGlobal,
    Description: "GitHub authentication for CI operations",
    Check: func() CheckResult {
        _, err := ci.ResolveToken()
        if err != nil {
            return CheckResult{
                Status:  StatusWarning,
                Message: "No GitHub token found",
                Remediation: &Remediation{
                    Command: "gh auth login",
                    Safe:    true,
                },
            }
        }
        return CheckResult{Status: StatusOK, Message: "GitHub token available"}
    },
}
```

---

## 4. Types

```go
// internal/ci/types.go

// PushResult is returned by PushAndCreatePR.
type PushResult struct {
    Branch  string `json:"branch"`
    PRNum   int    `json:"prNumber"`
    PRURL   string `json:"prUrl"`
    Created bool   `json:"created"` // false if PR already existed
}

// CheckResult is returned by GetCheckStatus and WaitForChecks.
type CheckResult struct {
    PRNum       int               `json:"prNumber"`
    PRURL       string            `json:"prUrl"`
    Status      CheckStatus       `json:"status"`  // passing, failing, pending
    Passed      []string          `json:"passed"`
    Failed      []string          `json:"failed"`
    Pending     []string          `json:"pending"`
    FailureLogs map[string]string `json:"failureLogs,omitempty"` // check name → log tail
}

type CheckStatus string

const (
    StatusPassing CheckStatus = "passing"
    StatusFailing CheckStatus = "failing"
    StatusPending CheckStatus = "pending"
)

// FixResult is returned by FixWithEngine.
type FixResult struct {
    Attempt     int    `json:"attempt"`
    CheckName   string `json:"checkName"`
    CommitHash  string `json:"commitHash"`
    CommitMsg   string `json:"commitMessage"`
    Pushed      bool   `json:"pushed"`
}

// MergeResult is returned by MergePR.
type MergeResult struct {
    PRNum    int    `json:"prNumber"`
    SHA      string `json:"mergeCommitSha"`
    Strategy string `json:"strategy"`
}

// PushOpts configures PushAndCreatePR.
type PushOpts struct {
    BaseBranch  string // PR target branch (default: repo default branch)
    Title       string // PR title (default: from prd.json or branch name)
    Body        string // PR body (default: auto-generated)
    Draft       bool   // Create as draft (default: true)
}

// WaitOpts configures WaitForChecks.
type WaitOpts struct {
    PollInterval time.Duration // Default: 30s
    Timeout      time.Duration // Default: 30m
}

// FixOpts configures FixWithEngine.
type FixOpts struct {
    MaxAttempts int           // Default: 3
    Engine      engine.Engine // Required
    Display     *engine.Display
}

// MergeOpts configures MergePR.
type MergeOpts struct {
    Strategy     string // "squash" (default), "merge", "rebase"
    DeleteBranch bool   // Delete remote branch after merge (default: true)
}
```

---

## 5. Core Functions

### `push.go` — PushAndCreatePR

```go
// PushAndCreatePR pushes the current branch and creates a draft PR.
// If a PR already exists for this branch, returns it without creating a new one.
func PushAndCreatePR(ctx context.Context, opts PushOpts) (*PushResult, error) {
    branch, err := currentBranch()
    if err != nil {
        return nil, fmt.Errorf("not on a branch: %w", err)
    }

    // 1. Push
    if err := gitPush(branch); err != nil {
        return nil, fmt.Errorf("push failed: %w", err)
    }

    // 2. Check if PR already exists
    owner, repo, err := ResolveRemote()
    if err != nil {
        return nil, err
    }

    client, err := newGitHubClient(ctx)
    if err != nil {
        return nil, err
    }

    existing, err := findPRForBranch(ctx, client, owner, repo, branch)
    if err == nil && existing != nil {
        return &PushResult{
            Branch:  branch,
            PRNum:   existing.GetNumber(),
            PRURL:   existing.GetHTMLURL(),
            Created: false,
        }, nil
    }

    // 3. Resolve defaults
    if opts.Title == "" {
        opts.Title = defaultPRTitle(branch)
    }
    if opts.BaseBranch == "" {
        opts.BaseBranch, _ = defaultBaseBranch(ctx, client, owner, repo)
    }

    // 4. Create draft PR
    pr, _, err := client.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
        Title: github.Ptr(opts.Title),
        Body:  github.Ptr(opts.Body),
        Head:  github.Ptr(branch),
        Base:  github.Ptr(opts.BaseBranch),
        Draft: github.Ptr(true),
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create PR: %w", err)
    }

    return &PushResult{
        Branch:  branch,
        PRNum:   pr.GetNumber(),
        PRURL:   pr.GetHTMLURL(),
        Created: true,
    }, nil
}

// defaultPRTitle generates a PR title from branch name or prd.json.
func defaultPRTitle(branch string) string {
    // Try prd.json first
    prd, err := engine.LoadPRD(template.HalDir)
    if err == nil && prd.Description != "" {
        return prd.Description
    }
    // Fallback: humanize branch name
    // hal/user-auth → "hal/user-auth"
    return branch
}
```

### `status.go` — GetCheckStatus / WaitForChecks

```go
// GetCheckStatus returns the current CI check status for the branch's PR.
func GetCheckStatus(ctx context.Context) (*CheckResult, error) {
    owner, repo, err := ResolveRemote()
    if err != nil { return nil, err }

    client, err := newGitHubClient(ctx)
    if err != nil { return nil, err }

    branch, err := currentBranch()
    if err != nil { return nil, err }

    pr, err := findPRForBranch(ctx, client, owner, repo, branch)
    if err != nil {
        return nil, fmt.Errorf("no PR found for branch %s: %w", branch, err)
    }

    // Get check suites for the PR's head SHA
    sha := pr.GetHead().GetSHA()
    checks, _, err := client.Checks.ListCheckRunsForRef(ctx, owner, repo, sha, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to list checks: %w", err)
    }

    result := &CheckResult{
        PRNum: pr.GetNumber(),
        PRURL: pr.GetHTMLURL(),
    }

    for _, run := range checks.CheckRuns {
        name := run.GetName()
        switch {
        case run.GetConclusion() == "success":
            result.Passed = append(result.Passed, name)
        case run.GetConclusion() == "failure":
            result.Failed = append(result.Failed, name)
        case run.GetStatus() == "in_progress" || run.GetStatus() == "queued":
            result.Pending = append(result.Pending, name)
        default:
            // skipped, cancelled, etc — treat as passed
            result.Passed = append(result.Passed, name)
        }
    }

    // Determine overall status
    switch {
    case len(result.Pending) > 0:
        result.Status = StatusPending
    case len(result.Failed) > 0:
        result.Status = StatusFailing
    default:
        result.Status = StatusPassing
    }

    // Fetch failure logs for failed checks
    if len(result.Failed) > 0 {
        result.FailureLogs = make(map[string]string)
        for _, run := range checks.CheckRuns {
            if run.GetConclusion() == "failure" {
                log, err := fetchCheckLog(ctx, client, owner, repo, run.GetID())
                if err == nil {
                    result.FailureLogs[run.GetName()] = truncateLog(log, 4096)
                }
            }
        }
    }

    return result, nil
}

// WaitForChecks polls until CI reaches a terminal state or timeout.
func WaitForChecks(ctx context.Context, opts WaitOpts) (*CheckResult, error) {
    if opts.PollInterval == 0 {
        opts.PollInterval = 30 * time.Second
    }
    if opts.Timeout == 0 {
        opts.Timeout = 30 * time.Minute
    }

    deadline := time.After(opts.Timeout)
    ticker := time.NewTicker(opts.PollInterval)
    defer ticker.Stop()

    for {
        result, err := GetCheckStatus(ctx)
        if err != nil {
            return nil, err
        }
        if result.Status != StatusPending {
            return result, nil
        }

        select {
        case <-ctx.Done():
            return result, ctx.Err()
        case <-deadline:
            return result, fmt.Errorf("CI checks timed out after %s (still pending: %v)",
                opts.Timeout, result.Pending)
        case <-ticker.C:
            // continue polling
        }
    }
}
```

### `fix.go` — ParseFailures / FixWithEngine

```go
// FixWithEngine attempts to fix CI failures using an AI engine.
// Returns after one fix attempt (caller decides whether to retry).
func FixWithEngine(ctx context.Context, checkResult *CheckResult, opts FixOpts) (*FixResult, error) {
    if len(checkResult.Failed) == 0 {
        return nil, fmt.Errorf("no failed checks to fix")
    }

    // Build focused fix prompt from failure logs
    prompt := buildFixPrompt(checkResult)

    // Single-shot engine invocation
    opts.Display.ShowInfo("   Fixing CI failure: %s\n", strings.Join(checkResult.Failed, ", "))
    _, err := opts.Engine.StreamPrompt(ctx, prompt, opts.Display)
    if err != nil {
        return nil, fmt.Errorf("engine fix failed: %w", err)
    }

    // Commit the fix
    checkName := checkResult.Failed[0] // primary failure
    commitMsg := fmt.Sprintf("fix: CI failure in %s", checkName)

    cmd := exec.Command("git", "add", "-A")
    if err := cmd.Run(); err != nil {
        return nil, fmt.Errorf("git add failed: %w", err)
    }

    cmd = exec.Command("git", "commit", "-m", commitMsg, "--allow-empty")
    out, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("git commit failed: %w", err)
    }

    // Extract commit hash
    hash := parseCommitHash(string(out))

    // Push
    branch, _ := currentBranch()
    if err := gitPush(branch); err != nil {
        return nil, fmt.Errorf("push after fix failed: %w", err)
    }

    return &FixResult{
        Attempt:    opts.currentAttempt,
        CheckName:  checkName,
        CommitHash: hash,
        CommitMsg:  commitMsg,
        Pushed:     true,
    }, nil
}

func buildFixPrompt(result *CheckResult) string {
    var sb strings.Builder
    sb.WriteString("CI checks are failing. Fix the issues below.\n\n")
    sb.WriteString("## Failed Checks\n\n")

    for _, name := range result.Failed {
        sb.WriteString(fmt.Sprintf("### %s\n\n", name))
        if log, ok := result.FailureLogs[name]; ok {
            sb.WriteString("```\n")
            sb.WriteString(log)
            sb.WriteString("\n```\n\n")
        }
    }

    sb.WriteString("## Instructions\n\n")
    sb.WriteString("1. Read the failure logs carefully\n")
    sb.WriteString("2. Identify the root cause\n")
    sb.WriteString("3. Fix the code — do NOT skip or disable tests\n")
    sb.WriteString("4. Ensure your fix doesn't break other tests\n")
    sb.WriteString("5. Do NOT modify CI configuration files unless the config itself is wrong\n")

    return sb.String()
}
```

### `merge.go` — MergePR

```go
// MergePR merges the PR for the current branch.
func MergePR(ctx context.Context, opts MergeOpts) (*MergeResult, error) {
    if opts.Strategy == "" {
        opts.Strategy = "squash"
    }

    owner, repo, err := ResolveRemote()
    if err != nil { return nil, err }

    client, err := newGitHubClient(ctx)
    if err != nil { return nil, err }

    branch, err := currentBranch()
    if err != nil { return nil, err }

    pr, err := findPRForBranch(ctx, client, owner, repo, branch)
    if err != nil {
        return nil, fmt.Errorf("no PR found for branch %s: %w", branch, err)
    }

    // Verify CI is green
    result, err := GetCheckStatus(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to check CI status: %w", err)
    }
    if result.Status != StatusPassing {
        return nil, fmt.Errorf("CI checks are %s — run 'hal ci fix' first", result.Status)
    }

    // Map strategy to GitHub merge method
    method := "squash"
    switch opts.Strategy {
    case "merge":
        method = "merge"
    case "rebase":
        method = "rebase"
    }

    // Merge
    merge, _, err := client.PullRequests.Merge(ctx, owner, repo, pr.GetNumber(),
        "", &github.PullRequestOptions{MergeMethod: method})
    if err != nil {
        return nil, fmt.Errorf("merge failed: %w", err)
    }

    // Delete remote branch
    if opts.DeleteBranch {
        client.Git.DeleteRef(ctx, owner, repo, "refs/heads/"+branch)
    }

    return &MergeResult{
        PRNum:    pr.GetNumber(),
        SHA:      merge.GetSHA(),
        Strategy: opts.Strategy,
    }, nil
}
```

---

## 6. CLI Commands

### `cmd/ci.go` — Parent

```go
var ciCmd = &cobra.Command{
    Use:   "ci",
    Short: "Manage CI/CD pipeline (push, status, fix, merge)",
    Long: `Push branches, check CI status, auto-fix failures, and merge PRs.

Commands:
  hal ci push      Push branch and open draft PR
  hal ci status    Check CI pipeline results
  hal ci fix       Auto-fix CI failures using an engine
  hal ci merge     Merge PR when CI is green

Prerequisites:
  GitHub authentication via $GITHUB_TOKEN or gh auth login.
  Run 'hal doctor' to verify.`,
    Example: `  hal ci push
  hal ci status --wait
  hal ci fix -e codex
  hal ci merge`,
}

func init() {
    rootCmd.AddCommand(ciCmd)
}
```

### `cmd/ci_push.go`

```go
var ciPushCmd = &cobra.Command{
    Use:   "push",
    Short: "Push branch and open draft PR",
    Long: `Push the current branch to origin and create a draft pull request.

If a PR already exists for this branch, it is returned without creating a new one.
PR title defaults to the feature name from prd.json, or the branch name.
PR body is auto-generated from prd.json stories and the latest report (if available).`,
    Example: `  hal ci push
  hal ci push --base develop
  hal ci push --title "feat: user auth"
  hal ci push --json`,
    Args: cobra.NoArgs,
    RunE: runCIPush,
}

// Flags
var (
    ciPushBaseFlag    string
    ciPushTitleFlag   string
    ciPushBodyFlag    string  // --body-from: "report" or literal text
    ciPushJSONFlag    bool
    ciPushDryRunFlag  bool
)

func init() {
    ciPushCmd.Flags().StringVarP(&ciPushBaseFlag, "base", "b", "", "PR target branch")
    ciPushCmd.Flags().StringVar(&ciPushTitleFlag, "title", "", "PR title")
    ciPushCmd.Flags().StringVar(&ciPushBodyFlag, "body-from", "", `PR body source: "report" or literal text`)
    ciPushCmd.Flags().BoolVar(&ciPushJSONFlag, "json", false, "Machine-readable output")
    ciPushCmd.Flags().BoolVar(&ciPushDryRunFlag, "dry-run", false, "Show what would happen")
    ciCmd.AddCommand(ciPushCmd)
}

// CIPushResult is the --json output.
type CIPushResult struct {
    ContractVersion int    `json:"contractVersion"`
    OK              bool   `json:"ok"`
    Branch          string `json:"branch"`
    PRNumber        int    `json:"prNumber,omitempty"`
    PRURL           string `json:"prUrl,omitempty"`
    Created         bool   `json:"created,omitempty"`
    Error           string `json:"error,omitempty"`
    Summary         string `json:"summary"`
}
```

### `cmd/ci_status.go`

```go
var ciStatusCmd = &cobra.Command{
    Use:   "status",
    Short: "Check CI pipeline results",
    Long: `Check the CI status for the current branch's pull request.

With --wait, polls every 30s until CI reaches a terminal state (passing/failing)
or the timeout is reached.`,
    Example: `  hal ci status
  hal ci status --wait
  hal ci status --wait --timeout 15m
  hal ci status --json`,
    Args: cobra.NoArgs,
    RunE: runCIStatus,
}

// Flags
var (
    ciStatusWaitFlag    bool
    ciStatusTimeoutFlag time.Duration
    ciStatusJSONFlag    bool
)

func init() {
    ciStatusCmd.Flags().BoolVar(&ciStatusWaitFlag, "wait", false, "Poll until CI completes")
    ciStatusCmd.Flags().DurationVar(&ciStatusTimeoutFlag, "timeout", 30*time.Minute, "Timeout for --wait")
    ciStatusCmd.Flags().BoolVar(&ciStatusJSONFlag, "json", false, "Machine-readable output")
    ciCmd.AddCommand(ciStatusCmd)
}

// CIStatusResult is the --json output.
type CIStatusResult struct {
    ContractVersion int               `json:"contractVersion"`
    OK              bool              `json:"ok"`
    PRNumber        int               `json:"prNumber,omitempty"`
    PRURL           string            `json:"prUrl,omitempty"`
    Status          string            `json:"status"` // passing, failing, pending
    Passed          []string          `json:"passed,omitempty"`
    Failed          []string          `json:"failed,omitempty"`
    Pending         []string          `json:"pending,omitempty"`
    FailureLogs     map[string]string `json:"failureLogs,omitempty"`
    Error           string            `json:"error,omitempty"`
    Summary         string            `json:"summary"`
}
```

### `cmd/ci_fix.go`

```go
var ciFixCmd = &cobra.Command{
    Use:   "fix",
    Short: "Auto-fix CI failures using an engine",
    Long: `Read CI failure logs, generate fixes using an AI engine, commit, and push.

This is a single-shot fix per invocation. Use --max-attempts to retry
automatically if the first fix doesn't resolve the issue.

The fix is a focused engine prompt — not a full hal run. The engine
receives the CI failure logs and the codebase, and makes targeted fixes.`,
    Example: `  hal ci fix
  hal ci fix --max-attempts 3
  hal ci fix -e claude
  hal ci fix --json`,
    Args: cobra.NoArgs,
    RunE: runCIFix,
}

// Flags
var (
    ciFixMaxAttemptsFlag int
    ciFixEngineFlag      string
    ciFixJSONFlag        bool
)

func init() {
    ciFixCmd.Flags().IntVar(&ciFixMaxAttemptsFlag, "max-attempts", 3, "Max fix attempts")
    ciFixCmd.Flags().StringVarP(&ciFixEngineFlag, "engine", "e", "codex", "Engine to use")
    ciFixCmd.Flags().BoolVar(&ciFixJSONFlag, "json", false, "Machine-readable output")
    ciCmd.AddCommand(ciFixCmd)
}

// CIFixResult is the --json output.
type CIFixResult struct {
    ContractVersion int         `json:"contractVersion"`
    OK              bool        `json:"ok"`
    Attempts        int         `json:"attempts"`
    CIStatus        string      `json:"ciStatus"` // passing, failing after all attempts
    Fixes           []FixDetail `json:"fixes,omitempty"`
    Error           string      `json:"error,omitempty"`
    Summary         string      `json:"summary"`
}

type FixDetail struct {
    Attempt    int    `json:"attempt"`
    CheckName  string `json:"checkName"`
    CommitHash string `json:"commitHash"`
    CommitMsg  string `json:"commitMessage"`
}
```

### `cmd/ci_merge.go`

```go
var ciMergeCmd = &cobra.Command{
    Use:   "merge",
    Short: "Merge PR when CI is green",
    Long: `Merge the pull request for the current branch.

Requires all CI checks to be passing. If checks are failing,
the command refuses and suggests 'hal ci fix'.

Default merge strategy is squash. Remote branch is deleted after merge.`,
    Example: `  hal ci merge
  hal ci merge --strategy rebase
  hal ci merge --delete-branch=false
  hal ci merge --json
  hal ci merge --dry-run`,
    Args: cobra.NoArgs,
    RunE: runCIMerge,
}

// Flags
var (
    ciMergeStrategyFlag     string
    ciMergeDeleteBranchFlag bool
    ciMergeJSONFlag         bool
    ciMergeDryRunFlag       bool
)

func init() {
    ciMergeCmd.Flags().StringVar(&ciMergeStrategyFlag, "strategy", "squash", "Merge strategy: squash, merge, rebase")
    ciMergeCmd.Flags().BoolVar(&ciMergeDeleteBranchFlag, "delete-branch", true, "Delete remote branch after merge")
    ciMergeCmd.Flags().BoolVar(&ciMergeJSONFlag, "json", false, "Machine-readable output")
    ciMergeCmd.Flags().BoolVar(&ciMergeDryRunFlag, "dry-run", false, "Show what would happen")
    ciCmd.AddCommand(ciMergeCmd)
}

// CIMergeResult is the --json output.
type CIMergeResult struct {
    ContractVersion int    `json:"contractVersion"`
    OK              bool   `json:"ok"`
    PRNumber        int    `json:"prNumber,omitempty"`
    MergeCommitSHA  string `json:"mergeCommitSha,omitempty"`
    Strategy        string `json:"strategy,omitempty"`
    Error           string `json:"error,omitempty"`
    Summary         string `json:"summary"`
}
```

---

## 7. `gh` CLI Fallback

When `go-github` can't authenticate (no `$GITHUB_TOKEN`), fall back to `gh`:

```go
// internal/ci/gh_fallback.go

type ghFallback struct{}

func (g *ghFallback) Push(branch string) error {
    return exec.Command("git", "push", "-u", "origin", branch).Run()
}

func (g *ghFallback) CreatePR(title, body, base, head string) (url string, num int, err error) {
    args := []string{"pr", "create", "--draft", "--title", title, "--body", body}
    if base != "" {
        args = append(args, "--base", base)
    }
    out, err := exec.Command("gh", args...).Output()
    if err != nil {
        return "", 0, err
    }
    url = strings.TrimSpace(string(out))
    // Parse PR number from URL
    num = parsePRNumber(url)
    return url, num, nil
}

func (g *ghFallback) GetCheckStatus(branch string) (*CheckResult, error) {
    out, err := exec.Command("gh", "pr", "checks", "--json",
        "name,state,conclusion", "-q", ".").Output()
    // Parse JSON output...
}

func (g *ghFallback) MergePR(strategy string) error {
    args := []string{"pr", "merge", "--" + strategy}
    return exec.Command("gh", args...).Run()
}
```

Selection logic:

```go
func newCIClient(ctx context.Context) (CIClient, error) {
    token, err := ResolveToken()
    if err != nil {
        // No token — check if gh is available
        if _, ghErr := exec.LookPath("gh"); ghErr != nil {
            return nil, fmt.Errorf("no GitHub auth: set $GITHUB_TOKEN or install gh CLI")
        }
        return &ghFallback{}, nil
    }
    return newGitHubAPIClient(ctx, token)
}
```

---

## 8. Integration with `hal auto` Pipeline

`internal/compound/pipeline.go` calls `internal/ci/` directly:

```go
func (p *Pipeline) runCIStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    p.display.ShowInfo("   Step: ci\n")

    if opts.SkipCI {
        p.display.ShowInfo("   Skipping CI (--skip-ci)\n")
        state.Step = StepArchive
        return p.saveState(state)
    }

    if opts.DryRun {
        p.display.ShowInfo("   [dry-run] Would push, create PR, wait for CI, merge\n")
        state.Step = StepArchive
        return nil
    }

    // 1. Push + PR
    body := buildPRBody(state)
    pushResult, err := ci.PushAndCreatePR(ctx, ci.PushOpts{
        BaseBranch: state.BaseBranch,
        Title:      state.Analysis.PriorityItem, // or derived from prd.json
        Body:       body,
        Draft:      true,
    })
    if err != nil {
        return fmt.Errorf("push failed: %w", err)
    }
    state.PRUrl = pushResult.PRURL
    p.display.ShowInfo("   PR: %s\n", pushResult.PRURL)

    // 2. Wait for CI
    p.display.ShowInfo("   Waiting for CI...\n")
    checkResult, err := ci.WaitForChecks(ctx, ci.WaitOpts{})
    if err != nil {
        return fmt.Errorf("CI check failed: %w", err)
    }

    // 3. Fix loop
    for checkResult.Status == ci.StatusFailing && state.CIAttempts < 3 {
        state.CIAttempts++
        p.display.ShowInfo("   CI failing, fix attempt %d/3...\n", state.CIAttempts)
        p.saveState(state)

        _, err := ci.FixWithEngine(ctx, checkResult, ci.FixOpts{
            Engine:  p.engine,
            Display: p.display,
        })
        if err != nil {
            return fmt.Errorf("fix attempt %d failed: %w", state.CIAttempts, err)
        }

        p.display.ShowInfo("   Waiting for CI...\n")
        checkResult, err = ci.WaitForChecks(ctx, ci.WaitOpts{})
        if err != nil {
            return fmt.Errorf("CI check after fix failed: %w", err)
        }
    }

    if checkResult.Status != ci.StatusPassing {
        return fmt.Errorf("CI still failing after %d fix attempts", state.CIAttempts)
    }

    // 4. Merge
    p.display.ShowInfo("   CI green, merging...\n")
    mergeResult, err := ci.MergePR(ctx, ci.MergeOpts{
        Strategy:     "squash",
        DeleteBranch: true,
    })
    if err != nil {
        return fmt.Errorf("merge failed: %w", err)
    }
    p.display.ShowInfo("   Merged: %s\n", mergeResult.SHA[:7])

    state.Step = StepArchive
    return p.saveState(state)
}
```

---

## 9. Migration from Current `pr` Step

The current `internal/compound/git.go` functions move to `internal/ci/`:

| Current location | New location | Notes |
|---|---|---|
| `compound.PushBranch()` | `ci.gitPush()` (internal) | Used by `ci.PushAndCreatePR` |
| `compound.CreatePR()` | `ci.PushAndCreatePR()` | Now uses go-github, not just gh CLI |
| `compound.CreateBranch()` | stays in `compound` | Not a CI operation |
| `compound.CurrentBranch()` | stays in `compound` | General git utility |

The `StepPR` case in pipeline.go maps to `StepCI` (see auto refactor spec).

---

## 10. Dependencies

### Go modules to add

```
github.com/google/go-github/v68
golang.org/x/oauth2
```

### Required external tools (optional, for fallback)

- `gh` CLI — only needed if `$GITHUB_TOKEN` is not set
- `git` — already required by hal

---

## 11. JSON Contract Documents

Add to `docs/contracts/`:

### `ci-push-v1.md`

```markdown
# CI Push Contract v1

**Command:** `hal ci push --json`

| Field | Type | Description |
|---|---|---|
| contractVersion | int | Always 1 |
| ok | bool | Whether push + PR succeeded |
| branch | string | Branch name that was pushed |
| prNumber | int | PR number (omitted on error) |
| prUrl | string | PR URL (omitted on error) |
| created | bool | true if new PR, false if existing |
| error | string | Error message (omitted on success) |
| summary | string | Human-readable summary |
```

### `ci-status-v1.md`

```markdown
# CI Status Contract v1

**Command:** `hal ci status --json`

| Field | Type | Description |
|---|---|---|
| contractVersion | int | Always 1 |
| ok | bool | Whether status check succeeded |
| prNumber | int | PR number |
| prUrl | string | PR URL |
| status | string | "passing", "failing", or "pending" |
| passed | []string | Names of passing checks |
| failed | []string | Names of failing checks |
| pending | []string | Names of pending checks |
| failureLogs | map | Check name → failure log tail |
| error | string | Error (omitted on success) |
| summary | string | Human-readable summary |
```

---

## 12. Test Plan

### Unit tests

| Test | File | Validates |
|---|---|---|
| Token resolution priority | `internal/ci/auth_test.go` | $GITHUB_TOKEN → $GH_TOKEN → gh auth token |
| Remote URL parsing (HTTPS) | `internal/ci/auth_test.go` | `https://github.com/owner/repo.git` → owner, repo |
| Remote URL parsing (SSH) | `internal/ci/auth_test.go` | `git@github.com:owner/repo.git` → owner, repo |
| CheckResult status classification | `internal/ci/status_test.go` | pending > failing > passing priority |
| Fix prompt generation | `internal/ci/fix_test.go` | Failure logs included, instructions present |
| Merge refuses when failing | `internal/ci/merge_test.go` | Returns error with "hal ci fix" hint |
| PR title from prd.json | `internal/ci/push_test.go` | Falls back to branch name |
| CI JSON contract fields | `cmd/ci_push_test.go` | All required fields present |
| Strategy validation | `internal/ci/merge_test.go` | Only squash/merge/rebase accepted |

### Integration tests (tagged `integration`)

| Test | Validates |
|---|---|
| Push to real GitHub repo | End-to-end push + PR creation |
| Check status on real PR | CI status polling |
| gh fallback when no token | Fallback path works |

### Command tests

| Test | File | Validates |
|---|---|---|
| `hal ci push --dry-run` | `cmd/ci_push_test.go` | No side effects, shows what would happen |
| `hal ci status --json` | `cmd/ci_status_test.go` | JSON output matches contract |
| `hal ci fix --json` | `cmd/ci_fix_test.go` | JSON output, engine flag wired |
| `hal ci merge --dry-run` | `cmd/ci_merge_test.go` | No side effects |
| `hal ci --help` | `cmd/ci_test.go` | All subcommands listed |
| Doctor check for github_auth | `cmd/doctor_test.go` | Warning when no token |
