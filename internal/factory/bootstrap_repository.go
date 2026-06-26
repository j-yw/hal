package factory

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	BootstrapStepCloneRepository  = "clone_repository"
	BootstrapStepEnsureWorkspace  = "ensure_workspace_root"
	BootstrapStepCleanEngineLinks = "clean_engine_links"
	BootstrapStepFetchRepository  = "fetch_repository"
	BootstrapStepCheckoutBase     = "checkout_base"
	BootstrapStepCheckLocalRun    = "check_local_run_branch"
	BootstrapStepCheckRemoteRun   = "check_remote_run_branch"
	BootstrapStepFetchRunBranch   = "fetch_run_branch"
	BootstrapStepCheckoutRun      = "checkout_run_branch"
	BootstrapStepCreateRunBranch  = "create_run_branch"

	bootstrapCleanEngineLinksScript = `git clean -fd -- .claude/skills/factory .pi/skills/factory && { git checkout -- .pi/skills/factory/SKILL.md 2>/dev/null || true; }`
	bootstrapGitHubTokenEnvKey      = "GITHUB_TOKEN"
	bootstrapGitHubExtraHeaderKey   = "http.https://github.com/.extraheader"
)

var (
	errBootstrapRepositoryURLRequired = errors.New("bootstrap repository URL is required")
	errBootstrapBaseBranchRequired    = errors.New("bootstrap base branch is required")
	errBootstrapWorkspaceDirRequired  = errors.New("bootstrap workspace dir is required")
)

// BootstrapBranchExistsFunc checks for a local or remote branch without tying
// repository bootstrap tests to real git refs.
type BootstrapBranchExistsFunc func(ctx context.Context, repoPath string, branch string) (bool, error)

// BootstrapRepositoryDeps holds dependencies for repository setup without
// tying tests or callers to the host filesystem or real git commands.
type BootstrapRepositoryDeps struct {
	Executor           BootstrapCommandExecutor
	Now                func() time.Time
	RepoExists         func(path string) (bool, error)
	LocalBranchExists  BootstrapBranchExistsFunc
	RemoteBranchExists BootstrapBranchExistsFunc
}

type bootstrapRepositoryCommand struct {
	stepName string
	command  BootstrapCommand
}

type bootstrapBranchProbeFailure struct {
	step          BootstrapStepResult
	commandResult BootstrapCommandResult
	failure       BootstrapFailure
	err           error
}

func (e *bootstrapBranchProbeFailure) Error() string {
	return e.err.Error()
}

func (e *bootstrapBranchProbeFailure) Unwrap() error {
	return e.err
}

// BootstrapRepositoryCheckout clones or updates the target repository, checks
// out the requested base branch, and prepares the explicit run branch when one
// is provided.
func BootstrapRepositoryCheckout(ctx context.Context, request BootstrapRequest, deps BootstrapRepositoryDeps) (BootstrapResult, error) {
	repoPath, err := normalizeBootstrapRepoPath(request.WorkspaceDir)
	result := BootstrapResult{
		RepoPath: repoPath,
	}
	if err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
	}
	if err := validateBootstrapRequiredEnv(request); err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
	}

	commands, err := bootstrapRepositoryCommands(request, deps, repoPath)
	if err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
	}

	result = BootstrapResult{
		RepoPath: repoPath,
		Steps:    make([]BootstrapStepResult, 0, len(commands)),
		Timeline: make([]BootstrapTimelineEvent, 0, len(commands)),
	}

	if err := runBootstrapRepositoryCommands(ctx, request, deps, &result, commands); err != nil {
		return result, err
	}
	result.CheckedOutBranch = strings.TrimSpace(request.BaseBranch)

	runBranch := strings.TrimSpace(request.RunBranch)
	if runBranch == "" {
		return result, nil
	}

	runBranchCommands, err := bootstrapRunBranchCommands(ctx, request, deps, &result, repoPath)
	if err != nil {
		recordBootstrapBranchProbeFailure(&result, request, deps, err)
		return result, err
	}
	if err := runBootstrapRepositoryCommands(ctx, request, deps, &result, runBranchCommands); err != nil {
		return result, err
	}
	result.CheckedOutBranch = runBranch
	return result, nil
}

func recordBootstrapBranchProbeFailure(result *BootstrapResult, request BootstrapRequest, deps BootstrapRepositoryDeps, err error) {
	var probeFailure *bootstrapBranchProbeFailure
	if errors.As(err, &probeFailure) {
		failure := probeFailure.failure
		result.Failure = &failure
		recordBootstrapStepResult(result, request, probeFailure.step, probeFailure.commandResult, &failure)
		return
	}

	stepName := BootstrapStepCheckLocalRun
	if strings.Contains(strings.ToLower(err.Error()), "remote run branch") {
		stepName = BootstrapStepCheckRemoteRun
	}
	startedAt := deps.now()
	finishedAt := deps.now()
	step := BootstrapStepResult{
		Name:       stepName,
		Status:     RunStatusFailed,
		StartedAt:  startedAt,
		FinishedAt: &finishedAt,
	}
	failure := ClassifyBootstrapFailure(step.Name, "", "", err)
	result.Failure = &failure
	recordBootstrapStepResult(result, request, step, BootstrapCommandResult{}, &failure)
}

func runBootstrapRepositoryCommands(ctx context.Context, request BootstrapRequest, deps BootstrapRepositoryDeps, result *BootstrapResult, commands []bootstrapRepositoryCommand) error {
	for _, planned := range commands {
		if request.Options.DryRun {
			recordBootstrapStepResult(result, request, plannedBootstrapStep(deps, request, planned.stepName, planned.command), BootstrapCommandResult{}, nil)
			continue
		}

		step, commandResult, failure, err := RunBootstrapStep(ctx, deps.stepDeps(request), planned.stepName, planned.command)
		recordBootstrapStepResult(result, request, step, commandResult, failure)
		if err != nil {
			result.Failure = failure
			return err
		}
	}

	return nil
}

func bootstrapRepositoryCommands(request BootstrapRequest, deps BootstrapRepositoryDeps, repoPath string) ([]bootstrapRepositoryCommand, error) {
	repositoryURL := strings.TrimSpace(request.RepositoryURL)
	baseBranch := strings.TrimSpace(request.BaseBranch)
	if baseBranch == "" {
		return nil, errBootstrapBaseBranchRequired
	}

	exists, err := deps.repoExists(repoPath)
	if err != nil {
		return nil, fmt.Errorf("check repository path %q: %w", repoPath, err)
	}

	commands := make([]bootstrapRepositoryCommand, 0, 2)
	if exists {
		commands = append(commands, bootstrapRepositoryCommand{
			stepName: BootstrapStepCleanEngineLinks,
			command: BootstrapCommand{
				Name: "sh",
				Args: []string{"-lc", bootstrapCleanEngineLinksScript},
				Dir:  repoPath,
				Env:  bootstrapGitEnv(request),
			},
		})
		commands = append(commands, bootstrapRepositoryCommand{
			stepName: BootstrapStepFetchRepository,
			command: BootstrapCommand{
				Name: "git",
				Args: []string{"fetch", "--prune", "origin"},
				Dir:  repoPath,
				Env:  bootstrapGitEnv(request),
			},
		})
	} else {
		if repositoryURL == "" {
			return nil, errBootstrapRepositoryURLRequired
		}
		workspaceRoot := filepath.Dir(repoPath)
		commands = append(commands, bootstrapRepositoryCommand{
			stepName: BootstrapStepEnsureWorkspace,
			command: BootstrapCommand{
				Name: "mkdir",
				Args: []string{"-p", workspaceRoot},
			},
		})
		commands = append(commands, bootstrapRepositoryCommand{
			stepName: BootstrapStepCloneRepository,
			command: BootstrapCommand{
				Name: "git",
				Args: []string{"clone", repositoryURL, repoPath},
				Dir:  workspaceRoot,
				Env:  bootstrapGitEnv(request),
			},
		})
	}

	checkoutArgs := []string{"checkout", "-f", baseBranch}
	if exists {
		checkoutArgs = []string{"checkout", "-f", "-B", baseBranch, "origin/" + baseBranch}
	}
	commands = append(commands, bootstrapRepositoryCommand{
		stepName: BootstrapStepCheckoutBase,
		command: BootstrapCommand{
			Name: "git",
			Args: checkoutArgs,
			Dir:  repoPath,
			Env:  bootstrapGitEnv(request),
		},
	})

	return commands, nil
}

func bootstrapRunBranchCommands(ctx context.Context, request BootstrapRequest, deps BootstrapRepositoryDeps, result *BootstrapResult, repoPath string) ([]bootstrapRepositoryCommand, error) {
	runBranch := strings.TrimSpace(request.RunBranch)
	if runBranch == "" {
		return nil, nil
	}
	baseBranch := strings.TrimSpace(request.BaseBranch)

	localExists, err := deps.recordedLocalBranchExists(ctx, request, result, repoPath, runBranch)
	if err != nil {
		return nil, fmt.Errorf("check local run branch %q: %w", runBranch, err)
	}
	if localExists {
		return []bootstrapRepositoryCommand{
			{
				stepName: BootstrapStepCheckoutRun,
				command: BootstrapCommand{
					Name: "git",
					Args: []string{"checkout", "-f", runBranch},
					Dir:  repoPath,
					Env:  bootstrapGitEnv(request),
				},
			},
		}, nil
	}

	remoteExists, err := deps.recordedRemoteBranchExists(ctx, request, result, repoPath, runBranch)
	if err != nil {
		return nil, fmt.Errorf("check remote run branch %q: %w", runBranch, err)
	}
	if remoteExists {
		return []bootstrapRepositoryCommand{
			{
				stepName: BootstrapStepFetchRunBranch,
				command: BootstrapCommand{
					Name: "git",
					Args: []string{"fetch", "origin", runBranch + ":refs/remotes/origin/" + runBranch},
					Dir:  repoPath,
					Env:  bootstrapGitEnv(request),
				},
			},
			{
				stepName: BootstrapStepCheckoutRun,
				command: BootstrapCommand{
					Name: "git",
					Args: []string{"checkout", "-f", "--track", "origin/" + runBranch},
					Dir:  repoPath,
					Env:  bootstrapGitEnv(request),
				},
			},
		}, nil
	}

	return []bootstrapRepositoryCommand{
		{
			stepName: BootstrapStepCreateRunBranch,
			command: BootstrapCommand{
				Name: "git",
				Args: []string{"checkout", "-f", "-b", runBranch, baseBranch},
				Dir:  repoPath,
				Env:  bootstrapGitEnv(request),
			},
		},
	}, nil
}

func plannedBootstrapStep(deps BootstrapRepositoryDeps, request BootstrapRequest, stepName string, command BootstrapCommand) BootstrapStepResult {
	command = injectBootstrapRequestEnv(request, command)
	command = NewBootstrapSanitizer(request).SanitizeCommand(command)
	return BootstrapStepResult{
		Name:           strings.TrimSpace(stepName),
		Status:         RunStatusPending,
		CommandSummary: command.Summary(),
		StartedAt:      deps.now(),
	}
}

func normalizeBootstrapRepoPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errBootstrapWorkspaceDirRequired
	}
	return filepath.Clean(path), nil
}

func bootstrapGitEnv(request BootstrapRequest) map[string]string {
	env := map[string]string{
		"GIT_TERMINAL_PROMPT": "0",
	}
	if header := bootstrapGitHubAuthHeaderForRequest(request); header != "" {
		index := bootstrapGitConfigIndex(request.Env)
		env["GIT_CONFIG_COUNT"] = strconv.Itoa(index + 1)
		env[fmt.Sprintf("GIT_CONFIG_KEY_%d", index)] = bootstrapGitHubExtraHeaderKey
		env[fmt.Sprintf("GIT_CONFIG_VALUE_%d", index)] = header
	}
	return env
}

func bootstrapGitHubAuthHeaderForRequest(request BootstrapRequest) string {
	token := strings.TrimSpace(request.Env[bootstrapGitHubTokenEnvKey])
	if token == "" {
		return ""
	}
	repositoryURL := strings.TrimSpace(request.RepositoryURL)
	if repositoryURL != "" && !bootstrapIsTrustedGitHubHTTPSURL(repositoryURL) {
		return ""
	}
	return bootstrapGitHubAuthHeader(token)
}

func bootstrapIsTrustedGitHubHTTPSURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https") && strings.EqualFold(parsed.Hostname(), "github.com")
}

func bootstrapGitConfigIndex(env map[string]string) int {
	if env == nil {
		return 0
	}
	count, err := strconv.Atoi(strings.TrimSpace(env["GIT_CONFIG_COUNT"]))
	if err != nil || count < 0 {
		return 0
	}
	return count
}

func bootstrapGitHubAuthHeader(token string) string {
	credential := bootstrapGitHubBasicAuthCredential(token)
	if credential == "" {
		return ""
	}
	return "AUTHORIZATION: basic " + credential
}

func bootstrapGitHubBasicAuthCredential(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
}

func (d BootstrapRepositoryDeps) stepDeps(request BootstrapRequest) BootstrapStepDeps {
	return BootstrapStepDeps{
		Executor: d.Executor,
		Now:      d.Now,
		Request:  request,
	}
}

func (d BootstrapRepositoryDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}

func (d BootstrapRepositoryDeps) repoExists(path string) (bool, error) {
	if d.RepoExists != nil {
		return d.RepoExists(path)
	}

	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("repository path exists but is not a directory")
	}

	hasGitMetadata, err := hasBootstrapGitMetadata(path)
	if err != nil {
		return false, err
	}
	if hasGitMetadata {
		return true, nil
	}

	empty, err := bootstrapDirIsEmpty(path)
	if err != nil {
		return false, err
	}
	if empty {
		return false, nil
	}
	return false, fmt.Errorf("repository path exists but is not a git checkout and is not empty")
}

func hasBootstrapGitMetadata(path string) (bool, error) {
	_, err := os.Stat(filepath.Join(path, ".git"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func bootstrapDirIsEmpty(path string) (bool, error) {
	dir, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer dir.Close()

	_, err = dir.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func (d BootstrapRepositoryDeps) localBranchExists(ctx context.Context, request BootstrapRequest, repoPath string, branch string) (bool, error) {
	if d.LocalBranchExists != nil {
		return d.LocalBranchExists(ctx, repoPath, branch)
	}
	if request.Options.DryRun || d.Executor == nil {
		return false, nil
	}
	return d.probeBranch(ctx, request, localRunBranchProbeCommand(repoPath, branch), BootstrapStepCheckLocalRun, 1)
}

func (d BootstrapRepositoryDeps) remoteBranchExists(ctx context.Context, request BootstrapRequest, repoPath string, branch string) (bool, error) {
	if d.RemoteBranchExists != nil {
		return d.RemoteBranchExists(ctx, repoPath, branch)
	}
	if request.Options.DryRun || d.Executor == nil {
		return false, nil
	}
	return d.probeBranch(ctx, request, remoteRunBranchProbeCommand(request, repoPath, branch), BootstrapStepCheckRemoteRun, 2)
}

func (d BootstrapRepositoryDeps) recordedLocalBranchExists(ctx context.Context, request BootstrapRequest, result *BootstrapResult, repoPath string, branch string) (bool, error) {
	if d.LocalBranchExists != nil || request.Options.DryRun || d.Executor == nil {
		return d.localBranchExists(ctx, request, repoPath, branch)
	}
	return d.recordedProbeBranch(ctx, request, result, localRunBranchProbeCommand(repoPath, branch), BootstrapStepCheckLocalRun, 1)
}

func (d BootstrapRepositoryDeps) recordedRemoteBranchExists(ctx context.Context, request BootstrapRequest, result *BootstrapResult, repoPath string, branch string) (bool, error) {
	if d.RemoteBranchExists != nil || request.Options.DryRun || d.Executor == nil {
		return d.remoteBranchExists(ctx, request, repoPath, branch)
	}
	return d.recordedProbeBranch(ctx, request, result, remoteRunBranchProbeCommand(request, repoPath, branch), BootstrapStepCheckRemoteRun, 2)
}

func localRunBranchProbeCommand(repoPath string, branch string) BootstrapCommand {
	return BootstrapCommand{
		Name: "git",
		Args: []string{"show-ref", "--verify", "--quiet", "refs/heads/" + branch},
		Dir:  repoPath,
		Env:  bootstrapGitEnv(BootstrapRequest{}),
	}
}

func remoteRunBranchProbeCommand(request BootstrapRequest, repoPath string, branch string) BootstrapCommand {
	return BootstrapCommand{
		Name: "git",
		Args: []string{"ls-remote", "--exit-code", "--heads", "origin", branch},
		Dir:  repoPath,
		Env:  bootstrapGitEnv(request),
	}
}

func (d BootstrapRepositoryDeps) probeBranch(ctx context.Context, request BootstrapRequest, command BootstrapCommand, stepName string, missingExitCode int) (bool, error) {
	exists, step, commandResult, failure, err := d.probeBranchStep(ctx, request, command, stepName, missingExitCode)
	if err != nil {
		return false, bootstrapBranchProbeStepError(step, commandResult, failure, err)
	}
	return exists, nil
}

func (d BootstrapRepositoryDeps) recordedProbeBranch(ctx context.Context, request BootstrapRequest, result *BootstrapResult, command BootstrapCommand, stepName string, missingExitCode int) (bool, error) {
	exists, step, commandResult, failure, err := d.probeBranchStep(ctx, request, command, stepName, missingExitCode)
	if err != nil {
		return false, bootstrapBranchProbeStepError(step, commandResult, failure, err)
	}
	if result != nil {
		recordBootstrapStepResult(result, request, step, commandResult, nil)
	}
	return exists, nil
}

func (d BootstrapRepositoryDeps) probeBranchStep(ctx context.Context, request BootstrapRequest, command BootstrapCommand, stepName string, missingExitCode int) (bool, BootstrapStepResult, BootstrapCommandResult, *BootstrapFailure, error) {
	step, commandResult, failure, err := RunBootstrapStep(ctx, d.stepDeps(request), stepName, command)
	if err != nil {
		if commandResult.ExitCode == missingExitCode {
			step.Status = RunStatusSucceeded
			return false, step, commandResult, nil, nil
		}
		return false, step, commandResult, failure, err
	}
	return true, step, commandResult, nil, nil
}

func bootstrapBranchProbeStepError(step BootstrapStepResult, commandResult BootstrapCommandResult, failure *BootstrapFailure, err error) error {
	if failure == nil {
		return err
	}
	return &bootstrapBranchProbeFailure{
		step:          step,
		commandResult: commandResult,
		failure:       *failure,
		err:           err,
	}
}

func (d BootstrapRepositoryDeps) branchProbeFailure(request BootstrapRequest, stepName string, command BootstrapCommand, result BootstrapCommandResult, err error) error {
	startedAt := d.now()
	finishedAt := d.now()
	sanitizer := NewBootstrapSanitizer(request)
	sanitizedCommand := sanitizer.SanitizeCommand(command)
	sanitizedResult := sanitizer.SanitizeCommandResult(result)
	commandSummary := sanitizedCommand.Summary()
	failure := ClassifyBootstrapFailure(stepName, commandSummary, result.classificationOutput(), err)

	return &bootstrapBranchProbeFailure{
		step: BootstrapStepResult{
			Name:           stepName,
			Status:         RunStatusFailed,
			CommandSummary: commandSummary,
			StartedAt:      startedAt,
			FinishedAt:     &finishedAt,
			ExitCode:       result.ExitCode,
		},
		commandResult: sanitizedResult,
		failure:       failure,
		err:           err,
	}
}
