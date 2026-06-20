package factory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	BootstrapStepCloneRepository = "clone_repository"
	BootstrapStepFetchRepository = "fetch_repository"
	BootstrapStepCheckoutBase    = "checkout_base"
	BootstrapStepFetchRunBranch  = "fetch_run_branch"
	BootstrapStepCheckoutRun     = "checkout_run_branch"
	BootstrapStepCreateRunBranch = "create_run_branch"
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

// BootstrapRepositoryCheckout clones or updates the target repository, checks
// out the requested base branch, and prepares the explicit run branch when one
// is provided.
func BootstrapRepositoryCheckout(ctx context.Context, request BootstrapRequest, deps BootstrapRepositoryDeps) (BootstrapResult, error) {
	repoPath, err := normalizeBootstrapRepoPath(request.WorkspaceDir)
	if err != nil {
		return BootstrapResult{}, err
	}

	commands, err := bootstrapRepositoryCommands(request, deps, repoPath)
	if err != nil {
		return BootstrapResult{RepoPath: repoPath}, err
	}

	result := BootstrapResult{
		RepoPath: repoPath,
		Steps:    make([]BootstrapStepResult, 0, len(commands)),
	}

	if err := runBootstrapRepositoryCommands(ctx, request, deps, &result, commands); err != nil {
		return result, err
	}
	result.CheckedOutBranch = strings.TrimSpace(request.BaseBranch)

	runBranch := strings.TrimSpace(request.RunBranch)
	if runBranch == "" {
		return result, nil
	}

	runBranchCommands, err := bootstrapRunBranchCommands(ctx, request, deps, repoPath)
	if err != nil {
		return result, err
	}
	if err := runBootstrapRepositoryCommands(ctx, request, deps, &result, runBranchCommands); err != nil {
		return result, err
	}
	result.CheckedOutBranch = runBranch
	return result, nil
}

func runBootstrapRepositoryCommands(ctx context.Context, request BootstrapRequest, deps BootstrapRepositoryDeps, result *BootstrapResult, commands []bootstrapRepositoryCommand) error {
	for _, planned := range commands {
		if request.Options.DryRun {
			result.Steps = append(result.Steps, plannedBootstrapStep(deps, planned.stepName, planned.command))
			continue
		}

		step, _, failure, err := RunBootstrapStep(ctx, deps.stepDeps(), planned.stepName, planned.command)
		result.Steps = append(result.Steps, step)
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
			stepName: BootstrapStepFetchRepository,
			command: BootstrapCommand{
				Name: "git",
				Args: []string{"fetch", "--prune", "origin"},
				Dir:  repoPath,
				Env:  bootstrapGitEnv(),
			},
		})
	} else {
		if repositoryURL == "" {
			return nil, errBootstrapRepositoryURLRequired
		}
		commands = append(commands, bootstrapRepositoryCommand{
			stepName: BootstrapStepCloneRepository,
			command: BootstrapCommand{
				Name: "git",
				Args: []string{"clone", repositoryURL, repoPath},
				Dir:  filepath.Dir(repoPath),
				Env:  bootstrapGitEnv(),
			},
		})
	}

	commands = append(commands, bootstrapRepositoryCommand{
		stepName: BootstrapStepCheckoutBase,
		command: BootstrapCommand{
			Name: "git",
			Args: []string{"checkout", baseBranch},
			Dir:  repoPath,
			Env:  bootstrapGitEnv(),
		},
	})

	return commands, nil
}

func bootstrapRunBranchCommands(ctx context.Context, request BootstrapRequest, deps BootstrapRepositoryDeps, repoPath string) ([]bootstrapRepositoryCommand, error) {
	runBranch := strings.TrimSpace(request.RunBranch)
	if runBranch == "" {
		return nil, nil
	}
	baseBranch := strings.TrimSpace(request.BaseBranch)

	localExists, err := deps.localBranchExists(ctx, repoPath, runBranch, request.Options.DryRun)
	if err != nil {
		return nil, fmt.Errorf("check local run branch %q: %w", runBranch, err)
	}
	if localExists {
		return []bootstrapRepositoryCommand{
			{
				stepName: BootstrapStepCheckoutRun,
				command: BootstrapCommand{
					Name: "git",
					Args: []string{"checkout", runBranch},
					Dir:  repoPath,
					Env:  bootstrapGitEnv(),
				},
			},
		}, nil
	}

	remoteExists, err := deps.remoteBranchExists(ctx, repoPath, runBranch, request.Options.DryRun)
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
					Env:  bootstrapGitEnv(),
				},
			},
			{
				stepName: BootstrapStepCheckoutRun,
				command: BootstrapCommand{
					Name: "git",
					Args: []string{"checkout", "--track", "origin/" + runBranch},
					Dir:  repoPath,
					Env:  bootstrapGitEnv(),
				},
			},
		}, nil
	}

	return []bootstrapRepositoryCommand{
		{
			stepName: BootstrapStepCreateRunBranch,
			command: BootstrapCommand{
				Name: "git",
				Args: []string{"checkout", "-b", runBranch, baseBranch},
				Dir:  repoPath,
				Env:  bootstrapGitEnv(),
			},
		},
	}, nil
}

func plannedBootstrapStep(deps BootstrapRepositoryDeps, stepName string, command BootstrapCommand) BootstrapStepResult {
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

func bootstrapGitEnv() map[string]string {
	return map[string]string{
		"GIT_TERMINAL_PROMPT": "0",
	}
}

func (d BootstrapRepositoryDeps) stepDeps() BootstrapStepDeps {
	return BootstrapStepDeps{
		Executor: d.Executor,
		Now:      d.Now,
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
	return true, nil
}

func (d BootstrapRepositoryDeps) localBranchExists(ctx context.Context, repoPath string, branch string, dryRun bool) (bool, error) {
	if d.LocalBranchExists != nil {
		return d.LocalBranchExists(ctx, repoPath, branch)
	}
	if dryRun || d.Executor == nil {
		return false, nil
	}
	return d.probeBranch(ctx, BootstrapCommand{
		Name: "git",
		Args: []string{"show-ref", "--verify", "--quiet", "refs/heads/" + branch},
		Dir:  repoPath,
		Env:  bootstrapGitEnv(),
	}, 1)
}

func (d BootstrapRepositoryDeps) remoteBranchExists(ctx context.Context, repoPath string, branch string, dryRun bool) (bool, error) {
	if d.RemoteBranchExists != nil {
		return d.RemoteBranchExists(ctx, repoPath, branch)
	}
	if dryRun || d.Executor == nil {
		return false, nil
	}
	return d.probeBranch(ctx, BootstrapCommand{
		Name: "git",
		Args: []string{"ls-remote", "--exit-code", "--heads", "origin", branch},
		Dir:  repoPath,
		Env:  bootstrapGitEnv(),
	}, 2)
}

func (d BootstrapRepositoryDeps) probeBranch(ctx context.Context, command BootstrapCommand, missingExitCode int) (bool, error) {
	result, err := d.Executor.Run(ctx, command)
	if err != nil {
		if result.ExitCode == missingExitCode {
			return false, nil
		}
		return false, err
	}
	switch result.ExitCode {
	case 0:
		return true, nil
	case missingExitCode:
		return false, nil
	}
	if result.ExitCode != 0 {
		return false, bootstrapCommandExitError{exitCode: result.ExitCode}
	}
	return true, nil
}
