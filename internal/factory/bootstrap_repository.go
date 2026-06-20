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
)

var (
	errBootstrapRepositoryURLRequired = errors.New("bootstrap repository URL is required")
	errBootstrapBaseBranchRequired    = errors.New("bootstrap base branch is required")
	errBootstrapWorkspaceDirRequired  = errors.New("bootstrap workspace dir is required")
)

// BootstrapRepositoryDeps holds dependencies for repository setup without
// tying tests or callers to the host filesystem or real git commands.
type BootstrapRepositoryDeps struct {
	Executor   BootstrapCommandExecutor
	Now        func() time.Time
	RepoExists func(path string) (bool, error)
}

type bootstrapRepositoryCommand struct {
	stepName string
	command  BootstrapCommand
}

// BootstrapRepositoryCheckout clones or updates the target repository and
// checks out the requested base branch using the injected bootstrap executor.
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

	for _, planned := range commands {
		if request.Options.DryRun {
			result.Steps = append(result.Steps, plannedBootstrapStep(deps, planned.stepName, planned.command))
			continue
		}

		step, _, failure, err := RunBootstrapStep(ctx, deps.stepDeps(), planned.stepName, planned.command)
		result.Steps = append(result.Steps, step)
		if err != nil {
			result.Failure = failure
			return result, err
		}
	}

	result.CheckedOutBranch = strings.TrimSpace(request.BaseBranch)
	return result, nil
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
