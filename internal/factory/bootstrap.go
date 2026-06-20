package factory

import (
	"context"
	"strings"
	"time"
)

const (
	BootstrapStepFinalCheckHalDoctor = "final_check_hal_doctor"

	bootstrapFinalCheckStepPrefix = "final_check_"
)

// BootstrapDeps holds all dependencies needed by the high-level workspace
// bootstrap entrypoint. Nil FinalChecks runs the default Hal doctor check after
// repository, tooling, and Hal setup; an empty slice disables final checks.
type BootstrapDeps struct {
	Executor           BootstrapCommandExecutor
	Now                func() time.Time
	RepoExists         func(path string) (bool, error)
	LocalBranchExists  BootstrapBranchExistsFunc
	RemoteBranchExists BootstrapBranchExistsFunc
	HalCheck           BootstrapToolingCheck
	EngineChecks       []BootstrapToolingCheck
	FinalChecks        []BootstrapToolingCheck
}

type bootstrapFinalCheckDeps struct {
	Executor BootstrapCommandExecutor
	Now      func() time.Time
	Checks   []BootstrapToolingCheck
}

// BootstrapWorkspace prepares a factory workspace in deterministic order:
// repository checkout, run branch preparation, tooling verification, Hal setup,
// and final workspace checks.
func BootstrapWorkspace(ctx context.Context, request BootstrapRequest, deps BootstrapDeps) (BootstrapResult, error) {
	result := BootstrapResult{
		RepoPath: bootstrapToolingRepoPath(request.WorkspaceDir),
	}

	repositoryResult, err := BootstrapRepositoryCheckout(ctx, request, deps.repositoryDeps())
	appendBootstrapResult(&result, repositoryResult)
	if err != nil {
		return result, err
	}

	toolingResult, err := BootstrapVerifyTooling(ctx, request, deps.toolingDeps())
	appendBootstrapResult(&result, toolingResult)
	if err != nil {
		return result, err
	}

	halResult, err := BootstrapRefreshHal(ctx, request, deps.halDeps())
	appendBootstrapResult(&result, halResult)
	if err != nil {
		return result, err
	}

	finalResult, err := bootstrapRunFinalChecks(ctx, request, deps.finalCheckDeps(result.RepoPath))
	appendBootstrapResult(&result, finalResult)
	if err != nil {
		return result, err
	}

	return result, nil
}

func bootstrapRunFinalChecks(ctx context.Context, request BootstrapRequest, deps bootstrapFinalCheckDeps) (BootstrapResult, error) {
	repoPath, err := normalizeBootstrapRepoPath(request.WorkspaceDir)
	if err != nil {
		return BootstrapResult{}, err
	}

	checks := normalizeBootstrapFinalChecks(repoPath, deps.Checks)
	result := BootstrapResult{
		RepoPath: repoPath,
		Steps:    make([]BootstrapStepResult, 0, len(checks)),
		Timeline: make([]BootstrapTimelineEvent, 0, len(checks)),
	}

	for _, check := range checks {
		if err := validateBootstrapToolingCheck(check); err != nil {
			return result, err
		}

		stepName := bootstrapFinalCheckStepName(check)
		if request.Options.DryRun {
			recordBootstrapStepResult(&result, request, plannedBootstrapFinalCheckStep(deps, request, stepName, check.Command), BootstrapCommandResult{}, nil)
			continue
		}

		step, commandResult, failure, err := RunBootstrapStep(ctx, BootstrapStepDeps{
			Executor: deps.Executor,
			Now:      deps.Now,
			Request:  request,
		}, stepName, check.Command)
		recordBootstrapStepResult(&result, request, step, commandResult, failure)
		if err != nil {
			result.Failure = failure
			return result, err
		}
	}

	return result, nil
}

func appendBootstrapResult(dst *BootstrapResult, src BootstrapResult) {
	if dst.RepoPath == "" {
		dst.RepoPath = src.RepoPath
	}
	if src.CheckedOutBranch != "" {
		dst.CheckedOutBranch = src.CheckedOutBranch
	}
	if len(src.Steps) > 0 {
		dst.Steps = append(dst.Steps, src.Steps...)
	}
	if len(src.Timeline) > 0 {
		dst.Timeline = append(dst.Timeline, src.Timeline...)
	}
	if src.Failure != nil {
		dst.Failure = src.Failure
	}
}

func normalizeBootstrapFinalChecks(repoPath string, checks []BootstrapToolingCheck) []BootstrapToolingCheck {
	if checks == nil {
		checks = []BootstrapToolingCheck{
			{
				Name: "hal_doctor",
				Command: BootstrapCommand{
					Name: "hal",
					Args: []string{"doctor", "--json"},
					Dir:  repoPath,
				},
			},
		}
	}

	normalized := make([]BootstrapToolingCheck, 0, len(checks))
	for _, check := range checks {
		if strings.TrimSpace(check.Command.Dir) == "" {
			check.Command.Dir = repoPath
		}
		normalized = append(normalized, check)
	}
	return normalized
}

func bootstrapFinalCheckStepName(check BootstrapToolingCheck) string {
	return bootstrapFinalCheckStepPrefix + bootstrapToolingStepToken(check)
}

func plannedBootstrapFinalCheckStep(deps bootstrapFinalCheckDeps, request BootstrapRequest, stepName string, command BootstrapCommand) BootstrapStepResult {
	command = injectBootstrapRequestEnv(request, command)
	command = NewBootstrapSanitizer(request).SanitizeCommand(command)
	return BootstrapStepResult{
		Name:           strings.TrimSpace(stepName),
		Status:         RunStatusPending,
		CommandSummary: command.Summary(),
		StartedAt:      deps.now(),
	}
}

func (d BootstrapDeps) repositoryDeps() BootstrapRepositoryDeps {
	return BootstrapRepositoryDeps{
		Executor:           d.Executor,
		Now:                d.Now,
		RepoExists:         d.RepoExists,
		LocalBranchExists:  d.LocalBranchExists,
		RemoteBranchExists: d.RemoteBranchExists,
	}
}

func (d BootstrapDeps) toolingDeps() BootstrapToolingDeps {
	return BootstrapToolingDeps{
		Executor:     d.Executor,
		Now:          d.Now,
		HalCheck:     d.HalCheck,
		EngineChecks: d.EngineChecks,
	}
}

func (d BootstrapDeps) halDeps() BootstrapHalDeps {
	return BootstrapHalDeps{
		Executor: d.Executor,
		Now:      d.Now,
	}
}

func (d BootstrapDeps) finalCheckDeps(repoPath string) bootstrapFinalCheckDeps {
	return bootstrapFinalCheckDeps{
		Executor: d.Executor,
		Now:      d.Now,
		Checks:   normalizeBootstrapFinalChecks(repoPath, d.FinalChecks),
	}
}

func (d bootstrapFinalCheckDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}
