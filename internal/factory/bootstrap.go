package factory

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	BootstrapStepValidateRequest     = "validate_bootstrap_request"
	BootstrapStepFinalCheckHalDoctor = "final_check_hal_doctor"

	bootstrapFinalCheckStepPrefix = "final_check_"
)

var errBootstrapRequiredEnvMissing = errors.New("bootstrap required environment value is missing")

type bootstrapRequiredEnvError struct{}

func (bootstrapRequiredEnvError) Error() string {
	return errBootstrapRequiredEnvMissing.Error()
}

func (bootstrapRequiredEnvError) Unwrap() error {
	return errBootstrapRequiredEnvMissing
}

// BootstrapDeps holds all dependencies needed by the high-level workspace
// bootstrap entrypoint. Nil FinalChecks runs the default Hal doctor check after
// repository, tooling, and Hal setup; an empty slice disables final checks.
type BootstrapDeps struct {
	Executor           BootstrapCommandExecutor
	Now                func() time.Time
	RepoExists         func(path string) (bool, error)
	RepoRemoteURL      func(path string) (string, error)
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
	if err := validateBootstrapRequiredEnv(request); err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
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
	if err := validateBootstrapRequiredEnv(request); err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
	}

	for _, check := range checks {
		stepName := bootstrapFinalCheckStepName(check)
		if err := validateBootstrapToolingCheck(check); err != nil {
			recordBootstrapFinalCheckValidationFailure(&result, request, deps, stepName, check, err)
			return result, err
		}

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

func validateBootstrapRequiredEnv(request BootstrapRequest) error {
	if len(request.RequiredEnvKeys) == 0 {
		return nil
	}

	env := make(map[string]string, len(request.Env))
	for key, value := range request.Env {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		env[key] = value
	}
	for _, key := range request.RequiredEnvKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value, ok := env[key]
		if !ok || strings.TrimSpace(value) == "" {
			return bootstrapRequiredEnvError{}
		}
	}
	return nil
}

func recordBootstrapRequestValidationFailure(result *BootstrapResult, request BootstrapRequest, nowFn func() time.Time, err error) {
	now := bootstrapNow(nowFn)
	startedAt := now()
	finishedAt := now()
	step := BootstrapStepResult{
		Name:       BootstrapStepValidateRequest,
		Status:     RunStatusFailed,
		StartedAt:  startedAt,
		FinishedAt: &finishedAt,
	}
	failure := ClassifyBootstrapFailure(step.Name, "", "", err)
	result.Failure = &failure
	recordBootstrapStepResult(result, request, step, BootstrapCommandResult{}, &failure)
}

func recordBootstrapFinalCheckValidationFailure(result *BootstrapResult, request BootstrapRequest, deps bootstrapFinalCheckDeps, stepName string, check BootstrapToolingCheck, err error) {
	now := bootstrapNow(deps.Now)
	startedAt := now()
	finishedAt := now()
	command := injectBootstrapRequestEnv(request, check.Command)
	command = NewBootstrapSanitizer(request).SanitizeCommand(command)
	commandSummary := command.Summary()
	stepName = strings.TrimSpace(stepName)
	step := BootstrapStepResult{
		Name:           stepName,
		Status:         RunStatusFailed,
		CommandSummary: commandSummary,
		StartedAt:      startedAt,
		FinishedAt:     &finishedAt,
	}
	failure := BootstrapFailure{
		Step:     stepName,
		Category: BootstrapFailureCategoryValidation,
		Message:  bootstrapFailureMessage(BootstrapFailureCategoryValidation, stepName, commandSummary),
	}
	result.Failure = &failure
	recordBootstrapStepResult(result, request, step, BootstrapCommandResult{}, &failure)
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
		RepoRemoteURL:      d.RepoRemoteURL,
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

func (d BootstrapDeps) now() time.Time {
	return bootstrapNow(d.Now)()
}

func (d bootstrapFinalCheckDeps) now() time.Time {
	return bootstrapNow(d.Now)()
}

func bootstrapNow(nowFn func() time.Time) func() time.Time {
	if nowFn != nil {
		return nowFn
	}
	return func() time.Time {
		return time.Now().UTC()
	}
}
