package factory

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	BootstrapStepVerifyHal  = "verify_hal"
	BootstrapStepInstallHal = "install_hal"
)

var errBootstrapToolingCommandRequired = errors.New("bootstrap tooling check command is required")

// BootstrapToolingCheck describes one required CLI verification command and an
// optional installer command used when missing CLI installation is enabled.
type BootstrapToolingCheck struct {
	Name           string            `json:"name"`
	Command        BootstrapCommand  `json:"command"`
	InstallCommand *BootstrapCommand `json:"installCommand,omitempty"`
}

// BootstrapToolingDeps holds injectable dependencies for bootstrap tool
// verification without tying tests to real Hal or engine CLIs.
type BootstrapToolingDeps struct {
	Executor     BootstrapCommandExecutor
	Now          func() time.Time
	HalCheck     BootstrapToolingCheck
	EngineChecks []BootstrapToolingCheck
}

type bootstrapToolingPlan struct {
	check    BootstrapToolingCheck
	stepName string
	install  string
	recheck  string
}

// BootstrapVerifyTooling verifies Hal and configured engine CLIs before the
// factory run starts. Missing CLIs fail as dependency errors unless
// InstallMissingCLIs is enabled and the check has an installer command.
func BootstrapVerifyTooling(ctx context.Context, request BootstrapRequest, deps BootstrapToolingDeps) (BootstrapResult, error) {
	result := BootstrapResult{
		RepoPath: bootstrapToolingRepoPath(request.WorkspaceDir),
	}
	if err := validateBootstrapRequiredEnv(request); err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
	}

	plans, err := bootstrapToolingPlans(request, deps)
	if err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
	}

	result = BootstrapResult{
		RepoPath: bootstrapToolingRepoPath(request.WorkspaceDir),
		Steps:    make([]BootstrapStepResult, 0, len(plans)),
		Timeline: make([]BootstrapTimelineEvent, 0, len(plans)),
	}

	for _, plan := range plans {
		if request.Options.DryRun {
			recordBootstrapStepResult(&result, request, plannedBootstrapToolingStep(deps, request, plan.stepName, plan.check.Command), BootstrapCommandResult{}, nil)
			continue
		}

		if err := runBootstrapToolingPlan(ctx, request, deps, &result, plan); err != nil {
			return result, err
		}
	}

	return result, nil
}

func runBootstrapToolingPlan(ctx context.Context, request BootstrapRequest, deps BootstrapToolingDeps, result *BootstrapResult, plan bootstrapToolingPlan) error {
	step, commandResult, failure, err := RunBootstrapStep(ctx, deps.stepDeps(request), plan.stepName, plan.check.Command)
	recordBootstrapStepResult(result, request, step, commandResult, failure)
	if err == nil {
		return nil
	}

	if !request.Options.InstallMissingCLIs || failure == nil || failure.Category != BootstrapFailureCategoryDependency || plan.check.InstallCommand == nil || strings.TrimSpace(plan.check.InstallCommand.Name) == "" {
		result.Failure = failure
		return err
	}

	installStep, installResult, installFailure, installErr := RunBootstrapStep(ctx, deps.stepDeps(request), plan.install, *plan.check.InstallCommand)
	recordBootstrapStepResult(result, request, installStep, installResult, installFailure)
	if installErr != nil {
		result.Failure = installFailure
		return installErr
	}

	recheckStep, recheckResult, recheckFailure, recheckErr := RunBootstrapStep(ctx, deps.stepDeps(request), plan.recheck, plan.check.Command)
	recordBootstrapStepResult(result, request, recheckStep, recheckResult, recheckFailure)
	if recheckErr != nil {
		result.Failure = recheckFailure
		return recheckErr
	}

	return nil
}

func bootstrapToolingPlans(request BootstrapRequest, deps BootstrapToolingDeps) ([]bootstrapToolingPlan, error) {
	workspaceDir := bootstrapToolingRepoPath(request.WorkspaceDir)
	halCheck := deps.HalCheck
	if halCheck.Name == "" {
		halCheck.Name = "hal"
	}
	if halCheck.Command.Name == "" {
		halCheck.Command = BootstrapCommand{
			Name: "hal",
			Args: []string{"--version"},
			Dir:  workspaceDir,
		}
	}
	if err := validateBootstrapToolingCheck(halCheck); err != nil {
		return nil, err
	}

	plans := []bootstrapToolingPlan{
		{
			check:    halCheck,
			stepName: BootstrapStepVerifyHal,
			install:  BootstrapStepInstallHal,
			recheck:  BootstrapStepVerifyHal + "_after_install",
		},
	}

	for _, check := range deps.EngineChecks {
		if err := validateBootstrapToolingCheck(check); err != nil {
			return nil, err
		}
		name := bootstrapToolingStepToken(check)
		plans = append(plans, bootstrapToolingPlan{
			check:    check,
			stepName: "verify_engine_" + name,
			install:  "install_engine_" + name,
			recheck:  "verify_engine_" + name + "_after_install",
		})
	}

	return plans, nil
}

func validateBootstrapToolingCheck(check BootstrapToolingCheck) error {
	if strings.TrimSpace(check.Command.Name) == "" {
		label := strings.TrimSpace(check.Name)
		if label == "" {
			return errBootstrapToolingCommandRequired
		}
		return fmt.Errorf("%s: %w", label, errBootstrapToolingCommandRequired)
	}
	return nil
}

func plannedBootstrapToolingStep(deps BootstrapToolingDeps, request BootstrapRequest, stepName string, command BootstrapCommand) BootstrapStepResult {
	command = injectBootstrapRequestEnv(request, command)
	command = NewBootstrapSanitizer(request).SanitizeCommand(command)
	return BootstrapStepResult{
		Name:           strings.TrimSpace(stepName),
		Status:         RunStatusPending,
		CommandSummary: command.Summary(),
		StartedAt:      deps.now(),
	}
}

func bootstrapToolingStepToken(check BootstrapToolingCheck) string {
	name := strings.TrimSpace(check.Name)
	if name == "" {
		name = bootstrapExecutable(check.Command.Summary())
	}
	name = strings.ToLower(name)

	var b strings.Builder
	lastSeparator := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastSeparator = false
			continue
		}
		if !lastSeparator {
			b.WriteByte('_')
			lastSeparator = true
		}
	}

	token := strings.Trim(b.String(), "_")
	if token == "" {
		return "cli"
	}
	return token
}

func bootstrapToolingRepoPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func (d BootstrapToolingDeps) stepDeps(request BootstrapRequest) BootstrapStepDeps {
	return BootstrapStepDeps{
		Executor: d.Executor,
		Now:      d.Now,
		Request:  request,
	}
}

func (d BootstrapToolingDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}
