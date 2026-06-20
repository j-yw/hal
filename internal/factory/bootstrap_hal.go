package factory

import (
	"context"
	"strings"
	"time"
)

const (
	BootstrapStepSetupHalTemplates = "setup_hal_templates"
	BootstrapStepRefreshHalSkills  = "refresh_hal_skills"
)

// BootstrapHalDeps holds injectable dependencies for refreshing Hal-managed
// workspace assets without invoking real CLI commands in tests.
type BootstrapHalDeps struct {
	Executor BootstrapCommandExecutor
	Now      func() time.Time
}

type bootstrapHalCommand struct {
	stepName string
	command  BootstrapCommand
}

// BootstrapRefreshHal initializes or refreshes Hal templates, managed skills,
// standards, and engine links in the prepared workspace by delegating to the
// existing Hal CLI ownership paths.
func BootstrapRefreshHal(ctx context.Context, request BootstrapRequest, deps BootstrapHalDeps) (BootstrapResult, error) {
	repoPath, err := normalizeBootstrapRepoPath(request.WorkspaceDir)
	if err != nil {
		return BootstrapResult{}, err
	}

	commands := bootstrapHalCommands(request, repoPath)
	result := BootstrapResult{
		RepoPath: repoPath,
		Steps:    make([]BootstrapStepResult, 0, len(commands)),
	}

	for _, planned := range commands {
		if request.Options.DryRun {
			result.Steps = append(result.Steps, plannedBootstrapHalStep(deps, planned.stepName, planned.command))
			continue
		}

		step, _, failure, err := RunBootstrapStep(ctx, deps.stepDeps(), planned.stepName, planned.command)
		result.Steps = append(result.Steps, step)
		if err != nil {
			result.Failure = failure
			return result, err
		}
	}

	return result, nil
}

func bootstrapHalCommands(request BootstrapRequest, repoPath string) []bootstrapHalCommand {
	initArgs := []string{"init"}
	if request.Options.RefreshHal {
		initArgs = append(initArgs, "--refresh-templates")
	}

	return []bootstrapHalCommand{
		{
			stepName: BootstrapStepSetupHalTemplates,
			command: BootstrapCommand{
				Name: "hal",
				Args: initArgs,
				Dir:  repoPath,
			},
		},
		{
			stepName: BootstrapStepRefreshHalSkills,
			command: BootstrapCommand{
				Name: "hal",
				Args: []string{"links", "refresh"},
				Dir:  repoPath,
			},
		},
	}
}

func plannedBootstrapHalStep(deps BootstrapHalDeps, stepName string, command BootstrapCommand) BootstrapStepResult {
	return BootstrapStepResult{
		Name:           strings.TrimSpace(stepName),
		Status:         RunStatusPending,
		CommandSummary: command.Summary(),
		StartedAt:      deps.now(),
	}
}

func (d BootstrapHalDeps) stepDeps() BootstrapStepDeps {
	return BootstrapStepDeps{
		Executor: d.Executor,
		Now:      d.Now,
	}
}

func (d BootstrapHalDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}
