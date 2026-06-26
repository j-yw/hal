package factory

import (
	"context"
	"strings"
	"time"
)

const (
	BootstrapStepSetupHalTemplates = "setup_hal_templates"
	BootstrapStepRefreshHalSkills  = "refresh_hal_skills"

	bootstrapRemoteHomeScript = `set -eu
remote_home="${HOME:-}"
if [ -z "$remote_home" ] && command -v getent >/dev/null 2>&1; then
  remote_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
fi
if [ -z "$remote_home" ]; then remote_home="$(pwd)"; fi
export HOME="$remote_home"`

	bootstrapInstallHalScript = bootstrapRemoteHomeScript + `
tmp="$(mktemp /tmp/hal-bootstrap.XXXXXX)"
trap 'rm -f "$tmp"' EXIT
bin_dir="$HOME/.local/bin"
mkdir -p "$bin_dir"
go build -o "$tmp" .
install -m 0755 "$tmp" "$bin_dir/hal"
"$bin_dir/hal" version`
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

// BootstrapRefreshHal installs the checked-out Hal binary, then initializes or
// refreshes Hal templates, managed skills, standards, and engine links in the
// prepared workspace by delegating to the existing Hal CLI ownership paths.
func BootstrapRefreshHal(ctx context.Context, request BootstrapRequest, deps BootstrapHalDeps) (BootstrapResult, error) {
	repoPath, err := normalizeBootstrapRepoPath(request.WorkspaceDir)
	if err != nil {
		return BootstrapResult{}, err
	}

	commands := bootstrapHalCommands(request, repoPath)
	result := BootstrapResult{
		RepoPath: repoPath,
		Steps:    make([]BootstrapStepResult, 0, len(commands)),
		Timeline: make([]BootstrapTimelineEvent, 0, len(commands)),
	}
	if err := validateBootstrapRequiredEnv(request); err != nil {
		recordBootstrapRequestValidationFailure(&result, request, deps.now, err)
		return result, err
	}

	for _, planned := range commands {
		if request.Options.DryRun {
			recordBootstrapStepResult(&result, request, plannedBootstrapHalStep(deps, request, planned.stepName, planned.command), BootstrapCommandResult{}, nil)
			continue
		}

		step, commandResult, failure, err := RunBootstrapStep(ctx, deps.stepDeps(request), planned.stepName, planned.command)
		recordBootstrapStepResult(&result, request, step, commandResult, failure)
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
			stepName: BootstrapStepInstallHal,
			command: BootstrapCommand{
				Name: "sh",
				Args: []string{"-lc", bootstrapInstallHalScript},
				Dir:  repoPath,
			},
		},
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

func plannedBootstrapHalStep(deps BootstrapHalDeps, request BootstrapRequest, stepName string, command BootstrapCommand) BootstrapStepResult {
	command = injectBootstrapRequestEnv(request, command)
	command = NewBootstrapSanitizer(request).SanitizeCommand(command)
	return BootstrapStepResult{
		Name:           strings.TrimSpace(stepName),
		Status:         RunStatusPending,
		CommandSummary: command.Summary(),
		StartedAt:      deps.now(),
	}
}

func (d BootstrapHalDeps) stepDeps(request BootstrapRequest) BootstrapStepDeps {
	return BootstrapStepDeps{
		Executor: d.Executor,
		Now:      d.Now,
		Request:  request,
	}
}

func (d BootstrapHalDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}
