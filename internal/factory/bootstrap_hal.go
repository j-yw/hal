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
install_existing_hal() {
  if ! command -v hal >/dev/null 2>&1; then
    return 1
  fi
  existing_hal="$(command -v hal)"
  if [ "$existing_hal" != "$bin_dir/hal" ]; then
    cp "$existing_hal" "$tmp"
    install -m 0755 "$tmp" "$bin_dir/hal"
  fi
  "$bin_dir/hal" version
  return 0
}
if command -v go >/dev/null 2>&1; then
  module_path="$(go list -m 2>/dev/null || true)"
  if [ "$module_path" = "github.com/jywlabs/hal" ] || [ "$module_path" = "github.com/ReScienceLab/hal" ]; then
    go build -o "$tmp" .
    install -m 0755 "$tmp" "$bin_dir/hal"
    "$bin_dir/hal" version
    exit 0
  fi
fi
if install_existing_hal; then
  exit 0
fi
echo "hal bootstrap failed: workspace is not a Hal source checkout and no existing hal binary was found" >&2
exit 127`
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
