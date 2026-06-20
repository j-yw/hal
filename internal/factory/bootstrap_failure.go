package factory

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

// Bootstrap failure category values.
const (
	BootstrapFailureCategoryRepo        = "repo"
	BootstrapFailureCategoryAuth        = "auth"
	BootstrapFailureCategoryDependency  = "dependency"
	BootstrapFailureCategoryEngineSetup = "engine_setup"
	BootstrapFailureCategoryUnknown     = "unknown"
)

// ClassifyBootstrapFailure maps a failed bootstrap command to the small
// bootstrap taxonomy used by remote workspace setup result and timeline events.
func ClassifyBootstrapFailure(step string, command string, output string, err error) BootstrapFailure {
	step = strings.TrimSpace(step)
	category := classifyBootstrapFailureCategory(step, command, output, err)
	return BootstrapFailure{
		Step:     step,
		Category: category,
		Message:  bootstrapFailureMessage(category, step, command),
	}
}

func classifyBootstrapFailureCategory(step string, command string, output string, err error) string {
	signal := bootstrapFailureSignal(step, command, output, err)
	switch {
	case hasBootstrapMissingDependencySignal(err, signal):
		return BootstrapFailureCategoryDependency
	case hasBootstrapAuthSignal(signal):
		return BootstrapFailureCategoryAuth
	case isBootstrapEngineSetupCommand(step, command):
		return BootstrapFailureCategoryEngineSetup
	case isBootstrapRepoCommand(step, command):
		return BootstrapFailureCategoryRepo
	default:
		return BootstrapFailureCategoryUnknown
	}
}

func bootstrapFailureSignal(step string, command string, output string, err error) string {
	parts := []string{step, command, output}
	if err != nil {
		parts = append(parts, err.Error())
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func hasBootstrapMissingDependencySignal(err error, signal string) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}

	var execErr *exec.Error
	if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
		return true
	}

	return bootstrapSignalContains(signal,
		"executable file not found",
		"command not found",
		"not found in $path",
		"no such file or directory",
	)
}

func hasBootstrapAuthSignal(signal string) bool {
	return bootstrapSignalContains(signal,
		"authentication failed",
		"auth failed",
		"bad credentials",
		"could not read username",
		"invalid username",
		"invalid password",
		"permission denied",
		"publickey",
		"unauthorized",
		"forbidden",
		"access denied",
		"could not read from remote repository",
	)
}

func isBootstrapEngineSetupCommand(step string, command string) bool {
	step = strings.ToLower(strings.TrimSpace(step))
	if bootstrapSignalContains(step, "hal", "engine", "skill", "template") {
		return true
	}

	switch bootstrapExecutable(command) {
	case "hal", "codex", "claude", "pi":
		return true
	default:
		return false
	}
}

func isBootstrapRepoCommand(step string, command string) bool {
	step = strings.ToLower(strings.TrimSpace(step))
	if bootstrapSignalContains(step, "repo", "repository", "clone", "fetch", "checkout", "branch") {
		return true
	}
	return bootstrapExecutable(command) == "git"
}

func bootstrapFailureMessage(category string, step string, command string) string {
	context := bootstrapFailureContext(step, command)
	switch category {
	case BootstrapFailureCategoryRepo:
		return "repository bootstrap failed " + context
	case BootstrapFailureCategoryAuth:
		return "authentication failed " + context
	case BootstrapFailureCategoryDependency:
		if executable := bootstrapExecutable(command); executable != "" {
			return "required bootstrap command not found: " + executable
		}
		return "required bootstrap command not found"
	case BootstrapFailureCategoryEngineSetup:
		return "Hal or engine setup failed " + context
	default:
		return "bootstrap command failed " + context
	}
}

func bootstrapFailureContext(step string, command string) string {
	if label := bootstrapCommandLabel(command); label != "" {
		return "while running " + label
	}
	if step = strings.TrimSpace(step); step != "" {
		return "during " + step
	}
	return "during bootstrap"
}

func bootstrapCommandLabel(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}

	executable := bootstrapExecutable(command)
	if executable == "" {
		return ""
	}

	if len(fields) > 1 {
		subcommand := strings.TrimSpace(fields[1])
		if subcommand != "" && !strings.HasPrefix(subcommand, "-") {
			switch executable {
			case "git", "hal":
				return executable + " " + subcommand
			}
		}
	}

	return executable
}

func bootstrapExecutable(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	executable := filepath.Base(fields[0])
	return strings.ToLower(strings.TrimSpace(executable))
}

func bootstrapSignalContains(signal string, fragments ...string) bool {
	for _, fragment := range fragments {
		if strings.Contains(signal, fragment) {
			return true
		}
	}
	return false
}
