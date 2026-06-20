package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

type runDeps struct {
	now            func() time.Time
	commandContext func(context.Context, string, ...string) *exec.Cmd
}

// Run executes configured verification checks and returns a verify-v1 result.
func Run(ctx context.Context, cfg *Config) (*Result, error) {
	if cfg == nil {
		defaultConfig := DefaultConfig()
		cfg = &defaultConfig
	}

	return runWithDeps(ctx, *cfg, runDeps{
		now:            time.Now,
		commandContext: exec.CommandContext,
	})
}

func runWithDeps(ctx context.Context, cfg Config, deps runDeps) (*Result, error) {
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.commandContext == nil {
		deps.commandContext = exec.CommandContext
	}

	result := &Result{
		SchemaVersion: SchemaVersion,
		Status:        StatusPass,
		Checks:        make([]CheckResult, 0, len(cfg.Checks)),
		Warnings:      []Warning{},
		Artifacts:     []ArtifactReference{},
	}

	for _, check := range cfg.Checks {
		checkResult := runShellCheck(ctx, check, deps)
		result.Checks = append(result.Checks, checkResult)
		applyCheckSummary(result, checkResult)
		if warning, ok := warningForCheck(checkResult); ok {
			result.Warnings = append(result.Warnings, warning)
		}
	}

	result.Summary.Total = len(result.Checks)
	result.Summary.Warnings = len(result.Warnings)
	result.Status = statusForResult(result)
	result.GeneratedAt = deps.now()
	return result, nil
}

func runShellCheck(ctx context.Context, check ShellCheck, deps runDeps) CheckResult {
	timeout := time.Duration(check.TimeoutSeconds) * time.Second
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startedAt := deps.now()
	shell, args := shellCommand(check.Command)
	cmd := deps.commandContext(checkCtx, shell, args...)
	cmd.Dir = check.WorkDir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	finishedAt := deps.now()

	result := CheckResult{
		ID:             check.ID,
		Name:           check.Name,
		Adapter:        AdapterShell,
		Status:         CheckStatusPass,
		Required:       check.Required,
		Command:        check.Command,
		WorkDir:        check.WorkDir,
		TimeoutSeconds: check.TimeoutSeconds,
		StartedAt:      startedAt,
		FinishedAt:     finishedAt,
		DurationMs:     finishedAt.Sub(startedAt).Milliseconds(),
		ExitCode:       0,
		StdoutArtifact: "",
		StderrArtifact: "",
		Message:        "check passed",
	}

	if err != nil {
		result.Status = CheckStatusFail
		result.ExitCode = exitCode(err)
		result.Message = fmt.Sprintf("check failed: %v", err)
		if errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
			result.Status = CheckStatusTimeout
			result.Message = fmt.Sprintf("check timed out after %d seconds", check.TimeoutSeconds)
		}
	}

	return result
}

func shellCommand(command string) (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C", command}
	}
	return "sh", []string{"-c", command}
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func applyCheckSummary(result *Result, check CheckResult) {
	switch check.Status {
	case CheckStatusPass:
		result.Summary.Passed++
	case CheckStatusFail:
		result.Summary.Failed++
	case CheckStatusTimeout:
		result.Summary.TimedOut++
	case CheckStatusMissing:
		result.Summary.Missing++
	case CheckStatusSkipped:
		result.Summary.Skipped++
	}
}

func warningForCheck(check CheckResult) (Warning, bool) {
	if check.Required || check.Status == CheckStatusPass {
		return Warning{}, false
	}

	return Warning{
		CheckID: check.ID,
		Status:  check.Status,
		Message: check.Message,
	}, true
}

func statusForResult(result *Result) string {
	for _, check := range result.Checks {
		if check.Required && (check.Status == CheckStatusFail || check.Status == CheckStatusTimeout || check.Status == CheckStatusMissing) {
			return StatusFail
		}
	}
	if len(result.Warnings) > 0 {
		return StatusWarn
	}
	return StatusPass
}
