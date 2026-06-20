package factory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var errBootstrapExecutorRequired = errors.New("bootstrap command executor is required")

type bootstrapCommandExitError struct {
	exitCode int
}

func (e bootstrapCommandExitError) Error() string {
	return fmt.Sprintf("bootstrap command exited with code %d", e.exitCode)
}

// BootstrapCommand describes one process invocation at the factory bootstrap
// boundary. Callers pass environment values here; later sanitization layers are
// responsible for redacting sensitive values before timeline persistence.
type BootstrapCommand struct {
	Name string            `json:"name"`
	Args []string          `json:"args,omitempty"`
	Dir  string            `json:"dir,omitempty"`
	Env  map[string]string `json:"env,omitempty"`
}

// BootstrapCommandResult captures sanitized command output and result metadata
// returned by an injected bootstrap executor.
type BootstrapCommandResult struct {
	ExitCode      int               `json:"exitCode"`
	StdoutSummary string            `json:"stdoutSummary,omitempty"`
	StderrSummary string            `json:"stderrSummary,omitempty"`
	OutputSummary string            `json:"outputSummary,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// BootstrapCommandExecutor runs bootstrap commands. Production adapters and
// tests implement this boundary instead of letting bootstrap logic spawn
// processes directly.
type BootstrapCommandExecutor interface {
	Run(ctx context.Context, command BootstrapCommand) (BootstrapCommandResult, error)
}

// BootstrapStepDeps holds injected dependencies for command-backed bootstrap
// steps.
type BootstrapStepDeps struct {
	Executor BootstrapCommandExecutor
	Now      func() time.Time
}

// RunBootstrapStep executes one bootstrap command through the injected
// executor and returns a step record plus a classified failure when it fails.
func RunBootstrapStep(ctx context.Context, deps BootstrapStepDeps, stepName string, command BootstrapCommand) (BootstrapStepResult, BootstrapCommandResult, *BootstrapFailure, error) {
	now := deps.now
	startedAt := now()

	if deps.Executor == nil {
		finishedAt := now()
		step := BootstrapStepResult{
			Name:           strings.TrimSpace(stepName),
			Status:         RunStatusFailed,
			CommandSummary: command.Summary(),
			StartedAt:      startedAt,
			FinishedAt:     &finishedAt,
		}
		failure := ClassifyBootstrapFailure(step.Name, "", "", errBootstrapExecutorRequired)
		return step, BootstrapCommandResult{}, &failure, errBootstrapExecutorRequired
	}

	result, err := deps.Executor.Run(ctx, command)
	finishedAt := now()
	if err == nil && result.ExitCode != 0 {
		err = bootstrapCommandExitError{exitCode: result.ExitCode}
	}

	status := RunStatusSucceeded
	if err != nil {
		status = RunStatusFailed
	}

	step := BootstrapStepResult{
		Name:           strings.TrimSpace(stepName),
		Status:         status,
		CommandSummary: command.Summary(),
		StartedAt:      startedAt,
		FinishedAt:     &finishedAt,
		ExitCode:       result.ExitCode,
	}

	if err != nil {
		failure := ClassifyBootstrapFailure(step.Name, command.Summary(), result.classificationOutput(), err)
		return step, result, &failure, err
	}

	return step, result, nil, nil
}

// Summary returns a deterministic human-readable command label for bootstrap
// step records.
func (c BootstrapCommand) Summary() string {
	parts := make([]string, 0, 1+len(c.Args))
	if name := strings.TrimSpace(c.Name); name != "" {
		parts = append(parts, name)
	}
	parts = append(parts, c.Args...)
	return strings.Join(parts, " ")
}

func (d BootstrapStepDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}

func (r BootstrapCommandResult) classificationOutput() string {
	parts := make([]string, 0, 3)
	for _, part := range []string{r.OutputSummary, r.StdoutSummary, r.StderrSummary} {
		if part = strings.TrimSpace(part); part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "\n")
}
