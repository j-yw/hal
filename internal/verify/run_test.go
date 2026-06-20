package verify

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunPassingShellChecks(t *testing.T) {
	projectRoot := t.TempDir()
	workDir := filepath.Join(projectRoot, "tools")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatalf("mkdir workDir: %v", err)
	}
	observedWorkDir := filepath.Join(projectRoot, "observed-workdir.txt")

	result, err := Run(context.Background(), &Config{
		Checks: []ShellCheck{
			{
				ID:             "unit",
				Name:           "Unit tests",
				Command:        helperCommand(t, "noop"),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       true,
			},
			{
				ID:             "workdir",
				Name:           "Workdir check",
				Command:        helperCommand(t, "write-pwd", observedWorkDir),
				WorkDir:        workDir,
				TimeoutSeconds: 10,
				Required:       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if result.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", result.SchemaVersion, SchemaVersion)
	}
	if result.Status != StatusPass {
		t.Fatalf("Status = %q, want %q", result.Status, StatusPass)
	}
	if result.Summary.Total != 2 {
		t.Errorf("Summary.Total = %d, want 2", result.Summary.Total)
	}
	if result.Summary.Passed != 2 {
		t.Errorf("Summary.Passed = %d, want 2", result.Summary.Passed)
	}
	if result.Summary.Failed != 0 || result.Summary.TimedOut != 0 || result.Summary.Missing != 0 || result.Summary.Skipped != 0 || result.Summary.Warnings != 0 {
		t.Errorf("Summary has unexpected non-pass counts: %#v", result.Summary)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("Warnings length = %d, want 0", len(result.Warnings))
	}

	for _, check := range result.Checks {
		if check.Adapter != AdapterShell {
			t.Errorf("%s Adapter = %q, want %q", check.ID, check.Adapter, AdapterShell)
		}
		if check.Status != CheckStatusPass {
			t.Errorf("%s Status = %q, want %q", check.ID, check.Status, CheckStatusPass)
		}
		if check.ExitCode != 0 {
			t.Errorf("%s ExitCode = %d, want 0", check.ID, check.ExitCode)
		}
		if check.StartedAt.IsZero() {
			t.Errorf("%s StartedAt is zero", check.ID)
		}
		if check.FinishedAt.IsZero() {
			t.Errorf("%s FinishedAt is zero", check.ID)
		}
		if check.FinishedAt.Before(check.StartedAt) {
			t.Errorf("%s FinishedAt %s is before StartedAt %s", check.ID, check.FinishedAt, check.StartedAt)
		}
		if check.DurationMs < 0 {
			t.Errorf("%s DurationMs = %d, want >= 0", check.ID, check.DurationMs)
		}
	}

	observed, err := os.ReadFile(observedWorkDir)
	if err != nil {
		t.Fatalf("read observed workdir: %v", err)
	}
	if got := string(observed); got != workDir {
		t.Fatalf("command ran in %q, want %q", got, workDir)
	}
}

func TestRunNilConfigReturnsPassingEmptyResult(t *testing.T) {
	result, err := Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("Run(nil) unexpected error: %v", err)
	}
	if result.Status != StatusPass {
		t.Fatalf("Status = %q, want %q", result.Status, StatusPass)
	}
	if result.Summary.Total != 0 {
		t.Fatalf("Summary.Total = %d, want 0", result.Summary.Total)
	}
}

func TestRunRequiredShellCheckFailure(t *testing.T) {
	projectRoot := t.TempDir()

	result, err := Run(context.Background(), &Config{
		Checks: []ShellCheck{
			{
				ID:             "test",
				Name:           "Unit tests",
				Command:        helperCommand(t, "exit-code", "23"),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if result.Status != StatusFail {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFail)
	}
	if result.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", result.Summary.Total)
	}
	if result.Summary.Failed != 1 {
		t.Errorf("Summary.Failed = %d, want 1", result.Summary.Failed)
	}
	if result.Summary.Passed != 0 || result.Summary.TimedOut != 0 || result.Summary.Missing != 0 || result.Summary.Skipped != 0 || result.Summary.Warnings != 0 {
		t.Errorf("Summary has unexpected non-fail counts: %#v", result.Summary)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("Warnings length = %d, want 0", len(result.Warnings))
	}
	if len(result.Checks) != 1 {
		t.Fatalf("Checks length = %d, want 1", len(result.Checks))
	}

	check := result.Checks[0]
	if check.Status != CheckStatusFail {
		t.Errorf("check Status = %q, want %q", check.Status, CheckStatusFail)
	}
	if !check.Required {
		t.Errorf("check Required = false, want true")
	}
	if check.ExitCode != 23 {
		t.Errorf("check ExitCode = %d, want 23", check.ExitCode)
	}
}

func TestRunRequiredShellCheckTimeout(t *testing.T) {
	projectRoot := t.TempDir()
	marker := filepath.Join(projectRoot, "timeout-marker.txt")

	result, err := Run(context.Background(), &Config{
		Checks: []ShellCheck{
			{
				ID:             "test",
				Name:           "Unit tests",
				Command:        helperCommand(t, "sleep-then-write", "2s", marker),
				WorkDir:        projectRoot,
				TimeoutSeconds: 1,
				Required:       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if result.Status != StatusFail {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFail)
	}
	if result.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", result.Summary.Total)
	}
	if result.Summary.TimedOut != 1 {
		t.Errorf("Summary.TimedOut = %d, want 1", result.Summary.TimedOut)
	}
	if result.Summary.Passed != 0 || result.Summary.Failed != 0 || result.Summary.Missing != 0 || result.Summary.Skipped != 0 || result.Summary.Warnings != 0 {
		t.Errorf("Summary has unexpected non-timeout counts: %#v", result.Summary)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("Warnings length = %d, want 0", len(result.Warnings))
	}
	if len(result.Checks) != 1 {
		t.Fatalf("Checks length = %d, want 1", len(result.Checks))
	}

	check := result.Checks[0]
	if check.Status != CheckStatusTimeout {
		t.Errorf("check Status = %q, want %q", check.Status, CheckStatusTimeout)
	}
	if !check.Required {
		t.Errorf("check Required = false, want true")
	}
	if !strings.Contains(check.Message, "timed out after 1 seconds") {
		t.Errorf("check Message = %q, want timeout message", check.Message)
	}

	if runtime.GOOS == "windows" {
		t.Skip("process group cleanup is Unix-only")
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("timed-out command wrote marker after timeout; stat err = %v", err)
	}
}

func TestRunOptionalShellCheckFailureWarns(t *testing.T) {
	projectRoot := t.TempDir()

	result, err := Run(context.Background(), &Config{
		Checks: []ShellCheck{
			{
				ID:             "lint",
				Name:           "Lint",
				Command:        helperCommand(t, "exit-code", "17"),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       false,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if result.Status != StatusWarn {
		t.Fatalf("Status = %q, want %q", result.Status, StatusWarn)
	}
	if result.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", result.Summary.Total)
	}
	if result.Summary.Failed != 1 {
		t.Errorf("Summary.Failed = %d, want 1", result.Summary.Failed)
	}
	if result.Summary.Warnings != 1 {
		t.Errorf("Summary.Warnings = %d, want 1", result.Summary.Warnings)
	}
	if result.Summary.Passed != 0 || result.Summary.TimedOut != 0 || result.Summary.Missing != 0 || result.Summary.Skipped != 0 {
		t.Errorf("Summary has unexpected optional-fail counts: %#v", result.Summary)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("Warnings length = %d, want 1", len(result.Warnings))
	}
	if len(result.Checks) != 1 {
		t.Fatalf("Checks length = %d, want 1", len(result.Checks))
	}

	check := result.Checks[0]
	if check.Status != CheckStatusFail {
		t.Errorf("check Status = %q, want %q", check.Status, CheckStatusFail)
	}
	if check.Required {
		t.Errorf("check Required = true, want false")
	}
	if check.ExitCode != 17 {
		t.Errorf("check ExitCode = %d, want 17", check.ExitCode)
	}
	warning := result.Warnings[0]
	if warning.CheckID != "lint" {
		t.Errorf("warning CheckID = %q, want lint", warning.CheckID)
	}
	if warning.Status != CheckStatusFail {
		t.Errorf("warning Status = %q, want %q", warning.Status, CheckStatusFail)
	}
	if !strings.Contains(warning.Message, "check failed") {
		t.Errorf("warning Message = %q, want failure details", warning.Message)
	}
}

func TestRunOptionalShellCheckMissingWarns(t *testing.T) {
	projectRoot := t.TempDir()
	missingWorkDir := filepath.Join(projectRoot, "missing")

	result, err := Run(context.Background(), &Config{
		Checks: []ShellCheck{
			{
				ID:             "advisory",
				Name:           "Advisory",
				Command:        "",
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       false,
			},
			{
				ID:             "tool",
				Name:           "Tool",
				Command:        helperCommand(t, "noop"),
				WorkDir:        missingWorkDir,
				TimeoutSeconds: 10,
				Required:       false,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if result.Status != StatusWarn {
		t.Fatalf("Status = %q, want %q", result.Status, StatusWarn)
	}
	if result.Summary.Total != 2 {
		t.Errorf("Summary.Total = %d, want 2", result.Summary.Total)
	}
	if result.Summary.Missing != 2 {
		t.Errorf("Summary.Missing = %d, want 2", result.Summary.Missing)
	}
	if result.Summary.Warnings != 2 {
		t.Errorf("Summary.Warnings = %d, want 2", result.Summary.Warnings)
	}
	if result.Summary.Passed != 0 || result.Summary.Failed != 0 || result.Summary.TimedOut != 0 || result.Summary.Skipped != 0 {
		t.Errorf("Summary has unexpected optional-missing counts: %#v", result.Summary)
	}
	if len(result.Warnings) != 2 {
		t.Fatalf("Warnings length = %d, want 2", len(result.Warnings))
	}
	if len(result.Checks) != 2 {
		t.Fatalf("Checks length = %d, want 2", len(result.Checks))
	}

	if result.Checks[0].Status != CheckStatusMissing {
		t.Errorf("command-missing Status = %q, want %q", result.Checks[0].Status, CheckStatusMissing)
	}
	if !strings.Contains(result.Checks[0].Message, "command is missing") {
		t.Errorf("command-missing Message = %q, want command missing details", result.Checks[0].Message)
	}
	if result.Checks[1].Status != CheckStatusMissing {
		t.Errorf("workdir-missing Status = %q, want %q", result.Checks[1].Status, CheckStatusMissing)
	}
	if !strings.Contains(result.Checks[1].Message, "working directory is missing") {
		t.Errorf("workdir-missing Message = %q, want workdir missing details", result.Checks[1].Message)
	}
	for _, warning := range result.Warnings {
		if warning.Status != CheckStatusMissing {
			t.Errorf("warning %s Status = %q, want %q", warning.CheckID, warning.Status, CheckStatusMissing)
		}
		if warning.Message == "" {
			t.Errorf("warning %s Message is empty", warning.CheckID)
		}
	}
}

func TestRunOptionalShellCheckTimeoutWarns(t *testing.T) {
	projectRoot := t.TempDir()
	marker := filepath.Join(projectRoot, "optional-timeout-marker.txt")

	result, err := Run(context.Background(), &Config{
		Checks: []ShellCheck{
			{
				ID:             "slow",
				Name:           "Slow advisory",
				Command:        helperCommand(t, "sleep-then-write", "2s", marker),
				WorkDir:        projectRoot,
				TimeoutSeconds: 1,
				Required:       false,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if result.Status != StatusWarn {
		t.Fatalf("Status = %q, want %q", result.Status, StatusWarn)
	}
	if result.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", result.Summary.Total)
	}
	if result.Summary.TimedOut != 1 {
		t.Errorf("Summary.TimedOut = %d, want 1", result.Summary.TimedOut)
	}
	if result.Summary.Warnings != 1 {
		t.Errorf("Summary.Warnings = %d, want 1", result.Summary.Warnings)
	}
	if result.Summary.Passed != 0 || result.Summary.Failed != 0 || result.Summary.Missing != 0 || result.Summary.Skipped != 0 {
		t.Errorf("Summary has unexpected optional-timeout counts: %#v", result.Summary)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("Warnings length = %d, want 1", len(result.Warnings))
	}
	if len(result.Checks) != 1 {
		t.Fatalf("Checks length = %d, want 1", len(result.Checks))
	}

	check := result.Checks[0]
	if check.Status != CheckStatusTimeout {
		t.Errorf("check Status = %q, want %q", check.Status, CheckStatusTimeout)
	}
	if check.Required {
		t.Errorf("check Required = true, want false")
	}
	if !strings.Contains(check.Message, "timed out after 1 seconds") {
		t.Errorf("check Message = %q, want timeout message", check.Message)
	}
	warning := result.Warnings[0]
	if warning.CheckID != "slow" {
		t.Errorf("warning CheckID = %q, want slow", warning.CheckID)
	}
	if warning.Status != CheckStatusTimeout {
		t.Errorf("warning Status = %q, want %q", warning.Status, CheckStatusTimeout)
	}
	if !strings.Contains(warning.Message, "timed out after 1 seconds") {
		t.Errorf("warning Message = %q, want timeout message", warning.Message)
	}
}

func TestVerifyHelperProcess(t *testing.T) {
	args := os.Args
	for i, arg := range args {
		if arg != "--" {
			continue
		}
		if len(args) <= i+1 {
			return
		}

		switch args[i+1] {
		case "noop":
			os.Exit(0)
		case "exit-code":
			if len(args) <= i+2 {
				os.Exit(2)
			}
			code, err := strconv.Atoi(args[i+2])
			if err != nil {
				os.Exit(2)
			}
			os.Exit(code)
		case "sleep-then-write":
			if len(args) <= i+3 {
				os.Exit(2)
			}
			delay, err := time.ParseDuration(args[i+2])
			if err != nil {
				os.Exit(2)
			}
			time.Sleep(delay)
			if err := os.WriteFile(args[i+3], []byte("finished"), 0644); err != nil {
				os.Exit(2)
			}
			os.Exit(0)
		case "write-pwd":
			if len(args) <= i+2 {
				os.Exit(2)
			}
			wd, err := os.Getwd()
			if err != nil {
				os.Exit(2)
			}
			if err := os.WriteFile(args[i+2], []byte(wd), 0644); err != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
	}
}

func helperCommand(t *testing.T, args ...string) string {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable(): %v", err)
	}

	parts := []string{
		shellQuote(exe),
		"-test.run=TestVerifyHelperProcess",
		"--",
	}
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return joinCommand(parts)
}

func shellQuote(value string) string {
	return strconv.Quote(value)
}

func joinCommand(parts []string) string {
	return strings.Join(parts, " ")
}
