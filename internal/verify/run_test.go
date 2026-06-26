package verify

import (
	"context"
	"errors"
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

func TestRunCapturesShellCheckArtifacts(t *testing.T) {
	projectRoot := t.TempDir()

	result, err := Run(context.Background(), &Config{
		ProjectRoot: projectRoot,
		Checks: []ShellCheck{
			{
				ID:             "test",
				Name:           "Unit tests",
				Command:        helperCommand(t, "write-output", "unit stdout", "unit stderr"),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(result.Checks) != 1 {
		t.Fatalf("Checks length = %d, want 1", len(result.Checks))
	}
	if len(result.Artifacts) != 2 {
		t.Fatalf("Artifacts length = %d, want 2: %#v", len(result.Artifacts), result.Artifacts)
	}

	check := result.Checks[0]
	if check.StdoutArtifact != ".hal/reports/verify/test-stdout.txt" {
		t.Errorf("StdoutArtifact = %q, want .hal/reports/verify/test-stdout.txt", check.StdoutArtifact)
	}
	if check.StderrArtifact != ".hal/reports/verify/test-stderr.txt" {
		t.Errorf("StderrArtifact = %q, want .hal/reports/verify/test-stderr.txt", check.StderrArtifact)
	}

	requireArtifact(t, result.Artifacts, "test", ArtifactKindStdout, ".hal/reports/verify/test-stdout.txt")
	requireArtifact(t, result.Artifacts, "test", ArtifactKindStderr, ".hal/reports/verify/test-stderr.txt")
	requireFileContent(t, filepath.Join(projectRoot, ".hal", "reports", "verify", "test-stdout.txt"), "unit stdout")
	requireFileContent(t, filepath.Join(projectRoot, ".hal", "reports", "verify", "test-stderr.txt"), "unit stderr")
}

func TestRunWritesArtifactsWithRestrictedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not portable on Windows")
	}
	projectRoot := t.TempDir()

	_, err := Run(context.Background(), &Config{
		ProjectRoot: projectRoot,
		Checks: []ShellCheck{
			{
				ID:             "test",
				Name:           "Unit tests",
				Command:        helperCommand(t, "write-output", "sensitive stdout", ""),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	requireFilePerm(t, filepath.Join(projectRoot, ".hal", "reports", "verify"), 0700)
	requireFilePerm(t, filepath.Join(projectRoot, ".hal", "reports", "verify", "test-stdout.txt"), 0600)
}

func TestRunReplacesExistingRestrictedArtifact(t *testing.T) {
	projectRoot := t.TempDir()
	cfg := func(output string) *Config {
		return &Config{
			ProjectRoot: projectRoot,
			Checks: []ShellCheck{
				{
					ID:             "test",
					Name:           "Unit tests",
					Command:        helperCommand(t, "write-output", output, ""),
					WorkDir:        projectRoot,
					TimeoutSeconds: 10,
					Required:       true,
				},
			},
		}
	}

	if _, err := Run(context.Background(), cfg("first stdout")); err != nil {
		t.Fatalf("first Run() unexpected error: %v", err)
	}
	if _, err := Run(context.Background(), cfg("second stdout")); err != nil {
		t.Fatalf("second Run() unexpected error: %v", err)
	}

	requireFileContent(t, filepath.Join(projectRoot, ".hal", "reports", "verify", "test-stdout.txt"), "second stdout")
}

func TestRunDisambiguatesSanitizedArtifactIDs(t *testing.T) {
	projectRoot := t.TempDir()

	result, err := Run(context.Background(), &Config{
		ProjectRoot: projectRoot,
		Checks: []ShellCheck{
			{
				ID:             "a/b",
				Name:           "Slash check",
				Command:        helperCommand(t, "write-output", "slash stdout", ""),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       true,
			},
			{
				ID:             "a_b",
				Name:           "Underscore check",
				Command:        helperCommand(t, "write-output", "underscore stdout", ""),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(result.Checks) != 2 {
		t.Fatalf("Checks length = %d, want 2", len(result.Checks))
	}

	if result.Checks[0].StdoutArtifact != ".hal/reports/verify/a_b-stdout.txt" {
		t.Errorf("first StdoutArtifact = %q, want .hal/reports/verify/a_b-stdout.txt", result.Checks[0].StdoutArtifact)
	}
	if result.Checks[1].StdoutArtifact != ".hal/reports/verify/a_b-2-stdout.txt" {
		t.Errorf("second StdoutArtifact = %q, want .hal/reports/verify/a_b-2-stdout.txt", result.Checks[1].StdoutArtifact)
	}

	requireArtifact(t, result.Artifacts, "a/b", ArtifactKindStdout, ".hal/reports/verify/a_b-stdout.txt")
	requireArtifact(t, result.Artifacts, "a_b", ArtifactKindStdout, ".hal/reports/verify/a_b-2-stdout.txt")
	requireFileContent(t, filepath.Join(projectRoot, ".hal", "reports", "verify", "a_b-stdout.txt"), "slash stdout")
	requireFileContent(t, filepath.Join(projectRoot, ".hal", "reports", "verify", "a_b-2-stdout.txt"), "underscore stdout")
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

func TestRunCanceledContextReturnsError(t *testing.T) {
	projectRoot := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Run(ctx, &Config{
		Checks: []ShellCheck{
			{
				ID:             "test",
				Name:           "Unit tests",
				Command:        helperCommand(t, "noop"),
				WorkDir:        projectRoot,
				TimeoutSeconds: 10,
				Required:       true,
			},
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if result != nil {
		t.Fatalf("Run() result = %#v, want nil", result)
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

func TestRunOptionalShellCheckUnavailableCommandWarns(t *testing.T) {
	projectRoot := t.TempDir()

	result, err := Run(context.Background(), &Config{
		Checks: []ShellCheck{
			{
				ID:             "lint",
				Name:           "Lint",
				Command:        "hal-verify-missing-command-for-test run",
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
	if result.Summary.Missing != 1 {
		t.Errorf("Summary.Missing = %d, want 1", result.Summary.Missing)
	}
	if result.Summary.Warnings != 1 {
		t.Errorf("Summary.Warnings = %d, want 1", result.Summary.Warnings)
	}
	check := result.Checks[0]
	if check.Status != CheckStatusMissing {
		t.Errorf("check Status = %q, want %q", check.Status, CheckStatusMissing)
	}
	if check.ExitCode == 0 {
		t.Errorf("check ExitCode = 0, want shell missing-command exit code")
	}
	if !strings.Contains(check.Message, "command is unavailable") {
		t.Errorf("check Message = %q, want unavailable command details", check.Message)
	}
	warning := result.Warnings[0]
	if warning.Status != CheckStatusMissing {
		t.Errorf("warning Status = %q, want %q", warning.Status, CheckStatusMissing)
	}
	if !strings.Contains(warning.Message, "command is unavailable") {
		t.Errorf("warning Message = %q, want unavailable command details", warning.Message)
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
		case "write-output":
			if len(args) <= i+3 {
				os.Exit(2)
			}
			if _, err := os.Stdout.Write([]byte(args[i+2])); err != nil {
				os.Exit(2)
			}
			if _, err := os.Stderr.Write([]byte(args[i+3])); err != nil {
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

func requireArtifact(t *testing.T, artifacts []ArtifactReference, checkID, kind, wantPath string) {
	t.Helper()

	for _, artifact := range artifacts {
		if artifact.CheckID == checkID && artifact.Kind == kind {
			if artifact.Path != wantPath {
				t.Fatalf("artifact %s path = %q, want %q", kind, artifact.Path, wantPath)
			}
			return
		}
	}
	t.Fatalf("missing %s artifact for check %s in %#v", kind, checkID, artifacts)
}

func requireFileContent(t *testing.T, path, want string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if got := string(data); got != want {
		t.Fatalf("%s content = %q, want %q", path, got, want)
	}
}

func requireFilePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s permissions = %#o, want %#o", path, got, want)
	}
}
