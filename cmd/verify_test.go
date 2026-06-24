package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/verify"
	"github.com/spf13/cobra"
)

func TestRunVerifyJSONLoadsConfigRunsChecksAndEmitsVerifyV1(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	dir := t.TempDir()
	cfg := &verify.Config{
		ProjectRoot: dir,
		Checks: []verify.ShellCheck{
			{
				ID:             "test",
				Name:           "Unit tests",
				Command:        "go test ./...",
				WorkDir:        dir,
				TimeoutSeconds: 60,
				Required:       true,
			},
		},
	}

	var loadedDir string
	runCalled := false
	deps := verifyDeps{
		loadConfig: func(gotDir string) (*verify.Config, error) {
			loadedDir = gotDir
			return cfg, nil
		},
		run: func(ctx context.Context, gotCfg *verify.Config) (*verify.Result, error) {
			runCalled = true
			if gotCfg != cfg {
				t.Fatalf("run cfg pointer = %p, want %p", gotCfg, cfg)
			}
			return verifyResultFixture(verify.StatusPass, verify.CheckStatusPass, true), nil
		},
	}

	err := runVerifyWithDeps(context.Background(), dir, true, &out, &errOut, deps, &cobra.Command{Use: "verify"})
	if err != nil {
		t.Fatalf("runVerifyWithDeps() error = %v", err)
	}
	if loadedDir != dir {
		t.Fatalf("loadConfig dir = %q, want %q", loadedDir, dir)
	}
	if !runCalled {
		t.Fatal("verify runner was not called")
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", errOut.String())
	}

	var result verify.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not valid verify JSON: %v\n%s", err, out.String())
	}
	if result.SchemaVersion != verify.SchemaVersion {
		t.Fatalf("schemaVersion = %q, want %q", result.SchemaVersion, verify.SchemaVersion)
	}
	if result.Status != verify.StatusPass {
		t.Fatalf("status = %q, want pass", result.Status)
	}
}

func TestRunVerifyJSONWarnExitsZero(t *testing.T) {
	var out bytes.Buffer
	deps := verifyDeps{
		loadConfig: func(string) (*verify.Config, error) {
			return &verify.Config{}, nil
		},
		run: func(context.Context, *verify.Config) (*verify.Result, error) {
			return verifyResultFixture(verify.StatusWarn, verify.CheckStatusFail, false), nil
		},
	}

	err := runVerifyWithDeps(context.Background(), t.TempDir(), true, &out, nil, deps, &cobra.Command{Use: "verify"})
	if err != nil {
		t.Fatalf("runVerifyWithDeps() error = %v, want nil for warn status", err)
	}

	var result verify.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if result.Status != verify.StatusWarn {
		t.Fatalf("status = %q, want warn", result.Status)
	}
}

func TestRunVerifyJSONFailExitsNonZeroAfterWritingJSON(t *testing.T) {
	var out bytes.Buffer
	deps := verifyDeps{
		loadConfig: func(string) (*verify.Config, error) {
			return &verify.Config{}, nil
		},
		run: func(context.Context, *verify.Config) (*verify.Result, error) {
			return verifyResultFixture(verify.StatusFail, verify.CheckStatusFail, true), nil
		},
	}

	err := runVerifyWithDeps(context.Background(), t.TempDir(), true, &out, nil, deps, &cobra.Command{Use: "verify"})
	if err == nil {
		t.Fatal("runVerifyWithDeps() error = nil, want non-zero exit")
	}
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error = %T, want *ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeExpectedNonZero {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeExpectedNonZero)
	}
	if exitErr.Err != nil {
		t.Fatalf("exit error payload = %v, want nil so JSON stdout remains the only command output", exitErr.Err)
	}

	var result verify.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not valid JSON after failing gate: %v\n%s", err, out.String())
	}
	if result.Status != verify.StatusFail {
		t.Fatalf("status = %q, want fail", result.Status)
	}
}

func TestRunVerifyJSONConfigErrorDoesNotWriteStdout(t *testing.T) {
	var out bytes.Buffer
	deps := verifyDeps{
		loadConfig: func(string) (*verify.Config, error) {
			return nil, errors.New("verify.checks[0].id must not be empty")
		},
	}

	err := runVerifyWithDeps(context.Background(), t.TempDir(), true, &out, nil, deps, &cobra.Command{Use: "verify"})
	if err == nil {
		t.Fatal("runVerifyWithDeps() error = nil, want validation error")
	}
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error = %T, want *ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on config error", out.String())
	}
}

func TestVerifyCommandExposesJSONFlag(t *testing.T) {
	flag := verifyCmd.Flags().Lookup("json")
	if flag == nil {
		t.Fatal("verify command missing --json flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--json default = %q, want false", flag.DefValue)
	}
}

func TestVerifyCommandHelpDocumentsConfiguration(t *testing.T) {
	help := verifyCmd.Long + "\n" + verifyCmd.Example
	requiredPhrases := []string{
		"hal verify --json",
		"Minimal shell-check configuration",
		"verify:",
		"checks:",
		"command: go test ./...",
		"required: false",
		"Required checks fail the verification gate",
		"Optional checks produce warnings",
		"pass and warn results",
		"fail results",
	}

	for _, phrase := range requiredPhrases {
		if !strings.Contains(help, phrase) {
			t.Fatalf("verify help missing %q:\n%s", phrase, help)
		}
	}
}

func verifyResultFixture(status, checkStatus string, required bool) *verify.Result {
	now := time.Date(2026, 6, 21, 5, 45, 0, 0, time.UTC)
	result := &verify.Result{
		SchemaVersion: verify.SchemaVersion,
		GeneratedAt:   now,
		Status:        status,
		Summary: verify.Summary{
			Total: 1,
		},
		Checks: []verify.CheckResult{
			{
				ID:             "test",
				Name:           "Unit tests",
				Adapter:        verify.AdapterShell,
				Status:         checkStatus,
				Required:       required,
				Command:        "go test ./...",
				WorkDir:        "/repo",
				TimeoutSeconds: 60,
				StartedAt:      now,
				FinishedAt:     now.Add(time.Second),
				DurationMs:     1000,
				ExitCode:       exitCodeForCheckStatus(checkStatus),
				StdoutArtifact: "",
				StderrArtifact: "",
				Message:        "check " + checkStatus,
			},
		},
		Warnings:  []verify.Warning{},
		Artifacts: []verify.ArtifactReference{},
	}

	switch checkStatus {
	case verify.CheckStatusPass:
		result.Summary.Passed = 1
	case verify.CheckStatusFail:
		result.Summary.Failed = 1
	case verify.CheckStatusTimeout:
		result.Summary.TimedOut = 1
	case verify.CheckStatusMissing:
		result.Summary.Missing = 1
	case verify.CheckStatusSkipped:
		result.Summary.Skipped = 1
	}
	if status == verify.StatusWarn {
		result.Summary.Warnings = 1
		result.Warnings = []verify.Warning{
			{
				CheckID: "test",
				Status:  checkStatus,
				Message: "check " + checkStatus,
			},
		}
	}

	return result
}

func exitCodeForCheckStatus(status string) int {
	if status == verify.CheckStatusPass {
		return 0
	}
	return 1
}
