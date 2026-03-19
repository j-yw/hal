package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
)

type analyzeFakeEngine struct{}

func (analyzeFakeEngine) Name() string { return "fake" }

func (analyzeFakeEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (analyzeFakeEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return "", nil
}

func (analyzeFakeEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return "", nil
}

func newAnalyzeTestCommand(t *testing.T) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "analyze"}
	cmd.Flags().String("reports-dir", "", "")
	cmd.Flags().String("format", "text", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().Bool("json", false, "")

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	return cmd, &out, &errOut
}

func baseAnalyzeDeps() analyzeDeps {
	return analyzeDeps{
		loadConfig: func(dir string) (*compound.AutoConfig, error) {
			return &compound.AutoConfig{
				ReportsDir:    ".hal/reports",
				BranchPrefix:  "compound/",
				MaxIterations: 25,
			}, nil
		},
		findLatest: func(reportsDir string) (string, error) {
			return ".hal/reports/latest.md", nil
		},
		findRecentPRDs: func(dir string, days int) ([]string, error) {
			return nil, nil
		},
		newEngine: func(name string) (engine.Engine, error) {
			return analyzeFakeEngine{}, nil
		},
		analyzeReport: func(ctx context.Context, eng engine.Engine, reportPath string, recentPRDs []string) (*compound.AnalysisResult, error) {
			return &compound.AnalysisResult{
				PriorityItem:       "Top priority",
				Description:        "Build the thing",
				Rationale:          "Big impact",
				AcceptanceCriteria: []string{"Works"},
				EstimatedTasks:     8,
				BranchName:         "top-priority",
			}, nil
		},
	}
}

func assertExitCodeError(t *testing.T, err error, code int, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected exit code error %d, got nil", code)
	}

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitCodeError, got %T: %v", err, err)
	}
	if exitErr.Code != code {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, code)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not contain %q", err.Error(), contains)
	}
}

func TestRunAnalyze_FormatValidation(t *testing.T) {
	cmd, _, _ := newAnalyzeTestCommand(t)
	if err := cmd.Flags().Set("format", "xml"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	err := runAnalyzeWithDeps(cmd, nil, baseAnalyzeDeps())
	assertExitCodeError(t, err, ExitCodeValidation, "invalid format")
}

func TestRunAnalyze_OutputAliasWarningAndConflict(t *testing.T) {
	t.Run("deprecated --output warns", func(t *testing.T) {
		cmd, out, errOut := newAnalyzeTestCommand(t)
		if err := cmd.Flags().Set("output", "json"); err != nil {
			t.Fatalf("set output: %v", err)
		}

		err := runAnalyzeWithDeps(cmd, nil, baseAnalyzeDeps())
		if err != nil {
			t.Fatalf("runAnalyzeWithDeps() unexpected error: %v", err)
		}

		if !strings.Contains(errOut.String(), "deprecated") {
			t.Fatalf("stderr %q does not contain deprecation warning", errOut.String())
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("stdout is not valid JSON: %q", out.String())
		}
	})

	t.Run("--output conflicts with --format", func(t *testing.T) {
		cmd, _, _ := newAnalyzeTestCommand(t)
		if err := cmd.Flags().Set("format", "json"); err != nil {
			t.Fatalf("set format: %v", err)
		}
		if err := cmd.Flags().Set("output", "text"); err != nil {
			t.Fatalf("set output: %v", err)
		}

		err := runAnalyzeWithDeps(cmd, nil, baseAnalyzeDeps())
		assertExitCodeError(t, err, ExitCodeValidation, "--output/-o cannot be used with --format/-f")
	})

	t.Run("--json=false does not conflict with --format", func(t *testing.T) {
		cmd, out, _ := newAnalyzeTestCommand(t)
		if err := cmd.Flags().Set("json", "false"); err != nil {
			t.Fatalf("set json: %v", err)
		}
		if err := cmd.Flags().Set("format", "json"); err != nil {
			t.Fatalf("set format: %v", err)
		}

		err := runAnalyzeWithDeps(cmd, nil, baseAnalyzeDeps())
		if err != nil {
			t.Fatalf("runAnalyzeWithDeps() unexpected error: %v", err)
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("stdout is not valid JSON: %q", out.String())
		}
	})
}

func TestRunAnalyze_JSONPurity(t *testing.T) {
	cmd, out, errOut := newAnalyzeTestCommand(t)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	deps := baseAnalyzeDeps()
	deps.findRecentPRDs = func(dir string, days int) ([]string, error) {
		return nil, errors.New("boom")
	}

	err := runAnalyzeWithDeps(cmd, nil, deps)
	if err != nil {
		t.Fatalf("runAnalyzeWithDeps() unexpected error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout is not valid JSON: %q", out.String())
	}
	if strings.Contains(out.String(), "warning:") {
		t.Fatalf("stdout should not contain warnings: %q", out.String())
	}
	if strings.Contains(out.String(), "ANALYSIS RESULT") {
		t.Fatalf("stdout should not contain text-mode prose: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "warning: could not find recent PRDs") {
		t.Fatalf("stderr %q missing warning", errOut.String())
	}
}

func TestRunAnalyze_JSONNoReportsExitCode3AndEmptyStdout(t *testing.T) {
	cmd, out, _ := newAnalyzeTestCommand(t)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	deps := baseAnalyzeDeps()
	deps.findLatest = func(reportsDir string) (string, error) {
		return "", compound.ErrNoReportsFound
	}

	err := runAnalyzeWithDeps(cmd, nil, deps)
	assertExitCodeError(t, err, ExitCodeAnalyzeNoReportsJSON, "no reports found")
	if out.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", out.String())
	}
}

func TestRunAnalyze_TextModeNoReportsFriendlyMessage(t *testing.T) {
	cmd, out, _ := newAnalyzeTestCommand(t)
	deps := baseAnalyzeDeps()
	deps.findLatest = func(reportsDir string) (string, error) {
		return "", compound.ErrNoReportsFound
	}

	err := runAnalyzeWithDeps(cmd, nil, deps)
	if err != nil {
		t.Fatalf("runAnalyzeWithDeps() unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "No reports found.") {
		t.Fatalf("stdout %q missing no-report message", out.String())
	}
	if !strings.Contains(out.String(), "Place your reports in") {
		t.Fatalf("stdout %q missing guidance", out.String())
	}
}

func TestRunAnalyze_JSONFindLatestErrorIsPropagated(t *testing.T) {
	cmd, out, _ := newAnalyzeTestCommand(t)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	deps := baseAnalyzeDeps()
	deps.findLatest = func(reportsDir string) (string, error) {
		return "", errors.New("failed to read reports directory: permission denied")
	}

	err := runAnalyzeWithDeps(cmd, nil, deps)
	if err == nil {
		t.Fatal("runAnalyzeWithDeps() expected error, got nil")
	}

	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) && exitErr.Code == ExitCodeAnalyzeNoReportsJSON {
		t.Fatalf("expected non-no-reports error to be propagated, got exit code %d: %v", exitErr.Code, err)
	}
	if !strings.Contains(err.Error(), "failed to find latest report: failed to read reports directory: permission denied") {
		t.Fatalf("error %q missing wrapped filesystem failure", err.Error())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", out.String())
	}
}
