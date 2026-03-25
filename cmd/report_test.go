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

type fakeReportEngine struct{}

func (fakeReportEngine) Name() string { return "fake" }

func (fakeReportEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (fakeReportEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return "", nil
}

func (fakeReportEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return "", nil
}

func TestReportCommandFlags(t *testing.T) {
	if reportCmd.Use != "report" {
		t.Fatalf("reportCmd.Use = %q, want %q", reportCmd.Use, "report")
	}
	if reportCmd.Args == nil {
		t.Fatal("report command should reject positional arguments")
	}
	if err := reportCmd.Args(reportCmd, []string{"unexpected"}); err == nil {
		t.Fatal("report command should return an error for positional arguments")
	}

	if !strings.Contains(strings.ToLower(reportCmd.Short), "report") {
		t.Fatalf("reportCmd.Short = %q, want to contain %q", reportCmd.Short, "report")
	}
	if !strings.Contains(strings.ToLower(reportCmd.Long), "summary report") {
		t.Fatalf("reportCmd.Long should mention summary report, got %q", reportCmd.Long)
	}

	if reportCmd.Flags().Lookup("dry-run") == nil {
		t.Fatal("report command missing --dry-run flag")
	}
	if reportCmd.Flags().Lookup("skip-agents") == nil {
		t.Fatal("report command missing --skip-agents flag")
	}

	engineFlag := reportCmd.Flags().Lookup("engine")
	if engineFlag == nil {
		t.Fatal("report command missing --engine flag")
	}
	if engineFlag.DefValue != "codex" {
		t.Fatalf("report --engine default = %q, want %q", engineFlag.DefValue, "codex")
	}
}

func TestRunReportWithDeps(t *testing.T) {
	type contextKey string
	const reviewContextKey contextKey = "report-test-key"
	const reviewContextValue = "report-test-value"

	tests := []struct {
		name             string
		dryRun           bool
		skipAgents       bool
		engineName       string
		newEngineErr     error
		reviewErr        error
		result           *compound.ReviewResult
		expectEngineCall bool
		expectReviewCall bool
		expectNilEngine  bool
		wantErr          string
		wantOutput       []string
		wantMissing      []string
	}{
		{
			name:       "success renders legacy review output",
			dryRun:     true,
			skipAgents: true,
			engineName: "codex",
			result: &compound.ReviewResult{
				ReportPath:      ".hal/reports/review-20260215.md",
				Summary:         "Implemented report split",
				Recommendations: []string{"Run hal report regularly", "Document migration for teams"},
			},
			expectEngineCall: false,
			expectReviewCall: true,
			expectNilEngine:  true,
			wantOutput: []string{
				"Review complete",
				"Summary: Implemented report split",
				"Recommendations:",
				"1. Run hal report regularly",
				"2. Document migration for teams",
			},
		},
		{
			name:       "missing report path returns error for non-dry-run",
			dryRun:     false,
			skipAgents: false,
			engineName: "claude",
			result: &compound.ReviewResult{
				Summary:         "ignored without report path",
				Recommendations: []string{"ignored"},
			},
			expectEngineCall: true,
			expectReviewCall: true,
			expectNilEngine:  false,
			wantErr:          "review did not produce a report path",
		},
		{
			name:       "missing report path is allowed in dry-run",
			dryRun:     true,
			skipAgents: false,
			engineName: "claude",
			result: &compound.ReviewResult{
				Summary:         "shown without report path",
				Recommendations: []string{"still shown in dry-run"},
			},
			expectEngineCall: false,
			expectReviewCall: true,
			expectNilEngine:  true,
			wantOutput: []string{
				"Summary: shown without report path",
				"Recommendations:",
				"1. still shown in dry-run",
			},
			wantMissing: []string{
				"Review complete",
			},
		},
		{
			name:             "engine creation failure",
			dryRun:           false,
			skipAgents:       false,
			engineName:       "pi",
			newEngineErr:     errors.New("engine unavailable"),
			expectEngineCall: true,
			expectReviewCall: false,
			wantErr:          "failed to create engine: engine unavailable",
		},
		{
			name:         "dry-run skips engine creation failure",
			dryRun:       true,
			skipAgents:   false,
			engineName:   "pi",
			newEngineErr: errors.New("engine unavailable"),
			result: &compound.ReviewResult{
				Summary: "dry-run preview works without engine",
			},
			expectEngineCall: false,
			expectReviewCall: true,
			expectNilEngine:  true,
			wantOutput: []string{
				"Summary: dry-run preview works without engine",
			},
		},
		{
			name:             "review failure bubbles up",
			dryRun:           false,
			skipAgents:       true,
			engineName:       "codex",
			reviewErr:        errors.New("review failed"),
			expectEngineCall: true,
			expectReviewCall: true,
			expectNilEngine:  false,
			wantErr:          "review failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			var reviewCalled bool
			var engineCalled bool
			var gotEngineName string
			var gotDir string
			var gotOpts compound.ReviewOptions
			var gotCtx context.Context
			var gotReviewEngine engine.Engine

			deps := reportDeps{
				newEngine: func(name string) (engine.Engine, error) {
					engineCalled = true
					gotEngineName = name
					if tt.newEngineErr != nil {
						return nil, tt.newEngineErr
					}
					return fakeReportEngine{}, nil
				},
				newDisplay: engine.NewDisplay,
				buildHeaderCtx: func(engineName string) engine.HeaderContext {
					return engine.HeaderContext{Engine: engineName}
				},
				runReview: func(ctx context.Context, eng engine.Engine, display *engine.Display, dir string, opts compound.ReviewOptions) (*compound.ReviewResult, error) {
					reviewCalled = true
					gotReviewEngine = eng
					gotCtx = ctx
					gotDir = dir
					gotOpts = opts
					if tt.reviewErr != nil {
						return nil, tt.reviewErr
					}
					return tt.result, nil
				},
			}

			inputCtx := context.WithValue(context.Background(), reviewContextKey, reviewContextValue)
			err := runReportWithDeps(inputCtx, "project-dir", tt.dryRun, tt.skipAgents, false, tt.engineName, &out, deps)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if reviewCalled != tt.expectReviewCall {
				t.Fatalf("reviewCalled = %v, want %v", reviewCalled, tt.expectReviewCall)
			}

			if engineCalled != tt.expectEngineCall {
				t.Fatalf("engineCalled = %v, want %v", engineCalled, tt.expectEngineCall)
			}

			if engineCalled && gotEngineName != tt.engineName {
				t.Fatalf("newEngine called with %q, want %q", gotEngineName, tt.engineName)
			}

			if tt.expectReviewCall {
				if gotCtx == nil {
					t.Fatal("expected context to be passed to runReview")
				}
				if gotCtx.Value(reviewContextKey) != reviewContextValue {
					t.Fatalf("context value = %v, want %v", gotCtx.Value(reviewContextKey), reviewContextValue)
				}
				if gotDir != "project-dir" {
					t.Fatalf("review dir = %q, want %q", gotDir, "project-dir")
				}
				if gotOpts.DryRun != tt.dryRun {
					t.Fatalf("DryRun = %v, want %v", gotOpts.DryRun, tt.dryRun)
				}
				if gotOpts.SkipAgents != tt.skipAgents {
					t.Fatalf("SkipAgents = %v, want %v", gotOpts.SkipAgents, tt.skipAgents)
				}
				if tt.expectNilEngine && gotReviewEngine != nil {
					t.Fatal("expected runReview to receive nil engine")
				}
				if !tt.expectNilEngine && gotReviewEngine == nil {
					t.Fatal("expected runReview to receive non-nil engine")
				}
			}

			output := out.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Fatalf("output %q does not contain %q", output, want)
				}
			}
			for _, missing := range tt.wantMissing {
				if strings.Contains(output, missing) {
					t.Fatalf("output %q should not contain %q", output, missing)
				}
			}
		})
	}
}

func TestRunReportWithDepsNormalizesEngineName(t *testing.T) {
	var out bytes.Buffer
	var gotEngineName string
	var gotHeaderEngineName string

	deps := reportDeps{
		newEngine: func(name string) (engine.Engine, error) {
			gotEngineName = name
			return fakeReportEngine{}, nil
		},
		newDisplay: engine.NewDisplay,
		buildHeaderCtx: func(engineName string) engine.HeaderContext {
			gotHeaderEngineName = engineName
			return engine.HeaderContext{Engine: engineName}
		},
		runReview: func(ctx context.Context, eng engine.Engine, display *engine.Display, dir string, opts compound.ReviewOptions) (*compound.ReviewResult, error) {
			return &compound.ReviewResult{
				ReportPath: ".hal/reports/review-20260215.md",
			}, nil
		},
	}

	err := runReportWithDeps(context.Background(), ".", false, false, false, " Claude ", &out, deps)
	if err != nil {
		t.Fatalf("runReportWithDeps returned error: %v", err)
	}

	if gotEngineName != "claude" {
		t.Fatalf("newEngine called with %q, want %q", gotEngineName, "claude")
	}
	if gotHeaderEngineName != "claude" {
		t.Fatalf("buildHeaderCtx called with %q, want %q", gotHeaderEngineName, "claude")
	}
}

func TestRunReportUsesCommandContext(t *testing.T) {
	originalDeps := defaultReportDeps
	originalDryRun := reportDryRunFlag
	originalSkipAgents := reportSkipAgentsFlag
	originalEngine := reportEngineFlag

	t.Cleanup(func() {
		defaultReportDeps = originalDeps
		reportDryRunFlag = originalDryRun
		reportSkipAgentsFlag = originalSkipAgents
		reportEngineFlag = originalEngine
	})

	type contextKey string
	const key contextKey = "command-context-key"
	const value = "command-context-value"

	var gotCtx context.Context
	defaultReportDeps = reportDeps{
		newEngine: func(name string) (engine.Engine, error) {
			return fakeReportEngine{}, nil
		},
		newDisplay: engine.NewDisplay,
		buildHeaderCtx: func(engineName string) engine.HeaderContext {
			return engine.HeaderContext{Engine: engineName}
		},
		runReview: func(ctx context.Context, eng engine.Engine, display *engine.Display, dir string, opts compound.ReviewOptions) (*compound.ReviewResult, error) {
			gotCtx = ctx
			return &compound.ReviewResult{}, nil
		},
	}

	reportDryRunFlag = true
	reportSkipAgentsFlag = false
	reportEngineFlag = "codex"

	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), key, value))

	if err := runReport(cmd, nil); err != nil {
		t.Fatalf("runReport returned error: %v", err)
	}

	if gotCtx == nil {
		t.Fatal("expected runReview to receive a context")
	}
	if gotCtx.Value(key) != value {
		t.Fatalf("runReview context value = %v, want %v", gotCtx.Value(key), value)
	}
}

func TestRunReportUsesCommandOutputWriter(t *testing.T) {
	originalDeps := defaultReportDeps
	originalDryRun := reportDryRunFlag
	originalSkipAgents := reportSkipAgentsFlag
	originalEngine := reportEngineFlag

	t.Cleanup(func() {
		defaultReportDeps = originalDeps
		reportDryRunFlag = originalDryRun
		reportSkipAgentsFlag = originalSkipAgents
		reportEngineFlag = originalEngine
	})

	defaultReportDeps = reportDeps{
		newEngine: func(name string) (engine.Engine, error) {
			return fakeReportEngine{}, nil
		},
		newDisplay: engine.NewDisplay,
		buildHeaderCtx: func(engineName string) engine.HeaderContext {
			return engine.HeaderContext{Engine: engineName}
		},
		runReview: func(ctx context.Context, eng engine.Engine, display *engine.Display, dir string, opts compound.ReviewOptions) (*compound.ReviewResult, error) {
			return &compound.ReviewResult{
				ReportPath: ".hal/reports/review-20260215.md",
				Summary:    "captured by command output",
			}, nil
		},
	}

	reportDryRunFlag = true
	reportSkipAgentsFlag = false
	reportEngineFlag = "codex"

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	if err := runReport(cmd, nil); err != nil {
		t.Fatalf("runReport returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Review complete") {
		t.Fatalf("output %q does not contain review success line", output)
	}
	if !strings.Contains(output, "Summary: captured by command output") {
		t.Fatalf("output %q does not contain summary", output)
	}
}

func TestReviewCommandLegacyFlagsRemoved(t *testing.T) {
	if reviewCmd.Flags().Lookup("dry-run") != nil {
		t.Fatal("review command should not expose legacy --dry-run flag")
	}
	if reviewCmd.Flags().Lookup("skip-agents") != nil {
		t.Fatal("review command should not expose legacy --skip-agents flag")
	}
}

func TestOutputReportJSON_IncludesNextAction(t *testing.T) {
	var buf bytes.Buffer
	result := &compound.ReviewResult{
		ReportPath: ".hal/reports/review.md",
		Summary:    "Done",
	}

	if err := outputReportJSON(&buf, result); err != nil {
		t.Fatalf("outputReportJSON error: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(buf.Bytes(), &raw)

	na, ok := raw["nextAction"].(map[string]interface{})
	if !ok {
		t.Fatal("nextAction should be present when reportPath is set")
	}
	if na["command"] != "hal auto" {
		t.Fatalf("nextAction.command = %q, want %q", na["command"], "hal auto")
	}
}
