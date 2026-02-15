package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
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
	tests := []struct {
		name             string
		dryRun           bool
		skipAgents       bool
		engineName       string
		newEngineErr     error
		reviewErr        error
		result           *compound.ReviewResult
		expectReviewCall bool
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
			expectReviewCall: true,
			wantOutput: []string{
				"Review complete",
				"Summary: Implemented report split",
				"Recommendations:",
				"1. Run hal report regularly",
				"2. Document migration for teams",
			},
		},
		{
			name:       "missing report path keeps quiet like legacy review",
			dryRun:     false,
			skipAgents: false,
			engineName: "claude",
			result: &compound.ReviewResult{
				Summary:         "ignored without report path",
				Recommendations: []string{"ignored"},
			},
			expectReviewCall: true,
			wantMissing: []string{
				"Review complete",
				"Summary:",
				"Recommendations:",
			},
		},
		{
			name:             "engine creation failure",
			dryRun:           false,
			skipAgents:       false,
			engineName:       "pi",
			newEngineErr:     errors.New("engine unavailable"),
			expectReviewCall: false,
			wantErr:          "failed to create engine: engine unavailable",
		},
		{
			name:             "review failure bubbles up",
			dryRun:           false,
			skipAgents:       true,
			engineName:       "codex",
			reviewErr:        errors.New("review failed"),
			expectReviewCall: true,
			wantErr:          "review failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			var reviewCalled bool
			var gotEngineName string
			var gotDir string
			var gotOpts compound.ReviewOptions

			deps := reportDeps{
				newEngine: func(name string) (engine.Engine, error) {
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
					gotDir = dir
					gotOpts = opts
					if tt.reviewErr != nil {
						return nil, tt.reviewErr
					}
					return tt.result, nil
				},
			}

			err := runReportWithDeps(context.Background(), "project-dir", tt.dryRun, tt.skipAgents, tt.engineName, &out, deps)

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

			if gotEngineName != tt.engineName {
				t.Fatalf("newEngine called with %q, want %q", gotEngineName, tt.engineName)
			}

			if tt.expectReviewCall {
				if gotDir != "project-dir" {
					t.Fatalf("review dir = %q, want %q", gotDir, "project-dir")
				}
				if gotOpts.DryRun != tt.dryRun {
					t.Fatalf("DryRun = %v, want %v", gotOpts.DryRun, tt.dryRun)
				}
				if gotOpts.SkipAgents != tt.skipAgents {
					t.Fatalf("SkipAgents = %v, want %v", gotOpts.SkipAgents, tt.skipAgents)
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

func TestReviewCommandLegacyFlagsRemoved(t *testing.T) {
	if reviewCmd.Flags().Lookup("dry-run") != nil {
		t.Fatal("review command should not expose legacy --dry-run flag")
	}
	if reviewCmd.Flags().Lookup("skip-agents") != nil {
		t.Fatal("review command should not expose legacy --skip-agents flag")
	}
	if reviewCmd.Flags().Lookup("engine") != nil {
		t.Fatal("review command should not expose legacy --engine flag")
	}
}
