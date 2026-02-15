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
)

func TestReviewCommandUsageAndExamples(t *testing.T) {
	if reviewCmd.Use != "review against <base-branch> [iterations]" {
		t.Fatalf("reviewCmd.Use = %q, want %q", reviewCmd.Use, "review against <base-branch> [iterations]")
	}

	examples := []string{
		"hal review against develop",
		"hal review against origin/main 5",
		"hal review against develop 3 -e codex",
	}
	for _, example := range examples {
		if !strings.Contains(reviewCmd.Example, example) {
			t.Fatalf("reviewCmd.Example = %q, missing %q", reviewCmd.Example, example)
		}
	}

	outputFlag := reviewCmd.Flags().Lookup("output")
	if outputFlag == nil {
		t.Fatal("review command should expose --output flag")
	}
	if outputFlag.DefValue != reviewOutputBoth {
		t.Fatalf("--output default = %q, want %q", outputFlag.DefValue, reviewOutputBoth)
	}

	engineFlag := reviewCmd.Flags().Lookup("engine")
	if engineFlag == nil {
		t.Fatal("review command should expose --engine flag")
	}
	if engineFlag.DefValue != "codex" {
		t.Fatalf("--engine default = %q, want %q", engineFlag.DefValue, "codex")
	}
}

func TestNormalizeReviewOutputMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantMode string
		wantErr  string
	}{
		{
			name:     "empty defaults to both",
			input:    "",
			wantMode: reviewOutputBoth,
		},
		{
			name:     "both",
			input:    "both",
			wantMode: reviewOutputBoth,
		},
		{
			name:     "human",
			input:    "human",
			wantMode: reviewOutputHuman,
		},
		{
			name:     "json",
			input:    "json",
			wantMode: reviewOutputJSON,
		},
		{
			name:     "mixed case and spaces",
			input:    "  HuMaN ",
			wantMode: reviewOutputHuman,
		},
		{
			name:    "invalid",
			input:   "yaml",
			wantErr: "output must be one of: human, json, both",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeReviewOutputMode(tt.input)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantMode {
				t.Fatalf("mode = %q, want %q", got, tt.wantMode)
			}
		})
	}
}

func TestNormalizeReviewEngine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty defaults to codex", in: "", want: "codex"},
		{name: "trim and lowercase", in: "  ClAuDe  ", want: "claude"},
		{name: "already normalized", in: "pi", want: "pi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeReviewEngine(tt.in); got != tt.want {
				t.Fatalf("normalizeReviewEngine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRunReviewWithDeps(t *testing.T) {
	tests := []struct {
		name               string
		args               []string
		outputMode         string
		engineName         string
		branchExists       bool
		branchErr          error
		runErr             error
		wantErr            string
		wantRun            bool
		expectBranchLookup bool
		wantBranch         string
		wantRequest        reviewRequest
	}{
		{
			name:               "valid args default iterations and default output mode",
			args:               []string{"against", "develop"},
			outputMode:         "",
			branchExists:       true,
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "develop",
			wantRequest: reviewRequest{
				BaseBranch: "develop",
				Iterations: 10,
				OutputMode: reviewOutputBoth,
				Engine:     "codex",
			},
		},
		{
			name:               "valid args explicit iterations and json output",
			args:               []string{"against", "origin/main", "5"},
			outputMode:         "json",
			branchExists:       true,
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "origin/main",
			wantRequest: reviewRequest{
				BaseBranch: "origin/main",
				Iterations: 5,
				OutputMode: reviewOutputJSON,
				Engine:     "codex",
			},
		},
		{
			name:               "valid args normalizes mixed-case output",
			args:               []string{"against", "develop"},
			outputMode:         "HuMaN",
			branchExists:       true,
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "develop",
			wantRequest: reviewRequest{
				BaseBranch: "develop",
				Iterations: 10,
				OutputMode: reviewOutputHuman,
				Engine:     "codex",
			},
		},
		{
			name:               "normalizes engine name",
			args:               []string{"against", "develop"},
			outputMode:         reviewOutputBoth,
			engineName:         "  ClAuDe  ",
			branchExists:       true,
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "develop",
			wantRequest: reviewRequest{
				BaseBranch: "develop",
				Iterations: 10,
				OutputMode: reviewOutputBoth,
				Engine:     "claude",
			},
		},
		{
			name:       "invalid output mode",
			args:       []string{"against", "develop"},
			outputMode: "xml",
			wantErr:    "output must be one of: human, json, both",
		},
		{
			name:               "missing branch",
			args:               []string{"against", "missing-branch"},
			outputMode:         reviewOutputBoth,
			branchExists:       false,
			wantErr:            "base branch missing-branch not found",
			expectBranchLookup: true,
			wantBranch:         "missing-branch",
		},
		{
			name:       "non-numeric iterations",
			args:       []string{"against", "develop", "nope"},
			outputMode: reviewOutputBoth,
			wantErr:    "iterations must be a positive integer",
		},
		{
			name:       "zero iterations",
			args:       []string{"against", "develop", "0"},
			outputMode: reviewOutputBoth,
			wantErr:    "iterations must be a positive integer",
		},
		{
			name:               "base branch check failure",
			args:               []string{"against", "develop"},
			outputMode:         reviewOutputBoth,
			branchErr:          errors.New("git unavailable"),
			wantErr:            "failed to verify base branch \"develop\": git unavailable",
			expectBranchLookup: true,
			wantBranch:         "develop",
		},
		{
			name:       "invalid syntax",
			args:       []string{"develop"},
			outputMode: reviewOutputBoth,
			wantErr:    reviewUsage,
		},
		{
			name:               "run loop failure bubbles up",
			args:               []string{"against", "develop"},
			outputMode:         reviewOutputBoth,
			branchExists:       true,
			runErr:             errors.New("loop failed"),
			wantErr:            "loop failed",
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "develop",
			wantRequest: reviewRequest{
				BaseBranch: "develop",
				Iterations: 10,
				OutputMode: reviewOutputBoth,
				Engine:     "codex",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var branchChecked bool
			var gotBranch string
			var runCalled bool
			var gotRequest reviewRequest

			deps := reviewDeps{
				baseBranchExists: func(branch string) (bool, error) {
					branchChecked = true
					gotBranch = branch
					return tt.branchExists, tt.branchErr
				},
				runLoop: func(ctx context.Context, req reviewRequest) error {
					runCalled = true
					gotRequest = req
					return tt.runErr
				},
			}

			err := runReviewWithDeps(context.Background(), tt.args, tt.outputMode, tt.engineName, deps)

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

			if runCalled != tt.wantRun {
				t.Fatalf("runCalled = %v, want %v", runCalled, tt.wantRun)
			}
			if branchChecked != tt.expectBranchLookup {
				t.Fatalf("branchChecked = %v, want %v", branchChecked, tt.expectBranchLookup)
			}

			if tt.expectBranchLookup && gotBranch != tt.wantBranch {
				t.Fatalf("baseBranchExists called with %q, want %q", gotBranch, tt.wantBranch)
			}
			if tt.wantRun && gotRequest != tt.wantRequest {
				t.Fatalf("request = %+v, want %+v", gotRequest, tt.wantRequest)
			}
		})
	}
}

type fakeReviewLoopEngine struct{}

func (fakeReviewLoopEngine) Name() string { return "fake" }

func (fakeReviewLoopEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (fakeReviewLoopEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return "", nil
}

func (fakeReviewLoopEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return "", nil
}

func TestRunReviewLoopWithDeps(t *testing.T) {
	tests := []struct {
		name                string
		req                 reviewRequest
		newEngineErr        error
		runLoopErr          error
		writeJSONErr        error
		writeMarkdownErr    error
		buildMarkdownErr    error
		renderMarkdownErr   error
		wantErr             string
		expectRun           bool
		expectJSONWrite     bool
		expectMarkdownWrite bool
		expectMarkdownBuild bool
		expectRender        bool
		wantBase            string
		wantIters           int
		wantEngine          string
		wantOutput          string
	}{
		{
			name: "runs codex review loop and renders markdown in default both mode",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 4,
				OutputMode: "",
			},
			expectRun:           true,
			expectJSONWrite:     true,
			expectMarkdownWrite: true,
			expectMarkdownBuild: true,
			expectRender:        true,
			wantBase:            "develop",
			wantIters:           4,
			wantEngine:          "codex",
			wantOutput:          "rendered output",
		},
		{
			name: "uses requested engine",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 2,
				OutputMode: reviewOutputBoth,
				Engine:     "claude",
			},
			expectRun:           true,
			expectJSONWrite:     true,
			expectMarkdownWrite: true,
			expectMarkdownBuild: true,
			expectRender:        true,
			wantBase:            "develop",
			wantIters:           2,
			wantEngine:          "claude",
		},
		{
			name: "engine creation failure",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 2,
				OutputMode: reviewOutputBoth,
			},
			newEngineErr: errors.New("missing codex"),
			wantErr:      "failed to create codex engine: missing codex",
			expectRun:    false,
			wantEngine:   "codex",
		},
		{
			name: "invalid output mode",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 2,
				OutputMode: "yaml",
			},
			wantErr: "output must be one of: human, json, both",
		},
		{
			name: "engine invocation failure is clear",
			req: reviewRequest{
				BaseBranch: "origin/main",
				Iterations: 1,
				OutputMode: reviewOutputBoth,
			},
			runLoopErr: errors.New("prompt crashed"),
			wantErr:    "review loop failed with codex: prompt crashed",
			expectRun:  true,
			wantBase:   "origin/main",
			wantIters:  1,
			wantEngine: "codex",
		},
		{
			name: "json report write failure is clear",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 3,
				OutputMode: reviewOutputBoth,
			},
			writeJSONErr:    errors.New("disk full"),
			wantErr:         "failed to write review loop JSON report: disk full",
			expectRun:       true,
			expectJSONWrite: true,
			wantBase:        "develop",
			wantIters:       3,
			wantEngine:      "codex",
		},
		{
			name: "markdown report write failure is clear",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 3,
				OutputMode: reviewOutputBoth,
			},
			writeMarkdownErr:    errors.New("permission denied"),
			wantErr:             "failed to write review loop markdown report: permission denied",
			expectRun:           true,
			expectJSONWrite:     true,
			expectMarkdownWrite: true,
			wantBase:            "develop",
			wantIters:           3,
			wantEngine:          "codex",
		},
		{
			name: "markdown build failure is clear",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 3,
				OutputMode: reviewOutputBoth,
			},
			buildMarkdownErr:    errors.New("missing fields"),
			wantErr:             "failed to build review loop markdown summary: missing fields",
			expectRun:           true,
			expectJSONWrite:     true,
			expectMarkdownWrite: true,
			expectMarkdownBuild: true,
			wantBase:            "develop",
			wantIters:           3,
			wantEngine:          "codex",
		},
		{
			name: "markdown render failure is clear",
			req: reviewRequest{
				BaseBranch: "develop",
				Iterations: 3,
				OutputMode: reviewOutputBoth,
			},
			renderMarkdownErr:   errors.New("renderer failed"),
			wantErr:             "failed to render review loop markdown summary: renderer failed",
			expectRun:           true,
			expectJSONWrite:     true,
			expectMarkdownWrite: true,
			expectMarkdownBuild: true,
			expectRender:        true,
			wantBase:            "develop",
			wantIters:           3,
			wantEngine:          "codex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotEngineName string
			var runCalled bool
			var gotBase string
			var gotIterations int
			var jsonWriteCalled bool
			var markdownWriteCalled bool
			var markdownBuildCalled bool
			var renderCalled bool
			var gotJSONReportDir string
			var gotMarkdownReportDir string
			var gotJSONReportResult *compound.ReviewLoopResult
			var gotMarkdownReportResult *compound.ReviewLoopResult
			var gotBuildResult *compound.ReviewLoopResult
			var gotRenderInput string

			runResult := &compound.ReviewLoopResult{Command: "hal review against develop 1"}
			var out bytes.Buffer

			deps := reviewLoopDeps{
				newEngine: func(name string) (engine.Engine, error) {
					gotEngineName = name
					if tt.newEngineErr != nil {
						return nil, tt.newEngineErr
					}
					return fakeReviewLoopEngine{}, nil
				},
				runLoop: func(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*compound.ReviewLoopResult, error) {
					runCalled = true
					gotBase = baseBranch
					gotIterations = requestedIterations
					if tt.runLoopErr != nil {
						return nil, tt.runLoopErr
					}
					return runResult, nil
				},
				writeJSONReport: func(dir string, result *compound.ReviewLoopResult) (string, error) {
					jsonWriteCalled = true
					gotJSONReportDir = dir
					gotJSONReportResult = result
					if tt.writeJSONErr != nil {
						return "", tt.writeJSONErr
					}
					return ".hal/reports/review-loop-2026-02-15-180000-000.json", nil
				},
				writeMarkdownReport: func(dir string, result *compound.ReviewLoopResult) (string, error) {
					markdownWriteCalled = true
					gotMarkdownReportDir = dir
					gotMarkdownReportResult = result
					if tt.writeMarkdownErr != nil {
						return "", tt.writeMarkdownErr
					}
					return ".hal/reports/review-loop-2026-02-15-180000-000.md", nil
				},
				buildMarkdown: func(result *compound.ReviewLoopResult) (string, error) {
					markdownBuildCalled = true
					gotBuildResult = result
					if tt.buildMarkdownErr != nil {
						return "", tt.buildMarkdownErr
					}
					return "# Review Loop Summary\n\ncontent", nil
				},
				renderMarkdown: func(markdown string) (string, error) {
					renderCalled = true
					gotRenderInput = markdown
					if tt.renderMarkdownErr != nil {
						return "", tt.renderMarkdownErr
					}
					if tt.wantOutput != "" {
						return tt.wantOutput, nil
					}
					return "rendered output", nil
				},
			}

			err := runReviewLoopWithDeps(context.Background(), tt.req, &out, deps)
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

			if gotEngineName != tt.wantEngine {
				t.Fatalf("newEngine called with %q, want %q", gotEngineName, tt.wantEngine)
			}

			if runCalled != tt.expectRun {
				t.Fatalf("runCalled = %v, want %v", runCalled, tt.expectRun)
			}
			if tt.expectRun {
				if gotBase != tt.wantBase {
					t.Fatalf("runLoop baseBranch = %q, want %q", gotBase, tt.wantBase)
				}
				if gotIterations != tt.wantIters {
					t.Fatalf("runLoop requestedIterations = %d, want %d", gotIterations, tt.wantIters)
				}
			}

			if jsonWriteCalled != tt.expectJSONWrite {
				t.Fatalf("jsonWriteCalled = %v, want %v", jsonWriteCalled, tt.expectJSONWrite)
			}
			if tt.expectJSONWrite {
				if gotJSONReportDir != "." {
					t.Fatalf("writeJSONReport dir = %q, want %q", gotJSONReportDir, ".")
				}
				if gotJSONReportResult != runResult {
					t.Fatalf("writeJSONReport result pointer mismatch")
				}
			}

			if markdownWriteCalled != tt.expectMarkdownWrite {
				t.Fatalf("markdownWriteCalled = %v, want %v", markdownWriteCalled, tt.expectMarkdownWrite)
			}
			if tt.expectMarkdownWrite {
				if gotMarkdownReportDir != "." {
					t.Fatalf("writeMarkdownReport dir = %q, want %q", gotMarkdownReportDir, ".")
				}
				if gotMarkdownReportResult != runResult {
					t.Fatalf("writeMarkdownReport result pointer mismatch")
				}
			}

			if markdownBuildCalled != tt.expectMarkdownBuild {
				t.Fatalf("markdownBuildCalled = %v, want %v", markdownBuildCalled, tt.expectMarkdownBuild)
			}
			if tt.expectMarkdownBuild {
				if gotBuildResult != runResult {
					t.Fatalf("buildMarkdown result pointer mismatch")
				}
			}

			if renderCalled != tt.expectRender {
				t.Fatalf("renderCalled = %v, want %v", renderCalled, tt.expectRender)
			}
			if tt.expectRender {
				if !strings.Contains(gotRenderInput, "# Review Loop Summary") {
					t.Fatalf("render input = %q, want markdown summary heading", gotRenderInput)
				}
			}

			if tt.wantErr == "" && tt.wantOutput != "" {
				if out.String() != tt.wantOutput {
					t.Fatalf("stdout = %q, want %q", out.String(), tt.wantOutput)
				}
			}
		})
	}
}

func TestRunReviewLoopWithDepsOutputModes(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		expectBuild  bool
		expectRender bool
		wantRendered bool
		wantJSON     bool
	}{
		{
			name:         "human mode prints rendered markdown only",
			mode:         reviewOutputHuman,
			expectBuild:  true,
			expectRender: true,
			wantRendered: true,
		},
		{
			name:     "json mode prints valid JSON only",
			mode:     reviewOutputJSON,
			wantJSON: true,
		},
		{
			name:         "both mode prints rendered markdown",
			mode:         reviewOutputBoth,
			expectBuild:  true,
			expectRender: true,
			wantRendered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &compound.ReviewLoopResult{
				Command:             "hal review against develop 2",
				BaseBranch:          "develop",
				CurrentBranch:       "feature",
				RequestedIterations: 2,
				CompletedIterations: 1,
				StopReason:          "no_valid_issues",
			}

			var jsonWriteCalled bool
			var markdownWriteCalled bool
			var markdownBuildCalled bool
			var renderCalled bool
			var out bytes.Buffer

			deps := reviewLoopDeps{
				newEngine: func(name string) (engine.Engine, error) {
					return fakeReviewLoopEngine{}, nil
				},
				runLoop: func(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*compound.ReviewLoopResult, error) {
					return result, nil
				},
				writeJSONReport: func(dir string, result *compound.ReviewLoopResult) (string, error) {
					jsonWriteCalled = true
					return ".hal/reports/review-loop-2026-02-15-180000-000.json", nil
				},
				writeMarkdownReport: func(dir string, result *compound.ReviewLoopResult) (string, error) {
					markdownWriteCalled = true
					return ".hal/reports/review-loop-2026-02-15-180000-000.md", nil
				},
				buildMarkdown: func(result *compound.ReviewLoopResult) (string, error) {
					markdownBuildCalled = true
					return "# Review Loop Summary\n\ncontent", nil
				},
				renderMarkdown: func(markdown string) (string, error) {
					renderCalled = true
					return "rendered output", nil
				},
			}

			err := runReviewLoopWithDeps(context.Background(), reviewRequest{
				BaseBranch: "develop",
				Iterations: 2,
				OutputMode: tt.mode,
			}, &out, deps)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !jsonWriteCalled {
				t.Fatal("expected writeJSONReport to be called")
			}
			if !markdownWriteCalled {
				t.Fatal("expected writeMarkdownReport to be called")
			}
			if markdownBuildCalled != tt.expectBuild {
				t.Fatalf("markdownBuildCalled = %v, want %v", markdownBuildCalled, tt.expectBuild)
			}
			if renderCalled != tt.expectRender {
				t.Fatalf("renderCalled = %v, want %v", renderCalled, tt.expectRender)
			}

			stdout := out.String()
			if tt.wantRendered {
				if stdout != "rendered output" {
					t.Fatalf("stdout = %q, want rendered output", stdout)
				}
			}

			if tt.wantJSON {
				if strings.Contains(stdout, "rendered output") {
					t.Fatalf("stdout should not contain rendered markdown output: %q", stdout)
				}
				if !json.Valid([]byte(stdout)) {
					t.Fatalf("stdout is not valid JSON: %q", stdout)
				}

				var parsed compound.ReviewLoopResult
				if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
					t.Fatalf("failed to unmarshal stdout JSON: %v", err)
				}
				if parsed.Command != result.Command {
					t.Fatalf("parsed command = %q, want %q", parsed.Command, result.Command)
				}
			}
		})
	}
}
