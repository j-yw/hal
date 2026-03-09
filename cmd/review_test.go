package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestReviewCommandUsageAndExamples(t *testing.T) {
	if reviewCmd.Use != "review --base <base-branch> [iterations]" {
		t.Fatalf("reviewCmd.Use = %q, want %q", reviewCmd.Use, "review --base <base-branch> [iterations]")
	}

	examples := []string{
		"hal review --base develop",
		"hal review --base origin/main 5",
		"hal review --base develop --iterations 3 -e codex",
		"hal review against develop 3",
	}
	for _, example := range examples {
		if !strings.Contains(reviewCmd.Example, example) {
			t.Fatalf("reviewCmd.Example = %q, missing %q", reviewCmd.Example, example)
		}
	}

	if reviewCmd.Flags().Lookup("base") == nil {
		t.Fatal("review command should expose --base flag")
	}
	if reviewCmd.Flags().Lookup("iterations") == nil {
		t.Fatal("review command should expose --iterations flag")
	}

	engineFlag := reviewCmd.Flags().Lookup("engine")
	if engineFlag == nil {
		t.Fatal("review command should expose --engine flag")
	}
	if engineFlag.DefValue != "codex" {
		t.Fatalf("--engine default = %q, want %q", engineFlag.DefValue, "codex")
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

func TestParseReviewRequest(t *testing.T) {
	tests := []struct {
		name                  string
		args                  []string
		baseFlag              string
		baseFlagChanged       bool
		iterationsFlag        int
		iterationsFlagChanged bool
		resolvedBranch        string
		resolveErr            error
		wantErr               string
		wantReq               reviewRequest
		wantWarning           string
		wantResolveInput      string
	}{
		{
			name:             "canonical base with default iterations",
			baseFlag:         "develop",
			baseFlagChanged:  true,
			iterationsFlag:   10,
			resolvedBranch:   "develop",
			wantResolveInput: "develop",
			wantReq: reviewRequest{
				BaseBranch: "develop",
				Iterations: 10,
			},
		},
		{
			name:             "canonical positional iterations",
			args:             []string{"4"},
			baseFlag:         "develop",
			baseFlagChanged:  true,
			iterationsFlag:   10,
			resolvedBranch:   "origin/develop",
			wantResolveInput: "develop",
			wantReq: reviewRequest{
				BaseBranch: "origin/develop",
				Iterations: 4,
			},
		},
		{
			name:                  "canonical --iterations",
			baseFlag:              "develop",
			baseFlagChanged:       true,
			iterationsFlag:        6,
			iterationsFlagChanged: true,
			resolvedBranch:        "develop",
			wantResolveInput:      "develop",
			wantReq: reviewRequest{
				BaseBranch: "develop",
				Iterations: 6,
			},
		},
		{
			name:                  "canonical positional and --iterations conflict",
			args:                  []string{"4"},
			baseFlag:              "develop",
			baseFlagChanged:       true,
			iterationsFlag:        6,
			iterationsFlagChanged: true,
			wantErr:               "iterations provided both positionally and via --iterations",
		},
		{
			name:             "canonical missing base",
			iterationsFlag:   10,
			resolvedBranch:   "",
			wantErr:          "--base is required",
			wantResolveInput: "",
		},
		{
			name:             "deprecated alias",
			args:             []string{"against", "develop", "3"},
			iterationsFlag:   10,
			resolvedBranch:   "develop",
			wantResolveInput: "develop",
			wantReq: reviewRequest{
				BaseBranch: "develop",
				Iterations: 3,
			},
			wantWarning: "deprecated",
		},
		{
			name:            "alias conflicts with --base",
			args:            []string{"against", "develop"},
			baseFlag:        "main",
			baseFlagChanged: true,
			iterationsFlag:  10,
			wantErr:         "cannot use --base",
		},
		{
			name:                  "alias conflicts with --iterations",
			args:                  []string{"against", "develop"},
			iterationsFlag:        2,
			iterationsFlagChanged: true,
			wantErr:               "cannot use --iterations",
		},
		{
			name:             "branch resolve failure",
			baseFlag:         "develop",
			baseFlagChanged:  true,
			iterationsFlag:   10,
			resolveErr:       errors.New("git unavailable"),
			wantErr:          "failed to verify base branch \"develop\": git unavailable",
			wantResolveInput: "develop",
		},
		{
			name:             "branch not found",
			baseFlag:         "missing",
			baseFlagChanged:  true,
			iterationsFlag:   10,
			resolvedBranch:   "",
			wantErr:          "base branch missing not found",
			wantResolveInput: "missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotResolveInput string
			resolveFn := func(branch string) (string, error) {
				gotResolveInput = branch
				return tt.resolvedBranch, tt.resolveErr
			}

			var warn bytes.Buffer
			got, err := parseReviewRequest(
				tt.args,
				tt.baseFlag,
				tt.baseFlagChanged,
				tt.iterationsFlag,
				tt.iterationsFlagChanged,
				resolveFn,
				&warn,
			)

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

			if got != tt.wantReq {
				t.Fatalf("request = %+v, want %+v", got, tt.wantReq)
			}
			if gotResolveInput != tt.wantResolveInput {
				t.Fatalf("resolve branch input = %q, want %q", gotResolveInput, tt.wantResolveInput)
			}
			if tt.wantWarning != "" && !strings.Contains(warn.String(), tt.wantWarning) {
				t.Fatalf("warning %q does not contain %q", warn.String(), tt.wantWarning)
			}
			if tt.wantWarning == "" && warn.Len() > 0 {
				t.Fatalf("unexpected warning: %q", warn.String())
			}
		})
	}
}

func TestRunReviewUsesCommandContextAndFlags(t *testing.T) {
	originalDeps := defaultReviewDeps
	t.Cleanup(func() { defaultReviewDeps = originalDeps })

	type ctxKey string
	const key ctxKey = "trace"
	const value = "ctx-value"

	var gotCtx context.Context
	var gotReq reviewRequest
	var gotOut io.Writer
	defaultReviewDeps = reviewDeps{
		resolveBaseBranch: func(branch string) (string, error) {
			return branch, nil
		},
		runLoop: func(ctx context.Context, req reviewRequest, out io.Writer) error {
			gotCtx = ctx
			gotReq = req
			gotOut = out
			return nil
		},
	}

	cmd := &cobra.Command{Use: "review"}
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().Int("iterations", 10, "")
	if err := cmd.Flags().Set("engine", "  ClAuDe  "); err != nil {
		t.Fatalf("set engine flag: %v", err)
	}
	if err := cmd.Flags().Set("base", "develop"); err != nil {
		t.Fatalf("set base flag: %v", err)
	}
	if err := cmd.Flags().Set("iterations", "3"); err != nil {
		t.Fatalf("set iterations flag: %v", err)
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.WithValue(context.Background(), key, value))

	if err := runReview(cmd, nil); err != nil {
		t.Fatalf("runReview() unexpected error: %v", err)
	}

	if gotCtx == nil {
		t.Fatal("runLoop context was nil")
	}
	if got := gotCtx.Value(key); got != value {
		t.Fatalf("runLoop context value = %v, want %v", got, value)
	}
	if gotReq.BaseBranch != "develop" {
		t.Fatalf("BaseBranch = %q, want %q", gotReq.BaseBranch, "develop")
	}
	if gotReq.Iterations != 3 {
		t.Fatalf("Iterations = %d, want %d", gotReq.Iterations, 3)
	}
	if gotReq.Engine != "claude" {
		t.Fatalf("Engine = %q, want %q", gotReq.Engine, "claude")
	}
	if gotOut != cmd.OutOrStdout() {
		t.Fatal("runLoop output writer did not match command output writer")
	}
}

func TestRunReviewAliasWarnsOnce(t *testing.T) {
	originalDeps := defaultReviewDeps
	t.Cleanup(func() { defaultReviewDeps = originalDeps })

	defaultReviewDeps = reviewDeps{
		resolveBaseBranch: func(branch string) (string, error) {
			return branch, nil
		},
		runLoop: func(ctx context.Context, req reviewRequest, out io.Writer) error {
			return nil
		},
	}

	cmd := &cobra.Command{Use: "review"}
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().Int("iterations", 10, "")

	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	cmd.SetOut(io.Discard)

	if err := runReview(cmd, []string{"against", "develop", "2"}); err != nil {
		t.Fatalf("runReview() unexpected error: %v", err)
	}

	warning := errOut.String()
	if !strings.Contains(warning, "deprecated") {
		t.Fatalf("expected deprecation warning, got %q", warning)
	}
	lines := strings.Split(strings.TrimSpace(warning), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one deprecation warning line, got %q", warning)
	}
}

func TestGitRefExists(t *testing.T) {
	t.Run("missing ref returns false without error", func(t *testing.T) {
		exists, err := gitRefExists("definitely-missing-branch-xyz")
		if err != nil {
			t.Fatalf("gitRefExists() unexpected error: %v", err)
		}
		if exists {
			t.Fatal("gitRefExists() = true, want false")
		}
	})

	t.Run("outside git repo returns actionable error", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("os.Getwd() error = %v", err)
		}

		tempDir := t.TempDir()
		if err := os.Chdir(tempDir); err != nil {
			t.Fatalf("os.Chdir(%q) error = %v", tempDir, err)
		}
		t.Cleanup(func() {
			_ = os.Chdir(cwd)
		})

		exists, err := gitRefExists("develop")
		if err == nil {
			t.Fatal("gitRefExists() error = nil, want non-nil")
		}
		if exists {
			t.Fatal("gitRefExists() = true, want false")
		}
		if !strings.Contains(err.Error(), "not a git repository") {
			t.Fatalf("gitRefExists() error = %q, want to contain %q", err.Error(), "not a git repository")
		}
	})
}
