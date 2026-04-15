package compound

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

func TestRunBranchStep_IdempotentBranchBehavior(t *testing.T) {
	requireGitCLI(t)

	tests := []struct {
		name  string
		setup func(t *testing.T, repoDir, baseBranch string) *PipelineState
		check func(t *testing.T, repoDir string)
	}{
		{
			name: "already on target branch returns success",
			setup: func(t *testing.T, repoDir, baseBranch string) *PipelineState {
				t.Helper()
				const target = "hal/already-on-target"
				runGit(t, repoDir, "checkout", "-b", target, baseBranch)
				return &PipelineState{
					Step:       StepBranch,
					BaseBranch: baseBranch,
					BranchName: target,
				}
			},
		},
		{
			name: "existing local target branch is checked out",
			setup: func(t *testing.T, repoDir, baseBranch string) *PipelineState {
				t.Helper()
				const target = "hal/existing-local-target"
				runGit(t, repoDir, "checkout", "-b", target, baseBranch)
				runGit(t, repoDir, "checkout", baseBranch)
				return &PipelineState{
					Step:       StepBranch,
					BaseBranch: baseBranch,
					BranchName: target,
				}
			},
		},
		{
			name: "missing local target branch is created from base branch",
			setup: func(t *testing.T, repoDir, baseBranch string) *PipelineState {
				t.Helper()

				runGit(t, repoDir, "checkout", "-b", "hal/other-work", baseBranch)
				writeFileInRepo(t, repoDir, "only-on-other.txt", "other branch content\n")
				runGit(t, repoDir, "add", "only-on-other.txt")
				runGit(t, repoDir, "commit", "-m", "other branch change")

				return &PipelineState{
					Step:       StepBranch,
					BaseBranch: baseBranch,
					BranchName: "hal/new-target-branch",
				}
			},
			check: func(t *testing.T, repoDir string) {
				t.Helper()
				if _, err := os.Stat(filepath.Join(repoDir, "only-on-other.txt")); !os.IsNotExist(err) {
					t.Fatalf("expected branch to be created from base without other-branch file, stat err=%v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir, baseBranch := initGitRepo(t)
			state := tt.setup(t, repoDir, baseBranch)

			var out bytes.Buffer
			display := engine.NewDisplay(&out)
			config := DefaultAutoConfig()
			pipeline := NewPipeline(&config, nil, display, repoDir)

			if err := pipeline.runBranchStep(context.Background(), state, RunOptions{}); err != nil {
				t.Fatalf("runBranchStep returned error: %v\noutput:\n%s", err, out.String())
			}

			if got := currentBranch(t, repoDir); got != state.BranchName {
				t.Fatalf("current branch = %q, want %q", got, state.BranchName)
			}
			if state.Step != StepSpec {
				t.Fatalf("state.Step = %q, want %q", state.Step, StepSpec)
			}

			if tt.check != nil {
				tt.check(t, repoDir)
			}
		})
	}
}

func TestRunBranchStep_CanRunRepeatedlyWithoutDuplicateBranchFailures(t *testing.T) {
	requireGitCLI(t)

	repoDir, baseBranch := initGitRepo(t)
	state := &PipelineState{
		Step:       StepBranch,
		BaseBranch: baseBranch,
		BranchName: "hal/retry-safe-branch",
	}

	var out bytes.Buffer
	display := engine.NewDisplay(&out)
	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, repoDir)

	for attempt := 1; attempt <= 3; attempt++ {
		state.Step = StepBranch
		if err := pipeline.runBranchStep(context.Background(), state, RunOptions{}); err != nil {
			t.Fatalf("attempt %d: runBranchStep returned error: %v", attempt, err)
		}
	}

	if got := currentBranch(t, repoDir); got != state.BranchName {
		t.Fatalf("current branch = %q, want %q", got, state.BranchName)
	}
}

func requireGitCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git CLI not found")
	}
}

func initGitRepo(t *testing.T) (string, string) {
	t.Helper()

	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.name", "hal-test")
	runGit(t, repoDir, "config", "user.email", "hal-test@example.com")

	writeFileInRepo(t, repoDir, "README.md", "# test repo\n")
	runGit(t, repoDir, "add", "README.md")
	runGit(t, repoDir, "commit", "-m", "initial commit")

	baseBranch := currentBranch(t, repoDir)
	if baseBranch == "" {
		t.Fatalf("expected non-empty base branch after init")
	}

	return repoDir, baseBranch
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s failed: %v (stdout: %s, stderr: %s)", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

func currentBranch(t *testing.T, dir string) string {
	t.Helper()
	branch, err := CurrentBranchOptionalInDir(dir)
	if err != nil {
		t.Fatalf("CurrentBranchOptionalInDir returned error: %v", err)
	}
	return strings.TrimSpace(branch)
}

func writeFileInRepo(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}
