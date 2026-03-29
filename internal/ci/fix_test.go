package ci

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

type stubFixEngine struct{}

func (stubFixEngine) Name() string { return "stub" }

func (stubFixEngine) Execute(context.Context, string, *engine.Display) engine.Result {
	return engine.Result{}
}

func (stubFixEngine) Prompt(context.Context, string) (string, error) {
	return "", nil
}

func (stubFixEngine) StreamPrompt(context.Context, string, *engine.Display) (string, error) {
	return "", nil
}

func TestFixWithEngineWithDeps_RejectsNonFailingStatus(t *testing.T) {
	t.Parallel()

	_, err := fixWithEngineWithDeps(context.Background(), StatusResult{Status: StatusPassing}, FixOptions{
		Engine: stubFixEngine{},
	}, fixDeps{})
	if err == nil {
		t.Fatal("fixWithEngineWithDeps() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrFixRequiresFailingStatus) {
		t.Fatalf("errors.Is(err, ErrFixRequiresFailingStatus) = false, err=%v", err)
	}
}

func TestFixWithEngineWithDeps_RejectsNilEngine(t *testing.T) {
	t.Parallel()

	_, err := fixWithEngineWithDeps(context.Background(), failingStatusResult(), FixOptions{}, fixDeps{})
	if err == nil {
		t.Fatal("fixWithEngineWithDeps() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrFixRequiresEngine) {
		t.Fatalf("errors.Is(err, ErrFixRequiresEngine) = false, err=%v", err)
	}
}

func TestFixWithEngineWithDeps_RequiresCleanWorkingTreeByDefault(t *testing.T) {
	t.Parallel()

	streamCalled := false

	_, err := fixWithEngineWithDeps(context.Background(), failingStatusResult(), FixOptions{
		Engine: stubFixEngine{},
	}, fixDeps{
		workingTreeChanges: func(context.Context) ([]string, error) {
			return []string{"new_untracked_file.go"}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-fix", nil
		},
		streamPrompt: func(context.Context, engine.Engine, string, *engine.Display) (string, error) {
			streamCalled = true
			return "", nil
		},
	})
	if err == nil {
		t.Fatal("fixWithEngineWithDeps() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrFixDirtyWorkingTree) {
		t.Fatalf("errors.Is(err, ErrFixDirtyWorkingTree) = false, err=%v", err)
	}
	if !strings.Contains(err.Error(), "new_untracked_file.go") {
		t.Fatalf("error %q should list changed file", err)
	}
	if streamCalled {
		t.Fatal("streamPrompt should not be called when tree is dirty")
	}
}

func TestFixWithEngineWithDeps_RejectsNoChangesAfterEngine(t *testing.T) {
	t.Parallel()

	streamCalled := false
	addCalled := false
	commitCalled := false
	pushCalled := false
	changesCalls := 0

	_, err := fixWithEngineWithDeps(context.Background(), failingStatusResult(), FixOptions{
		Engine: stubFixEngine{},
	}, fixDeps{
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-fix", nil
		},
		workingTreeChanges: func(context.Context) ([]string, error) {
			changesCalls++
			return nil, nil
		},
		streamPrompt: func(_ context.Context, _ engine.Engine, prompt string, _ *engine.Display) (string, error) {
			streamCalled = true
			if !strings.Contains(prompt, "build") {
				t.Fatalf("prompt should include failing check name, got %q", prompt)
			}
			return "", nil
		},
		addAll: func(context.Context) error {
			addCalled = true
			return nil
		},
		commit: func(context.Context, string) error {
			commitCalled = true
			return nil
		},
		currentHeadSHA: func(context.Context) (string, error) {
			return "deadbeef", nil
		},
		pushBranch: func(context.Context, string) error {
			pushCalled = true
			return nil
		},
	})
	if err == nil {
		t.Fatal("fixWithEngineWithDeps() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrFixNoChanges) {
		t.Fatalf("errors.Is(err, ErrFixNoChanges) = false, err=%v", err)
	}
	if !streamCalled {
		t.Fatal("streamPrompt should be called")
	}
	if changesCalls != 2 {
		t.Fatalf("workingTreeChanges calls = %d, want 2", changesCalls)
	}
	if addCalled {
		t.Fatal("addAll should not be called when no files changed")
	}
	if commitCalled {
		t.Fatal("commit should not be called when no files changed")
	}
	if pushCalled {
		t.Fatal("pushBranch should not be called when no files changed")
	}
}

func TestFixWithEngineWithDeps_SuccessCommitsAndPushes(t *testing.T) {
	t.Parallel()

	const branch = "hal/ci-fix"

	changesCalls := 0
	addCalls := 0
	commitCalls := 0
	pushCalls := 0
	streamCalls := 0
	commitMessage := ""

	result, err := fixWithEngineWithDeps(context.Background(), failingStatusResult(), FixOptions{
		Engine:      stubFixEngine{},
		Attempt:     2,
		MaxAttempts: 4,
	}, fixDeps{
		currentBranch: func(context.Context) (string, error) {
			return branch, nil
		},
		workingTreeChanges: func(context.Context) ([]string, error) {
			changesCalls++
			if changesCalls == 1 {
				return nil, nil
			}
			return []string{"z.go", "a.go", "a.go", "b.go"}, nil
		},
		streamPrompt: func(_ context.Context, _ engine.Engine, prompt string, _ *engine.Display) (string, error) {
			streamCalls++
			for _, want := range []string{"build", "lint"} {
				if !strings.Contains(prompt, want) {
					t.Fatalf("prompt %q should contain %q", prompt, want)
				}
			}
			return "done", nil
		},
		addAll: func(context.Context) error {
			addCalls++
			return nil
		},
		commit: func(_ context.Context, msg string) error {
			commitCalls++
			commitMessage = msg
			return nil
		},
		currentHeadSHA: func(context.Context) (string, error) {
			return "deadbeef", nil
		},
		pushBranch: func(_ context.Context, gotBranch string) error {
			pushCalls++
			if gotBranch != branch {
				t.Fatalf("push branch = %q, want %q", gotBranch, branch)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("fixWithEngineWithDeps() error = %v", err)
	}

	if streamCalls != 1 {
		t.Fatalf("streamPrompt calls = %d, want 1", streamCalls)
	}
	if changesCalls != 2 {
		t.Fatalf("workingTreeChanges calls = %d, want 2", changesCalls)
	}
	if addCalls != 1 {
		t.Fatalf("addAll calls = %d, want 1", addCalls)
	}
	if commitCalls != 1 {
		t.Fatalf("commit calls = %d, want 1", commitCalls)
	}
	if pushCalls != 1 {
		t.Fatalf("pushBranch calls = %d, want 1", pushCalls)
	}

	if !strings.Contains(commitMessage, "attempt 2") {
		t.Fatalf("commit message = %q, want to include attempt metadata", commitMessage)
	}

	if result.ContractVersion != FixContractVersion {
		t.Fatalf("result.ContractVersion = %q, want %q", result.ContractVersion, FixContractVersion)
	}
	if result.Attempt != 2 {
		t.Fatalf("result.Attempt = %d, want 2", result.Attempt)
	}
	if result.MaxAttempts != 4 {
		t.Fatalf("result.MaxAttempts = %d, want 4", result.MaxAttempts)
	}
	if !result.Applied {
		t.Fatal("result.Applied = false, want true")
	}
	if result.Branch != branch {
		t.Fatalf("result.Branch = %q, want %q", result.Branch, branch)
	}
	if result.CommitSHA != "deadbeef" {
		t.Fatalf("result.CommitSHA = %q, want %q", result.CommitSHA, "deadbeef")
	}
	if !result.Pushed {
		t.Fatal("result.Pushed = false, want true")
	}
	if got, want := result.FilesChanged, []string{"a.go", "b.go", "z.go"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("result.FilesChanged = %v, want %v", got, want)
	}
	if !strings.Contains(result.Summary, branch) {
		t.Fatalf("result.Summary = %q, want branch %q", result.Summary, branch)
	}
}

func TestParsePorcelainPath_HandlesUntrackedAndRename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line string
		want string
	}{
		{line: "?? new_file.go", want: "new_file.go"},
		{line: " M internal/ci/fix.go", want: "internal/ci/fix.go"},
		{line: "R  old_name.go -> new_name.go", want: "new_name.go"},
		{line: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()

			if got := parsePorcelainPath(tt.line); got != tt.want {
				t.Fatalf("parsePorcelainPath(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func failingStatusResult() StatusResult {
	return StatusResult{
		Status: StatusFailing,
		Checks: []StatusCheck{
			{
				Key:    "check:build",
				Source: CheckSourceCheckRun,
				Name:   "build",
				Status: StatusFailing,
			},
			{
				Key:    "status:lint",
				Source: CheckSourceStatus,
				Name:   "lint",
				Status: StatusFailing,
			},
		},
		Summary: "status=failing (passing=0, failing=2, pending=0)",
	}
}
