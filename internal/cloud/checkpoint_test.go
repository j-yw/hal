package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// checkpointMockGit implements runner.GitOps for checkpoint service tests.
type checkpointMockGit struct {
	addErr    error
	commitErr error
	commitSHA string
	pushErr   error

	addCalls    []checkpointGitAddCall
	commitCalls []checkpointGitCommitCall
	pushCalls   []checkpointGitPushCall
}

type checkpointGitAddCall struct {
	SandboxID string
	Path      string
	Files     []string
}

type checkpointGitCommitCall struct {
	SandboxID string
	Request   *runner.GitCommitRequest
}

type checkpointGitPushCall struct {
	SandboxID string
	Request   *runner.GitPushRequest
}

func (g *checkpointMockGit) GitClone(_ context.Context, _ string, _ *runner.GitCloneRequest) error {
	return nil
}

func (g *checkpointMockGit) GitAdd(_ context.Context, sandboxID, path string, files []string) error {
	g.addCalls = append(g.addCalls, checkpointGitAddCall{SandboxID: sandboxID, Path: path, Files: files})
	return g.addErr
}

func (g *checkpointMockGit) GitCommit(_ context.Context, sandboxID string, req *runner.GitCommitRequest) (*runner.GitCommitResult, error) {
	g.commitCalls = append(g.commitCalls, checkpointGitCommitCall{SandboxID: sandboxID, Request: req})
	if g.commitErr != nil {
		return nil, g.commitErr
	}
	return &runner.GitCommitResult{SHA: g.commitSHA}, nil
}

func (g *checkpointMockGit) GitPush(_ context.Context, sandboxID string, req *runner.GitPushRequest) error {
	g.pushCalls = append(g.pushCalls, checkpointGitPushCall{SandboxID: sandboxID, Request: req})
	return g.pushErr
}

func (g *checkpointMockGit) GitCreateBranch(_ context.Context, _, _, _ string) error { return nil }
func (g *checkpointMockGit) GitCheckout(_ context.Context, _, _, _ string) error     { return nil }
func (g *checkpointMockGit) GitListBranches(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}

func validCheckpointRequest() *CheckpointRequest {
	return &CheckpointRequest{
		SandboxID:     "sandbox-001",
		AttemptID:     "att-001",
		RunID:         "run-001",
		WorkingBranch: "hal/cloud/run-001",
		RepoPath:      "/workspace",
		Message:       "checkpoint after attempt 1",
		GitUsername:    "x-access-token",
		GitPassword:   "ghp_test123",
	}
}

func TestCheckpoint(t *testing.T) {
	t.Run("successful_checkpoint", func(t *testing.T) {
		store := &bootstrapMockStore{}
		git := &checkpointMockGit{commitSHA: "abc123"}

		idCounter := 0
		svc := NewCheckpointService(store, git, CheckpointConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		result, err := svc.Checkpoint(context.Background(), validCheckpointRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.CommitSHA != "abc123" {
			t.Errorf("CommitSHA = %q, want %q", result.CommitSHA, "abc123")
		}
		if !result.Pushed {
			t.Error("Pushed = false, want true")
		}

		// Verify add call.
		if len(git.addCalls) != 1 {
			t.Fatalf("addCalls = %d, want 1", len(git.addCalls))
		}
		if git.addCalls[0].SandboxID != "sandbox-001" {
			t.Errorf("add sandboxID = %q, want %q", git.addCalls[0].SandboxID, "sandbox-001")
		}
		if git.addCalls[0].Path != "/workspace" {
			t.Errorf("add path = %q, want %q", git.addCalls[0].Path, "/workspace")
		}
		if len(git.addCalls[0].Files) != 1 || git.addCalls[0].Files[0] != "." {
			t.Errorf("add files = %v, want [\".\"]", git.addCalls[0].Files)
		}

		// Verify commit call.
		if len(git.commitCalls) != 1 {
			t.Fatalf("commitCalls = %d, want 1", len(git.commitCalls))
		}
		cr := git.commitCalls[0].Request
		if cr.Path != "/workspace" {
			t.Errorf("commit path = %q, want %q", cr.Path, "/workspace")
		}
		if cr.Message != "checkpoint after attempt 1" {
			t.Errorf("commit message = %q, want checkpoint message", cr.Message)
		}
		if cr.Author != "hal-cloud" {
			t.Errorf("commit author = %q, want %q", cr.Author, "hal-cloud")
		}
		if cr.AllowEmpty {
			t.Error("commit allowEmpty = true, want false")
		}

		// Verify push call with credentials.
		if len(git.pushCalls) != 1 {
			t.Fatalf("pushCalls = %d, want 1", len(git.pushCalls))
		}
		pr := git.pushCalls[0].Request
		if pr.Path != "/workspace" {
			t.Errorf("push path = %q, want %q", pr.Path, "/workspace")
		}
		if pr.Username != "x-access-token" {
			t.Errorf("push username = %q, want %q", pr.Username, "x-access-token")
		}
		if pr.Password != "ghp_test123" {
			t.Errorf("push password = %q, want %q", pr.Password, "ghp_test123")
		}

		// Verify events: checkpoint_started + checkpoint_completed.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("events = %d, want 2", len(store.insertedEvents))
		}
		if store.insertedEvents[0].EventType != "checkpoint_started" {
			t.Errorf("event[0] = %q, want checkpoint_started", store.insertedEvents[0].EventType)
		}
		if store.insertedEvents[1].EventType != "checkpoint_completed" {
			t.Errorf("event[1] = %q, want checkpoint_completed", store.insertedEvents[1].EventType)
		}
		// Verify completed payload has commit SHA.
		var payload checkpointEventPayload
		if err := json.Unmarshal([]byte(*store.insertedEvents[1].PayloadJSON), &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if payload.CommitSHA != "abc123" {
			t.Errorf("payload commit_sha = %q, want %q", payload.CommitSHA, "abc123")
		}
	})

	t.Run("nothing_to_commit_still_pushes", func(t *testing.T) {
		store := &bootstrapMockStore{}
		git := &checkpointMockGit{
			commitErr: fmt.Errorf("nothing to commit, working tree clean"),
		}

		svc := NewCheckpointService(store, git, CheckpointConfig{})

		result, err := svc.Checkpoint(context.Background(), validCheckpointRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.CommitSHA != "" {
			t.Errorf("CommitSHA = %q, want empty (nothing to commit)", result.CommitSHA)
		}
		if !result.Pushed {
			t.Error("Pushed = false, want true (push should still happen)")
		}

		// Push should still be called (prior unpushed commits may exist).
		if len(git.pushCalls) != 1 {
			t.Fatalf("pushCalls = %d, want 1", len(git.pushCalls))
		}
	})

	t.Run("add_failure", func(t *testing.T) {
		store := &bootstrapMockStore{}
		git := &checkpointMockGit{
			addErr: fmt.Errorf("sandbox unreachable"),
		}

		svc := NewCheckpointService(store, git, CheckpointConfig{})

		_, err := svc.Checkpoint(context.Background(), validCheckpointRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "checkpoint add failed") {
			t.Errorf("error = %q, want to contain 'checkpoint add failed'", err.Error())
		}

		// No commit or push should have been attempted.
		if len(git.commitCalls) != 0 {
			t.Errorf("commitCalls = %d, want 0", len(git.commitCalls))
		}
		if len(git.pushCalls) != 0 {
			t.Errorf("pushCalls = %d, want 0", len(git.pushCalls))
		}

		// checkpoint_failed event should have been emitted.
		failed := filterEventsByType(store.insertedEvents, "checkpoint_failed")
		if len(failed) != 1 {
			t.Fatalf("checkpoint_failed events = %d, want 1", len(failed))
		}
		var payload checkpointEventPayload
		if err := json.Unmarshal([]byte(*failed[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if payload.Step != "add" {
			t.Errorf("payload step = %q, want %q", payload.Step, "add")
		}
	})

	t.Run("push_failure", func(t *testing.T) {
		store := &bootstrapMockStore{}
		git := &checkpointMockGit{
			commitSHA: "def456",
			pushErr:   fmt.Errorf("authentication failed"),
		}

		svc := NewCheckpointService(store, git, CheckpointConfig{})

		_, err := svc.Checkpoint(context.Background(), validCheckpointRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "checkpoint push failed") {
			t.Errorf("error = %q, want to contain 'checkpoint push failed'", err.Error())
		}

		// checkpoint_failed event with step=push.
		failed := filterEventsByType(store.insertedEvents, "checkpoint_failed")
		if len(failed) != 1 {
			t.Fatalf("checkpoint_failed events = %d, want 1", len(failed))
		}
		var payload checkpointEventPayload
		if err := json.Unmarshal([]byte(*failed[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if payload.Step != "push" {
			t.Errorf("payload step = %q, want %q", payload.Step, "push")
		}
	})

	t.Run("default_message", func(t *testing.T) {
		store := &bootstrapMockStore{}
		git := &checkpointMockGit{commitSHA: "aaa"}

		svc := NewCheckpointService(store, git, CheckpointConfig{})

		req := validCheckpointRequest()
		req.Message = ""
		_, err := svc.Checkpoint(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if git.commitCalls[0].Request.Message != "hal cloud checkpoint" {
			t.Errorf("commit message = %q, want default", git.commitCalls[0].Request.Message)
		}
	})

	t.Run("custom_author_email", func(t *testing.T) {
		store := &bootstrapMockStore{}
		git := &checkpointMockGit{commitSHA: "bbb"}

		svc := NewCheckpointService(store, git, CheckpointConfig{
			Author: "my-bot",
			Email:  "bot@example.com",
		})

		_, err := svc.Checkpoint(context.Background(), validCheckpointRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cr := git.commitCalls[0].Request
		if cr.Author != "my-bot" {
			t.Errorf("commit author = %q, want %q", cr.Author, "my-bot")
		}
		if cr.Email != "bot@example.com" {
			t.Errorf("commit email = %q, want %q", cr.Email, "bot@example.com")
		}
	})
}

func TestCheckpointRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *CheckpointRequest)
		wantErr string
	}{
		{name: "valid", modify: func(r *CheckpointRequest) {}, wantErr: ""},
		{name: "empty_sandboxID", modify: func(r *CheckpointRequest) { r.SandboxID = "" }, wantErr: "sandboxID must not be empty"},
		{name: "empty_attemptID", modify: func(r *CheckpointRequest) { r.AttemptID = "" }, wantErr: "attemptID must not be empty"},
		{name: "empty_runID", modify: func(r *CheckpointRequest) { r.RunID = "" }, wantErr: "runID must not be empty"},
		{name: "empty_workingBranch", modify: func(r *CheckpointRequest) { r.WorkingBranch = "" }, wantErr: "workingBranch must not be empty"},
		{name: "empty_repoPath", modify: func(r *CheckpointRequest) { r.RepoPath = "" }, wantErr: "repoPath must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validCheckpointRequest()
			tt.modify(req)
			err := req.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
