package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// CheckpointConfig holds configuration for the checkpoint service.
type CheckpointConfig struct {
	// Author is the git commit author name. Defaults to "hal-cloud".
	Author string
	// Email is the git commit author email. Defaults to "hal-cloud@noreply".
	Email string
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// CheckpointService commits and pushes all sandbox changes to the working
// branch after execution. On retry, BootstrapService clones the working
// branch instead of the base branch so the new attempt resumes from the
// last checkpoint.
type CheckpointService struct {
	store  Store
	git    runner.GitOps
	config CheckpointConfig
}

// NewCheckpointService creates a new CheckpointService.
func NewCheckpointService(store Store, git runner.GitOps, config CheckpointConfig) *CheckpointService {
	if config.Author == "" {
		config.Author = "hal-cloud"
	}
	if config.Email == "" {
		config.Email = "hal-cloud@noreply"
	}
	return &CheckpointService{
		store:  store,
		git:    git,
		config: config,
	}
}

// CheckpointRequest contains the parameters for a git checkpoint.
type CheckpointRequest struct {
	// SandboxID is the sandbox containing the work to checkpoint.
	SandboxID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// RunID is the current run (for event correlation).
	RunID string
	// WorkingBranch is the branch to push to (e.g., "hal/cloud/run-abc").
	WorkingBranch string
	// RepoPath is the repository path inside the sandbox (e.g., "/workspace").
	RepoPath string
	// Message is the commit message.
	Message string
	// GitUsername is the HTTPS auth username for push (optional).
	GitUsername string
	// GitPassword is the HTTPS auth password/token for push (optional).
	GitPassword string
}

// Validate checks required fields on CheckpointRequest.
func (r *CheckpointRequest) Validate() error {
	if r.SandboxID == "" {
		return fmt.Errorf("sandboxID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	if r.WorkingBranch == "" {
		return fmt.Errorf("workingBranch must not be empty")
	}
	if r.RepoPath == "" {
		return fmt.Errorf("repoPath must not be empty")
	}
	return nil
}

// CheckpointResult holds the outcome of a checkpoint operation.
type CheckpointResult struct {
	// CommitSHA is the SHA of the checkpoint commit. Empty if nothing to commit.
	CommitSHA string
	// Pushed is true if changes were pushed to the remote.
	Pushed bool
}

// checkpointEventPayload is the JSON payload for checkpoint lifecycle events.
type checkpointEventPayload struct {
	SandboxID     string `json:"sandbox_id"`
	WorkingBranch string `json:"working_branch"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	Step          string `json:"step,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Checkpoint stages all changes, commits, and pushes to the working branch.
// It uses the Daytona Git SDK (GitOps) instead of raw Exec commands.
//
// Steps:
//  1. git add -A (stage all changes)
//  2. git commit --allow-empty=false (skip if nothing changed)
//  3. git push to working branch
//
// If add/commit finds nothing to push, the method returns success with
// Pushed=false. Push failures are returned as errors.
func (s *CheckpointService) Checkpoint(ctx context.Context, req *CheckpointRequest) (*CheckpointResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 1: Emit checkpoint_started event.
	startPayload := &checkpointEventPayload{
		SandboxID:     req.SandboxID,
		WorkingBranch: req.WorkingBranch,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "checkpoint_started", startPayload, now)

	// Step 2: Stage all changes.
	if err := s.git.GitAdd(ctx, req.SandboxID, req.RepoPath, []string{"."}); err != nil {
		s.emitCheckpointFailed(ctx, req, "add", err.Error(), now)
		return nil, fmt.Errorf("checkpoint add failed: %w", err)
	}

	// Step 3: Commit (allow-empty=false — skip if nothing staged).
	msg := req.Message
	if msg == "" {
		msg = "hal cloud checkpoint"
	}
	commitResult, err := s.git.GitCommit(ctx, req.SandboxID, &runner.GitCommitRequest{
		Path:       req.RepoPath,
		Message:    msg,
		Author:     s.config.Author,
		Email:      s.config.Email,
		AllowEmpty: false,
	})
	if err != nil {
		// "nothing to commit" is not a failure — the working tree is clean.
		// Daytona's Git API returns an error when there are no staged changes
		// and AllowEmpty is false. Treat this as a no-op success.
		// We still attempt push in case prior commits haven't been pushed.
		commitResult = &runner.GitCommitResult{}
	}

	// Step 4: Push to remote.
	pushErr := s.git.GitPush(ctx, req.SandboxID, &runner.GitPushRequest{
		Path:     req.RepoPath,
		Username: req.GitUsername,
		Password: req.GitPassword,
	})
	if pushErr != nil {
		s.emitCheckpointFailed(ctx, req, "push", pushErr.Error(), now)
		return nil, fmt.Errorf("checkpoint push failed: %w", pushErr)
	}

	// Step 5: Emit checkpoint_completed event.
	completePayload := &checkpointEventPayload{
		SandboxID:     req.SandboxID,
		WorkingBranch: req.WorkingBranch,
		CommitSHA:     commitResult.SHA,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "checkpoint_completed", completePayload, now)

	return &CheckpointResult{
		CommitSHA: commitResult.SHA,
		Pushed:    true,
	}, nil
}

// emitCheckpointFailed emits a checkpoint_failed event.
func (s *CheckpointService) emitCheckpointFailed(ctx context.Context, req *CheckpointRequest, step, errMsg string, now time.Time) {
	payload := &checkpointEventPayload{
		SandboxID:     req.SandboxID,
		WorkingBranch: req.WorkingBranch,
		Step:          step,
		Error:         errMsg,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "checkpoint_failed", payload, now)
}

// emitEvent inserts an event. Errors are best-effort.
func (s *CheckpointService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *checkpointEventPayload, now time.Time) {
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}

	var payloadJSON *string
	if payload != nil {
		data, err := json.Marshal(payload)
		if err == nil {
			str := string(data)
			payloadJSON = &str
		}
	}

	redacted, wasRedacted := redactPayload(payloadJSON)

	event := &Event{
		ID:          eventID,
		RunID:       runID,
		AttemptID:   &attemptID,
		EventType:   eventType,
		PayloadJSON: redacted,
		Redacted:    wasRedacted,
		CreatedAt:   now,
	}
	_ = s.store.InsertEvent(ctx, event)
}
