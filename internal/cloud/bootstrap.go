package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// BootstrapConfig holds configuration for the bootstrap service.
type BootstrapConfig struct {
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// BootstrapService manages deterministic environment setup before Hal
// execution. It clones or fetches the repository, checks out the target
// branch, and runs hal init inside the sandbox.
//
// When constructed with NewBootstrapServiceWithGit and the request has
// WorkingBranch + AttemptNumber > 1, Bootstrap will attempt to clone the
// working branch (resume path). If the working branch does not exist on
// the remote, it falls back to the base branch transparently.
type BootstrapService struct {
	store  Store
	runner runner.Runner
	git    runner.GitOps // optional; enables resume via Daytona Git SDK
	config BootstrapConfig
}

// NewBootstrapService creates a new BootstrapService with the given store,
// runner, and config. This constructor does not enable the resume path —
// use NewBootstrapServiceWithGit to enable working-branch resume.
func NewBootstrapService(store Store, r runner.Runner, config BootstrapConfig) *BootstrapService {
	return &BootstrapService{
		store:  store,
		runner: r,
		config: config,
	}
}

// NewBootstrapServiceWithGit creates a BootstrapService with Daytona Git
// SDK support, enabling the working-branch resume path for retry attempts.
func NewBootstrapServiceWithGit(store Store, r runner.Runner, git runner.GitOps, config BootstrapConfig) *BootstrapService {
	return &BootstrapService{
		store:  store,
		runner: r,
		git:    git,
		config: config,
	}
}

// BootstrapRequest contains the parameters for bootstrapping a sandbox.
type BootstrapRequest struct {
	// Repo is the repository URL to clone (e.g., "https://github.com/org/repo.git").
	Repo string
	// Branch is the target branch to checkout after cloning.
	Branch string
	// SandboxID is the sandbox to bootstrap.
	SandboxID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// RunID is the current run (for event correlation).
	RunID string

	// --- Resume fields (zero values preserve original behavior) ---

	// WorkingBranch is the deterministic branch for this run
	// (e.g., "hal/cloud/run-abc"). When non-empty and AttemptNumber > 1,
	// Bootstrap tries to clone the working branch first (resume path).
	// On first attempt or when empty, the base Branch is cloned.
	WorkingBranch string
	// AttemptNumber is the current attempt number. When > 1 and
	// WorkingBranch is set, the resume path is attempted.
	AttemptNumber int
	// GitUsername is the HTTPS auth username for clone (optional).
	GitUsername string
	// GitPassword is the HTTPS auth password/token for clone (optional).
	GitPassword string
}

// Validate checks required fields on BootstrapRequest.
func (r *BootstrapRequest) Validate() error {
	if r.Repo == "" {
		return fmt.Errorf("repo must not be empty")
	}
	if r.Branch == "" {
		return fmt.Errorf("branch must not be empty")
	}
	if r.SandboxID == "" {
		return fmt.Errorf("sandboxID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	return nil
}

// bootstrapEventPayload is the JSON payload for bootstrap lifecycle events.
type bootstrapEventPayload struct {
	SandboxID     string `json:"sandbox_id"`
	Repo          string `json:"repo,omitempty"`
	Branch        string `json:"branch,omitempty"`
	WorkingBranch string `json:"working_branch,omitempty"`
	Resumed       bool   `json:"resumed,omitempty"`
	Step          string `json:"step,omitempty"`
	Error         string `json:"error,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
}

// Bootstrap clones or fetches the repository, checks out the target branch,
// and runs hal init inside the sandbox. On failure, a bootstrap_failed event
// is emitted and the error is returned. On success, bootstrap_completed is
// emitted.
//
// Resume behavior (requires NewBootstrapServiceWithGit):
// When WorkingBranch is set and AttemptNumber > 1, Bootstrap uses the Daytona
// Git SDK to check whether the working branch exists on the remote. If it
// does, that branch is cloned instead of the base branch so the new attempt
// resumes from the last checkpoint. If the working branch does not exist,
// bootstrap falls back to the base branch and creates the working branch.
//
// On the first attempt (or when git is nil), the base branch is cloned and
// the working branch is created and checked out for future checkpoints.
func (s *BootstrapService) Bootstrap(ctx context.Context, req *BootstrapRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 1: Emit bootstrap_started event.
	startPayload := &bootstrapEventPayload{
		SandboxID:     req.SandboxID,
		Repo:          req.Repo,
		Branch:        req.Branch,
		WorkingBranch: req.WorkingBranch,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "bootstrap_started", startPayload, now)

	// Step 2: Determine clone strategy.
	cloneBranch := req.Branch
	resumed := false

	if s.git != nil && req.WorkingBranch != "" && req.AttemptNumber > 1 {
		// Resume path: try to clone the working branch from a prior checkpoint.
		if s.tryResumeClone(ctx, req, now) {
			resumed = true
			cloneBranch = req.WorkingBranch
		}
		// If tryResumeClone returned false, fall through to base branch clone.
	}

	if !resumed {
		// Fresh clone: base branch via Exec (preserves original behavior).
		if err := s.cloneViaExec(ctx, req, cloneBranch, now); err != nil {
			return err
		}

		// Create and checkout working branch if GitOps is available.
		if s.git != nil && req.WorkingBranch != "" {
			if err := s.createWorkingBranch(ctx, req, now); err != nil {
				return err
			}
		}
	}

	// Step 3: Run hal init (idempotent — safe on both fresh and resumed clones).
	initResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: "hal init",
		WorkDir: "/workspace",
	})
	if err != nil {
		s.emitBootstrapFailed(ctx, req, "init", err.Error(), nil, now)
		return fmt.Errorf("bootstrap init failed: %w", err)
	}
	if initResult.ExitCode != 0 {
		output := initResult.Stderr
		if output == "" {
			output = initResult.Stdout
		}
		s.emitBootstrapFailed(ctx, req, "init", output, &initResult.ExitCode, now)
		return fmt.Errorf("bootstrap init failed: exit code %d: %s", initResult.ExitCode, output)
	}

	// Step 4: Emit bootstrap_completed event.
	completePayload := &bootstrapEventPayload{
		SandboxID:     req.SandboxID,
		Repo:          req.Repo,
		Branch:        cloneBranch,
		WorkingBranch: req.WorkingBranch,
		Resumed:       resumed,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "bootstrap_completed", completePayload, now)

	return nil
}

// tryResumeClone attempts to clone the working branch via the Daytona Git SDK.
// Returns true if the working branch was found and cloned successfully.
// Returns false if the branch doesn't exist or clone fails (caller falls back
// to the base branch).
func (s *BootstrapService) tryResumeClone(ctx context.Context, req *BootstrapRequest, now time.Time) bool {
	err := s.git.GitClone(ctx, req.SandboxID, &runner.GitCloneRequest{
		URL:      req.Repo,
		Path:     "/workspace",
		Branch:   req.WorkingBranch,
		Username: req.GitUsername,
		Password: req.GitPassword,
	})
	if err != nil {
		// Working branch doesn't exist on remote or clone failed.
		// This is expected on first retry when no checkpoint was pushed.
		// Fall back to base branch silently.
		return false
	}
	return true
}

// cloneViaExec clones using the original runner.Exec path (backward compatible).
func (s *BootstrapService) cloneViaExec(ctx context.Context, req *BootstrapRequest, branch string, now time.Time) error {
	cloneCmd := fmt.Sprintf("git clone --branch %s --single-branch %s /workspace", branch, req.Repo)
	cloneResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: cloneCmd,
	})
	if err != nil {
		s.emitBootstrapFailed(ctx, req, "clone", err.Error(), nil, now)
		return fmt.Errorf("bootstrap clone failed: %w", err)
	}
	if cloneResult.ExitCode != 0 {
		output := cloneResult.Stderr
		if output == "" {
			output = cloneResult.Stdout
		}
		s.emitBootstrapFailed(ctx, req, "clone", output, &cloneResult.ExitCode, now)
		return fmt.Errorf("bootstrap clone failed: exit code %d: %s", cloneResult.ExitCode, output)
	}
	return nil
}

// createWorkingBranch creates and checks out the working branch via GitOps.
func (s *BootstrapService) createWorkingBranch(ctx context.Context, req *BootstrapRequest, now time.Time) error {
	if err := s.git.GitCreateBranch(ctx, req.SandboxID, "/workspace", req.WorkingBranch); err != nil {
		s.emitBootstrapFailed(ctx, req, "create_branch", err.Error(), nil, now)
		return fmt.Errorf("bootstrap create branch failed: %w", err)
	}
	if err := s.git.GitCheckout(ctx, req.SandboxID, "/workspace", req.WorkingBranch); err != nil {
		s.emitBootstrapFailed(ctx, req, "checkout", err.Error(), nil, now)
		return fmt.Errorf("bootstrap checkout failed: %w", err)
	}
	return nil
}

// emitBootstrapFailed emits a bootstrap_failed event with error context.
func (s *BootstrapService) emitBootstrapFailed(ctx context.Context, req *BootstrapRequest, step, errMsg string, exitCode *int, now time.Time) {
	payload := &bootstrapEventPayload{
		SandboxID: req.SandboxID,
		Repo:      req.Repo,
		Branch:    req.Branch,
		Step:      step,
		Error:     errMsg,
		ExitCode:  exitCode,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "bootstrap_failed", payload, now)
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block bootstrap.
func (s *BootstrapService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *bootstrapEventPayload, now time.Time) {
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
