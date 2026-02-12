package cloud

import (
	"context"
	"fmt"
	"time"
)

// SubmitRequest contains the fields required to create a new cloud run.
type SubmitRequest struct {
	Repo          string       `json:"repo"`
	BaseBranch    string       `json:"base_branch"`
	WorkflowKind  WorkflowKind `json:"workflow_kind"`
	Engine        string       `json:"engine"`
	AuthProfileID string       `json:"auth_profile_id"`
	ScopeRef      string       `json:"scope_ref"`
}

// Validate checks that all required fields are set.
func (r *SubmitRequest) Validate() error {
	if r.Repo == "" {
		return fmt.Errorf("repo must not be empty")
	}
	if r.BaseBranch == "" {
		return fmt.Errorf("base_branch must not be empty")
	}
	if !r.WorkflowKind.IsValid() {
		return fmt.Errorf("workflow_kind %q is not a valid workflow kind", r.WorkflowKind)
	}
	if r.Engine == "" {
		return fmt.Errorf("engine must not be empty")
	}
	if r.AuthProfileID == "" {
		return fmt.Errorf("auth_profile_id must not be empty")
	}
	if r.ScopeRef == "" {
		return fmt.Errorf("scope_ref must not be empty")
	}
	return nil
}

// ProviderPolicy defines allow/deny lists for provider-based access control.
// If AllowList is non-empty, only listed providers are permitted.
// If DenyList is non-empty, listed providers are rejected.
// AllowList is evaluated before DenyList.
type ProviderPolicy struct {
	AllowList []string
	DenyList  []string
}

// IsAllowed returns true if the provider passes the allow/deny policy.
func (p *ProviderPolicy) IsAllowed(provider string) bool {
	if len(p.AllowList) > 0 {
		for _, a := range p.AllowList {
			if a == provider {
				return true
			}
		}
		return false
	}
	for _, d := range p.DenyList {
		if d == provider {
			return false
		}
	}
	return true
}

// EngineProviderMap defines which engines are compatible with which providers.
// The key is the engine name and the value is the set of compatible providers.
// An empty map means all engine/provider combinations are allowed.
type EngineProviderMap map[string]map[string]bool

// IsCompatible returns true if the engine/provider combination is allowed.
// If no mapping exists for the engine, all providers are considered compatible.
func (m EngineProviderMap) IsCompatible(engine, provider string) bool {
	if len(m) == 0 {
		return true
	}
	providers, ok := m[engine]
	if !ok {
		return true
	}
	return providers[provider]
}

// SubmitConfig holds configuration for the submit service.
type SubmitConfig struct {
	// DefaultMaxAttempts is the max retry attempts for new runs.
	DefaultMaxAttempts int
	// DefaultTimeout is the default run deadline duration from submission.
	DefaultTimeout time.Duration
	// ProviderPolicy is the allow/deny policy for providers.
	ProviderPolicy ProviderPolicy
	// EngineProviders maps engines to their compatible providers.
	EngineProviders EngineProviderMap
	// IDFunc generates unique run IDs. If nil, callers must set the ID.
	IDFunc func() string
}

// SubmitService validates and enqueues new cloud runs.
type SubmitService struct {
	store  Store
	config SubmitConfig
}

// submitAtomicStore is an optional Store extension for atomically persisting
// a run and its initial input snapshot in one transaction.
type submitAtomicStore interface {
	SubmitRunWithInputSnapshot(ctx context.Context, run *Run, snapshot *RunStateSnapshot) error
}

// NewSubmitService creates a new SubmitService with the given store and config.
func NewSubmitService(store Store, config SubmitConfig) *SubmitService {
	if config.DefaultMaxAttempts < 1 {
		config.DefaultMaxAttempts = 3
	}
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 1 * time.Hour
	}
	return &SubmitService{
		store:  store,
		config: config,
	}
}

// Submit validates a request, checks auth profile status and engine/provider
// compatibility, applies provider policy, and enqueues a new run.
func (s *SubmitService) Submit(ctx context.Context, req *SubmitRequest) (*Run, error) {
	run, err := s.prepareRun(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.store.EnqueueRun(ctx, run); err != nil {
		return nil, fmt.Errorf("failed to enqueue run: %w", err)
	}

	return run, nil
}

// BundlePayload contains the bundle content and manifest for submit-with-bundle.
type BundlePayload struct {
	Manifest BundleManifest `json:"manifest"`
	Content  []byte         `json:"content"`
}

// SubmitWithBundle validates a request and bundle, enqueues a run, stores the
// bundle as an input snapshot (kind=input, version=1), and sets the run's
// input_snapshot_id and latest_snapshot_id to the stored snapshot.
func (s *SubmitService) SubmitWithBundle(ctx context.Context, req *SubmitRequest, bundle *BundlePayload) (*Run, error) {
	// 1. Validate the bundle manifest.
	if bundle == nil {
		return nil, fmt.Errorf("bundle must not be nil")
	}
	if err := bundle.Manifest.Validate(); err != nil {
		return nil, fmt.Errorf("bundle validation failed: %w", err)
	}

	// 2. Verify the manifest hash matches recomputed hash.
	if err := bundle.Manifest.VerifyHash(); err != nil {
		return nil, ErrBundleHashMismatch
	}

	// 3. Build the run (validates request, auth profile, policy, etc.).
	run, err := s.prepareRun(ctx, req)
	if err != nil {
		return nil, err
	}

	// 4. Generate snapshot ID.
	snapshotID := ""
	if s.config.IDFunc != nil {
		snapshotID = s.config.IDFunc()
	}

	// 5. Build the input snapshot.
	now := time.Now().UTC().Truncate(time.Second)
	snapshot := &RunStateSnapshot{
		ID:              snapshotID,
		RunID:           run.ID,
		SnapshotKind:    SnapshotKindInput,
		Version:         1,
		SHA256:          bundle.Manifest.SHA256,
		SizeBytes:       int64(len(bundle.Content)),
		ContentEncoding: "application/gzip",
		ContentBlob:     bundle.Content,
		CreatedAt:       now,
	}

	// 6. Prefer an atomic write path when supported by the store adapter.
	if atomicStore, ok := s.store.(submitAtomicStore); ok {
		if err := atomicStore.SubmitRunWithInputSnapshot(ctx, run, snapshot); err != nil {
			return nil, fmt.Errorf("failed to submit run with input snapshot: %w", err)
		}
	} else {
		// Fallback path for test/memory stores that do not expose a transaction API.
		if err := s.store.EnqueueRun(ctx, run); err != nil {
			return nil, fmt.Errorf("failed to enqueue run: %w", err)
		}

		if err := s.store.PutSnapshot(ctx, snapshot); err != nil {
			// Best-effort compensation: prevent the orphaned queued run from executing.
			_ = s.store.TransitionRun(ctx, run.ID, RunStatusQueued, RunStatusFailed)
			return nil, fmt.Errorf("failed to store input snapshot: %w", err)
		}

		if err := s.store.UpdateRunSnapshotRefs(ctx, run.ID, &snapshot.ID, &snapshot.ID, 1); err != nil {
			// Best-effort compensation: run exists without valid refs; do not leave it queued.
			_ = s.store.TransitionRun(ctx, run.ID, RunStatusQueued, RunStatusFailed)
			return nil, fmt.Errorf("failed to update run snapshot refs: %w", err)
		}
	}

	run.InputSnapshotID = &snapshot.ID
	run.LatestSnapshotID = &snapshot.ID
	run.LatestSnapshotVersion = 1

	return run, nil
}

// prepareRun validates a submit request, checks auth/profile policy constraints,
// and constructs a queued run record without persisting it.
func (s *SubmitService) prepareRun(ctx context.Context, req *SubmitRequest) (*Run, error) {
	// 1. Validate required fields.
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// 2. Fetch and validate auth profile.
	profile, err := s.store.GetAuthProfile(ctx, req.AuthProfileID)
	if err != nil {
		if IsNotFound(err) {
			return nil, fmt.Errorf("auth profile %q not found", req.AuthProfileID)
		}
		return nil, fmt.Errorf("failed to get auth profile: %w", err)
	}

	if profile.Status != AuthProfileStatusLinked {
		return nil, fmt.Errorf("auth profile %q is not linked (status: %s)", req.AuthProfileID, profile.Status)
	}

	// 3. Check engine/provider compatibility.
	if !s.config.EngineProviders.IsCompatible(req.Engine, profile.Provider) {
		return nil, fmt.Errorf("engine %q is not compatible with provider %q", req.Engine, profile.Provider)
	}

	// 4. Apply provider allow/deny policy.
	if !s.config.ProviderPolicy.IsAllowed(profile.Provider) {
		return nil, fmt.Errorf("provider %q is not allowed by policy", profile.Provider)
	}

	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(s.config.DefaultTimeout)

	runID := ""
	if s.config.IDFunc != nil {
		runID = s.config.IDFunc()
	}

	return &Run{
		ID:            runID,
		Repo:          req.Repo,
		BaseBranch:    req.BaseBranch,
		WorkflowKind:  req.WorkflowKind,
		Engine:        req.Engine,
		AuthProfileID: req.AuthProfileID,
		ScopeRef:      req.ScopeRef,
		Status:        RunStatusQueued,
		AttemptCount:  0,
		MaxAttempts:   s.config.DefaultMaxAttempts,
		DeadlineAt:    &deadline,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}
