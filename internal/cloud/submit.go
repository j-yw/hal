package cloud

import (
	"context"
	"fmt"
	"time"
)

// SubmitRequest contains the fields required to create a new cloud run.
type SubmitRequest struct {
	Repo          string `json:"repo"`
	BaseBranch    string `json:"base_branch"`
	Engine        string `json:"engine"`
	AuthProfileID string `json:"auth_profile_id"`
	ScopeRef      string `json:"scope_ref"`
}

// Validate checks that all required fields are set.
func (r *SubmitRequest) Validate() error {
	if r.Repo == "" {
		return fmt.Errorf("repo must not be empty")
	}
	if r.BaseBranch == "" {
		return fmt.Errorf("base_branch must not be empty")
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

	// 5. Build and enqueue the run.
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(s.config.DefaultTimeout)

	runID := ""
	if s.config.IDFunc != nil {
		runID = s.config.IDFunc()
	}

	run := &Run{
		ID:            runID,
		Repo:          req.Repo,
		BaseBranch:    req.BaseBranch,
		Engine:        req.Engine,
		AuthProfileID: req.AuthProfileID,
		ScopeRef:      req.ScopeRef,
		Status:        RunStatusQueued,
		AttemptCount:  0,
		MaxAttempts:   s.config.DefaultMaxAttempts,
		DeadlineAt:    &deadline,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.store.EnqueueRun(ctx, run); err != nil {
		return nil, fmt.Errorf("failed to enqueue run: %w", err)
	}

	return run, nil
}
