package cloud

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// submitMockStore is a test store for submit service tests.
type submitMockStore struct {
	mockStore
	profiles map[string]*AuthProfile
	runs     []*Run
	enqErr   error
}

func newSubmitMockStore() *submitMockStore {
	return &submitMockStore{
		profiles: make(map[string]*AuthProfile),
	}
}

func (s *submitMockStore) GetAuthProfile(_ context.Context, profileID string) (*AuthProfile, error) {
	p, ok := s.profiles[profileID]
	if !ok {
		return nil, ErrNotFound
	}
	return p, nil
}

func (s *submitMockStore) EnqueueRun(_ context.Context, run *Run) error {
	if s.enqErr != nil {
		return s.enqErr
	}
	s.runs = append(s.runs, run)
	return nil
}

func linkedProfile(id, provider string) *AuthProfile {
	return &AuthProfile{
		ID:                id,
		OwnerID:           "owner-1",
		Provider:          provider,
		Mode:              "session",
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
}

func validSubmitRequest() *SubmitRequest {
	return &SubmitRequest{
		Repo:          "org/repo",
		BaseBranch:    "main",
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
	}
}

func TestSubmitRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *SubmitRequest)
		wantErr string
	}{
		{
			name:   "valid request",
			modify: func(r *SubmitRequest) {},
		},
		{
			name:    "missing repo",
			modify:  func(r *SubmitRequest) { r.Repo = "" },
			wantErr: "repo must not be empty",
		},
		{
			name:    "missing base_branch",
			modify:  func(r *SubmitRequest) { r.BaseBranch = "" },
			wantErr: "base_branch must not be empty",
		},
		{
			name:    "missing engine",
			modify:  func(r *SubmitRequest) { r.Engine = "" },
			wantErr: "engine must not be empty",
		},
		{
			name:    "missing auth_profile_id",
			modify:  func(r *SubmitRequest) { r.AuthProfileID = "" },
			wantErr: "auth_profile_id must not be empty",
		},
		{
			name:    "missing scope_ref",
			modify:  func(r *SubmitRequest) { r.ScopeRef = "" },
			wantErr: "scope_ref must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validSubmitRequest()
			tt.modify(r)
			err := r.Validate()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if got := err.Error(); got != tt.wantErr {
					t.Errorf("error = %q, want %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestProviderPolicyIsAllowed(t *testing.T) {
	tests := []struct {
		name     string
		policy   ProviderPolicy
		provider string
		want     bool
	}{
		{
			name:     "empty policy allows all",
			policy:   ProviderPolicy{},
			provider: "anthropic",
			want:     true,
		},
		{
			name:     "allowlist permits listed provider",
			policy:   ProviderPolicy{AllowList: []string{"anthropic", "openai"}},
			provider: "anthropic",
			want:     true,
		},
		{
			name:     "allowlist rejects unlisted provider",
			policy:   ProviderPolicy{AllowList: []string{"anthropic"}},
			provider: "openai",
			want:     false,
		},
		{
			name:     "denylist blocks listed provider",
			policy:   ProviderPolicy{DenyList: []string{"blocked-provider"}},
			provider: "blocked-provider",
			want:     false,
		},
		{
			name:     "denylist allows unlisted provider",
			policy:   ProviderPolicy{DenyList: []string{"blocked-provider"}},
			provider: "anthropic",
			want:     true,
		},
		{
			name:     "allowlist takes precedence over denylist",
			policy:   ProviderPolicy{AllowList: []string{"anthropic"}, DenyList: []string{"anthropic"}},
			provider: "anthropic",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.IsAllowed(tt.provider)
			if got != tt.want {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}

func TestEngineProviderMapIsCompatible(t *testing.T) {
	tests := []struct {
		name     string
		m        EngineProviderMap
		engine   string
		provider string
		want     bool
	}{
		{
			name:     "nil map allows all",
			m:        nil,
			engine:   "claude",
			provider: "anthropic",
			want:     true,
		},
		{
			name:     "empty map allows all",
			m:        EngineProviderMap{},
			engine:   "claude",
			provider: "anthropic",
			want:     true,
		},
		{
			name:     "unmapped engine allows all providers",
			m:        EngineProviderMap{"codex": {"openai": true}},
			engine:   "claude",
			provider: "anthropic",
			want:     true,
		},
		{
			name:     "mapped engine with compatible provider",
			m:        EngineProviderMap{"claude": {"anthropic": true}},
			engine:   "claude",
			provider: "anthropic",
			want:     true,
		},
		{
			name:     "mapped engine with incompatible provider",
			m:        EngineProviderMap{"claude": {"anthropic": true}},
			engine:   "claude",
			provider: "openai",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.m.IsCompatible(tt.engine, tt.provider)
			if got != tt.want {
				t.Errorf("IsCompatible(%q, %q) = %v, want %v", tt.engine, tt.provider, got, tt.want)
			}
		})
	}
}

func TestSubmitService(t *testing.T) {
	idSeq := 0
	idFunc := func() string {
		idSeq++
		return fmt.Sprintf("run-%d", idSeq)
	}

	tests := []struct {
		name      string
		setup     func(s *submitMockStore)
		config    func(c *SubmitConfig)
		modify    func(r *SubmitRequest)
		wantErr   string
		checkRun  func(t *testing.T, run *Run)
	}{
		{
			name: "successful submit",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			checkRun: func(t *testing.T, run *Run) {
				t.Helper()
				if run.Status != RunStatusQueued {
					t.Errorf("status = %q, want %q", run.Status, RunStatusQueued)
				}
				if run.Repo != "org/repo" {
					t.Errorf("repo = %q, want %q", run.Repo, "org/repo")
				}
				if run.MaxAttempts != 3 {
					t.Errorf("max_attempts = %d, want 3", run.MaxAttempts)
				}
				if run.DeadlineAt == nil {
					t.Error("deadline_at should be set")
				}
				if run.ID == "" {
					t.Error("id should be set by IDFunc")
				}
			},
		},
		{
			name:    "missing required field",
			setup:   func(s *submitMockStore) {},
			modify:  func(r *SubmitRequest) { r.Repo = "" },
			wantErr: "validation failed: repo must not be empty",
		},
		{
			name:    "auth profile not found",
			setup:   func(s *submitMockStore) {},
			wantErr: `auth profile "profile-1" not found`,
		},
		{
			name: "auth profile not linked - pending_link",
			setup: func(s *submitMockStore) {
				p := linkedProfile("profile-1", "anthropic")
				p.Status = AuthProfileStatusPendingLink
				s.profiles["profile-1"] = p
			},
			wantErr: `auth profile "profile-1" is not linked (status: pending_link)`,
		},
		{
			name: "auth profile not linked - invalid",
			setup: func(s *submitMockStore) {
				p := linkedProfile("profile-1", "anthropic")
				p.Status = AuthProfileStatusInvalid
				s.profiles["profile-1"] = p
			},
			wantErr: `auth profile "profile-1" is not linked (status: invalid)`,
		},
		{
			name: "auth profile not linked - revoked",
			setup: func(s *submitMockStore) {
				p := linkedProfile("profile-1", "anthropic")
				p.Status = AuthProfileStatusRevoked
				s.profiles["profile-1"] = p
			},
			wantErr: `auth profile "profile-1" is not linked (status: revoked)`,
		},
		{
			name: "engine provider mismatch",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "openai")
			},
			config: func(c *SubmitConfig) {
				c.EngineProviders = EngineProviderMap{
					"claude": {"anthropic": true},
				}
			},
			wantErr: `engine "claude" is not compatible with provider "openai"`,
		},
		{
			name: "provider denied by policy",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "blocked-provider")
			},
			config: func(c *SubmitConfig) {
				c.ProviderPolicy = ProviderPolicy{
					DenyList: []string{"blocked-provider"},
				}
			},
			wantErr: `provider "blocked-provider" is not allowed by policy`,
		},
		{
			name: "provider not in allowlist",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			config: func(c *SubmitConfig) {
				c.ProviderPolicy = ProviderPolicy{
					AllowList: []string{"openai"},
				}
			},
			wantErr: `provider "anthropic" is not allowed by policy`,
		},
		{
			name: "enqueue store error",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
				s.enqErr = fmt.Errorf("database connection lost")
			},
			wantErr: "failed to enqueue run: database connection lost",
		},
		{
			name: "custom max attempts",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			config: func(c *SubmitConfig) {
				c.DefaultMaxAttempts = 5
			},
			checkRun: func(t *testing.T, run *Run) {
				t.Helper()
				if run.MaxAttempts != 5 {
					t.Errorf("max_attempts = %d, want 5", run.MaxAttempts)
				}
			},
		},
		{
			name: "custom timeout",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			config: func(c *SubmitConfig) {
				c.DefaultTimeout = 30 * time.Minute
			},
			checkRun: func(t *testing.T, run *Run) {
				t.Helper()
				if run.DeadlineAt == nil {
					t.Fatal("deadline_at should be set")
				}
				// Deadline should be ~30min from now, not 1h.
				deadline := *run.DeadlineAt
				delta := deadline.Sub(run.CreatedAt)
				if delta != 30*time.Minute {
					t.Errorf("deadline delta = %v, want 30m", delta)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idSeq = 0
			store := newSubmitMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			cfg := SubmitConfig{
				IDFunc: idFunc,
			}
			if tt.config != nil {
				tt.config(&cfg)
			}

			svc := NewSubmitService(store, cfg)

			req := validSubmitRequest()
			if tt.modify != nil {
				tt.modify(req)
			}

			run, err := svc.Submit(context.Background(), req)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if got := err.Error(); got != tt.wantErr {
					t.Errorf("error = %q, want %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if run == nil {
				t.Fatal("expected non-nil run")
			}
			if tt.checkRun != nil {
				tt.checkRun(t, run)
			}
		})
	}
}

func TestNewSubmitServiceDefaults(t *testing.T) {
	store := newSubmitMockStore()

	svc := NewSubmitService(store, SubmitConfig{})
	if svc.config.DefaultMaxAttempts != 3 {
		t.Errorf("DefaultMaxAttempts = %d, want 3", svc.config.DefaultMaxAttempts)
	}
	if svc.config.DefaultTimeout != 1*time.Hour {
		t.Errorf("DefaultTimeout = %v, want 1h", svc.config.DefaultTimeout)
	}
}
