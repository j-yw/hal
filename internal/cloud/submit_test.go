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
	profiles  map[string]*AuthProfile
	runs      []*Run
	snapshots []*RunStateSnapshot
	snapRefs  []updateRunSnapshotRefsCall
	enqErr    error
	snapErr   error
	refsErr   error
}

type updateRunSnapshotRefsCall struct {
	runID                 string
	inputSnapshotID       *string
	latestSnapshotID      *string
	latestSnapshotVersion int
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

func (s *submitMockStore) PutSnapshot(_ context.Context, snap *RunStateSnapshot) error {
	if s.snapErr != nil {
		return s.snapErr
	}
	s.snapshots = append(s.snapshots, snap)
	return nil
}

func (s *submitMockStore) UpdateRunSnapshotRefs(_ context.Context, runID string, inputSnapshotID, latestSnapshotID *string, latestSnapshotVersion int) error {
	if s.refsErr != nil {
		return s.refsErr
	}
	s.snapRefs = append(s.snapRefs, updateRunSnapshotRefsCall{
		runID:                 runID,
		inputSnapshotID:       inputSnapshotID,
		latestSnapshotID:      latestSnapshotID,
		latestSnapshotVersion: latestSnapshotVersion,
	})
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
		WorkflowKind:  WorkflowKindRun,
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
			name:    "empty workflow_kind",
			modify:  func(r *SubmitRequest) { r.WorkflowKind = "" },
			wantErr: `workflow_kind "" is not a valid workflow kind`,
		},
		{
			name:    "invalid workflow_kind",
			modify:  func(r *SubmitRequest) { r.WorkflowKind = "deploy" },
			wantErr: `workflow_kind "deploy" is not a valid workflow kind`,
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
		name     string
		setup    func(s *submitMockStore)
		config   func(c *SubmitConfig)
		modify   func(r *SubmitRequest)
		wantErr  string
		checkRun func(t *testing.T, run *Run)
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
				if run.WorkflowKind != WorkflowKindRun {
					t.Errorf("workflow_kind = %q, want %q", run.WorkflowKind, WorkflowKindRun)
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

func validBundlePayload() *BundlePayload {
	content := []byte("compressed-bundle-content")
	records := []BundleManifestRecord{
		NewBundleManifestRecord(".hal/prd.json", []byte(`{"project":"test"}`)),
		NewBundleManifestRecord(".hal/progress.txt", []byte("## progress")),
	}
	manifest := NewBundleManifest(records)
	return &BundlePayload{
		Manifest: manifest,
		Content:  content,
	}
}

func TestSubmitWithBundle(t *testing.T) {
	idSeq := 0
	idFunc := func() string {
		idSeq++
		return fmt.Sprintf("id-%d", idSeq)
	}

	tests := []struct {
		name     string
		setup    func(s *submitMockStore)
		config   func(c *SubmitConfig)
		modify   func(r *SubmitRequest)
		bundle   func() *BundlePayload
		wantErr  string
		isErr    func(error) bool
		checkRun func(t *testing.T, run *Run, store *submitMockStore)
	}{
		{
			name: "successful submit with bundle",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			bundle: validBundlePayload,
			checkRun: func(t *testing.T, run *Run, store *submitMockStore) {
				t.Helper()
				if run.Status != RunStatusQueued {
					t.Errorf("status = %q, want %q", run.Status, RunStatusQueued)
				}
				// Run should have snapshot refs set.
				if run.InputSnapshotID == nil {
					t.Fatal("InputSnapshotID should be set")
				}
				if run.LatestSnapshotID == nil {
					t.Fatal("LatestSnapshotID should be set")
				}
				if *run.InputSnapshotID != *run.LatestSnapshotID {
					t.Errorf("InputSnapshotID=%q != LatestSnapshotID=%q", *run.InputSnapshotID, *run.LatestSnapshotID)
				}
				if run.LatestSnapshotVersion != 1 {
					t.Errorf("LatestSnapshotVersion = %d, want 1", run.LatestSnapshotVersion)
				}
				// Snapshot should be stored.
				if len(store.snapshots) != 1 {
					t.Fatalf("snapshots count = %d, want 1", len(store.snapshots))
				}
				snap := store.snapshots[0]
				if snap.SnapshotKind != SnapshotKindInput {
					t.Errorf("snapshot_kind = %q, want %q", snap.SnapshotKind, SnapshotKindInput)
				}
				if snap.Version != 1 {
					t.Errorf("snapshot version = %d, want 1", snap.Version)
				}
				if snap.RunID != run.ID {
					t.Errorf("snapshot run_id = %q, want %q", snap.RunID, run.ID)
				}
				if snap.ContentEncoding != "application/gzip" {
					t.Errorf("content_encoding = %q, want application/gzip", snap.ContentEncoding)
				}
				// Refs should be updated.
				if len(store.snapRefs) != 1 {
					t.Fatalf("snapRefs count = %d, want 1", len(store.snapRefs))
				}
				ref := store.snapRefs[0]
				if ref.runID != run.ID {
					t.Errorf("ref runID = %q, want %q", ref.runID, run.ID)
				}
				if ref.latestSnapshotVersion != 1 {
					t.Errorf("ref latestSnapshotVersion = %d, want 1", ref.latestSnapshotVersion)
				}
			},
		},
		{
			name:    "nil bundle",
			setup:   func(s *submitMockStore) {},
			bundle:  func() *BundlePayload { return nil },
			wantErr: "bundle must not be nil",
		},
		{
			name:  "manifest validation fails - empty sha256",
			setup: func(s *submitMockStore) {},
			bundle: func() *BundlePayload {
				b := validBundlePayload()
				b.Manifest.SHA256 = ""
				return b
			},
			wantErr: "bundle validation failed: bundle_manifest.sha256 must not be empty",
		},
		{
			name:  "manifest validation fails - empty records",
			setup: func(s *submitMockStore) {},
			bundle: func() *BundlePayload {
				b := validBundlePayload()
				b.Manifest.Records = nil
				return b
			},
			wantErr: "bundle validation failed: bundle_manifest.records must not be empty",
		},
		{
			name:  "manifest hash mismatch",
			setup: func(s *submitMockStore) {},
			bundle: func() *BundlePayload {
				b := validBundlePayload()
				b.Manifest.SHA256 = "badhash0000000000000000000000000000000000000000000000000000000000"
				return b
			},
			wantErr: "bundle_hash_mismatch",
			isErr:   IsBundleHashMismatch,
		},
		{
			name: "submit request validation fails with bundle",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			modify:  func(r *SubmitRequest) { r.Repo = "" },
			bundle:  validBundlePayload,
			wantErr: "validation failed: repo must not be empty",
		},
		{
			name: "put snapshot store error",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
				s.snapErr = fmt.Errorf("snapshot write failed")
			},
			bundle:  validBundlePayload,
			wantErr: "failed to store input snapshot: snapshot write failed",
		},
		{
			name: "update snapshot refs store error",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
				s.refsErr = fmt.Errorf("refs update failed")
			},
			bundle:  validBundlePayload,
			wantErr: "failed to update run snapshot refs: refs update failed",
		},
		{
			name: "snapshot stores manifest sha256",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			bundle: validBundlePayload,
			checkRun: func(t *testing.T, run *Run, store *submitMockStore) {
				t.Helper()
				if len(store.snapshots) != 1 {
					t.Fatalf("snapshots count = %d, want 1", len(store.snapshots))
				}
				snap := store.snapshots[0]
				bundle := validBundlePayload()
				if snap.SHA256 != bundle.Manifest.SHA256 {
					t.Errorf("snapshot sha256 = %q, want %q", snap.SHA256, bundle.Manifest.SHA256)
				}
			},
		},
		{
			name: "snapshot stores bundle content",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			bundle: validBundlePayload,
			checkRun: func(t *testing.T, run *Run, store *submitMockStore) {
				t.Helper()
				if len(store.snapshots) != 1 {
					t.Fatalf("snapshots count = %d, want 1", len(store.snapshots))
				}
				snap := store.snapshots[0]
				bundle := validBundlePayload()
				if string(snap.ContentBlob) != string(bundle.Content) {
					t.Errorf("snapshot content = %q, want %q", snap.ContentBlob, bundle.Content)
				}
				if snap.SizeBytes != int64(len(bundle.Content)) {
					t.Errorf("snapshot size_bytes = %d, want %d", snap.SizeBytes, len(bundle.Content))
				}
			},
		},
		{
			name: "snapshot and refs use IDFunc",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			bundle: validBundlePayload,
			checkRun: func(t *testing.T, run *Run, store *submitMockStore) {
				t.Helper()
				// IDFunc generates sequential IDs: id-1 for run, id-2 for snapshot.
				if run.ID != "id-1" {
					t.Errorf("run.ID = %q, want id-1", run.ID)
				}
				if len(store.snapshots) != 1 {
					t.Fatalf("snapshots count = %d, want 1", len(store.snapshots))
				}
				if store.snapshots[0].ID != "id-2" {
					t.Errorf("snapshot.ID = %q, want id-2", store.snapshots[0].ID)
				}
			},
		},
		{
			name: "input and latest snapshot IDs match",
			setup: func(s *submitMockStore) {
				s.profiles["profile-1"] = linkedProfile("profile-1", "anthropic")
			},
			bundle: validBundlePayload,
			checkRun: func(t *testing.T, run *Run, store *submitMockStore) {
				t.Helper()
				if len(store.snapRefs) != 1 {
					t.Fatalf("snapRefs count = %d, want 1", len(store.snapRefs))
				}
				ref := store.snapRefs[0]
				if ref.inputSnapshotID == nil || ref.latestSnapshotID == nil {
					t.Fatal("snapshot IDs should not be nil")
				}
				if *ref.inputSnapshotID != *ref.latestSnapshotID {
					t.Errorf("inputSnapshotID=%q != latestSnapshotID=%q", *ref.inputSnapshotID, *ref.latestSnapshotID)
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

			var bundle *BundlePayload
			if tt.bundle != nil {
				bundle = tt.bundle()
			}

			run, err := svc.SubmitWithBundle(context.Background(), req, bundle)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if got := err.Error(); got != tt.wantErr {
					t.Errorf("error = %q, want %q", got, tt.wantErr)
				}
				if tt.isErr != nil && !tt.isErr(err) {
					t.Errorf("error type check failed for %q", err)
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
				tt.checkRun(t, run, store)
			}
		})
	}
}
