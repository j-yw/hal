package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

// cloudMockStore is a minimal mock store for cloud CLI tests.
type cloudMockStore struct {
	profiles       map[string]*cloud.AuthProfile
	runs           []*cloud.Run
	runsByID       map[string]*cloud.Run
	activeAttempts map[string]*cloud.Attempt
	events         map[string][]*cloud.Event
	snapshots      map[string]*cloud.RunStateSnapshot // runID → latest snapshot
	locks          map[string]*cloud.AuthProfileLock  // authProfileID → active lock
	enqErr         error
	listRunsErr    error
	getRErr        error
	getAttemptErr  error
	listEventsErr  error
	setCancelErr   error
	getSnapshotErr error
	getAuthLockErr error
}

func newCloudMockStore() *cloudMockStore {
	return &cloudMockStore{
		profiles:       make(map[string]*cloud.AuthProfile),
		runsByID:       make(map[string]*cloud.Run),
		activeAttempts: make(map[string]*cloud.Attempt),
		events:         make(map[string][]*cloud.Event),
		snapshots:      make(map[string]*cloud.RunStateSnapshot),
		locks:          make(map[string]*cloud.AuthProfileLock),
	}
}

func (s *cloudMockStore) EnqueueRun(_ context.Context, run *cloud.Run) error {
	if s.enqErr != nil {
		return s.enqErr
	}
	s.runs = append(s.runs, run)
	return nil
}

func (s *cloudMockStore) CreateAuthProfile(_ context.Context, profile *cloud.AuthProfile) error {
	if _, ok := s.profiles[profile.ID]; ok {
		return cloud.ErrDuplicateKey
	}
	s.profiles[profile.ID] = profile
	return nil
}

func (s *cloudMockStore) GetAuthProfile(_ context.Context, id string) (*cloud.AuthProfile, error) {
	p, ok := s.profiles[id]
	if !ok {
		return nil, cloud.ErrNotFound
	}
	return p, nil
}

// Remaining Store interface methods — no-op stubs.
func (s *cloudMockStore) ClaimRun(_ context.Context, _ string) (*cloud.Run, error) { return nil, nil }
func (s *cloudMockStore) TransitionRun(_ context.Context, _ string, _, _ cloud.RunStatus) error {
	return nil
}
func (s *cloudMockStore) GetRun(_ context.Context, id string) (*cloud.Run, error) {
	if s.getRErr != nil {
		return nil, s.getRErr
	}
	r, ok := s.runsByID[id]
	if !ok {
		return nil, cloud.ErrNotFound
	}
	return r, nil
}
func (s *cloudMockStore) ListRuns(_ context.Context, limit int) ([]*cloud.Run, error) {
	if s.listRunsErr != nil {
		return nil, s.listRunsErr
	}
	runs := s.runs
	if limit > 0 && limit < len(runs) {
		runs = runs[:limit]
	}
	return runs, nil
}
func (s *cloudMockStore) ListOverdueRuns(_ context.Context, _ time.Time) ([]*cloud.Run, error) {
	return nil, nil
}
func (s *cloudMockStore) SetCancelIntent(_ context.Context, runID string) error {
	if s.setCancelErr != nil {
		return s.setCancelErr
	}
	r, ok := s.runsByID[runID]
	if !ok {
		return cloud.ErrNotFound
	}
	r.CancelRequested = true
	return nil
}
func (s *cloudMockStore) CreateAttempt(_ context.Context, _ *cloud.Attempt) error { return nil }
func (s *cloudMockStore) HeartbeatAttempt(_ context.Context, _ string, _, _ time.Time) error {
	return nil
}
func (s *cloudMockStore) TransitionAttempt(_ context.Context, _ string, _ cloud.AttemptStatus, _ time.Time, _, _ *string) error {
	return nil
}
func (s *cloudMockStore) UpdateAttemptSandboxID(_ context.Context, _, _ string) error { return nil }
func (s *cloudMockStore) ListStaleAttempts(_ context.Context, _ time.Time) ([]*cloud.Attempt, error) {
	return nil, nil
}
func (s *cloudMockStore) GetAttempt(_ context.Context, _ string) (*cloud.Attempt, error) {
	return nil, nil
}
func (s *cloudMockStore) GetActiveAttemptByRun(_ context.Context, runID string) (*cloud.Attempt, error) {
	if s.getAttemptErr != nil {
		return nil, s.getAttemptErr
	}
	a, ok := s.activeAttempts[runID]
	if !ok {
		return nil, cloud.ErrNotFound
	}
	return a, nil
}
func (s *cloudMockStore) InsertEvent(_ context.Context, _ *cloud.Event) error { return nil }
func (s *cloudMockStore) ListEvents(_ context.Context, runID string) ([]*cloud.Event, error) {
	if s.listEventsErr != nil {
		return nil, s.listEventsErr
	}
	return s.events[runID], nil
}
func (s *cloudMockStore) PutIdempotencyKey(_ context.Context, _ *cloud.IdempotencyKey) error {
	return nil
}
func (s *cloudMockStore) GetIdempotencyKey(_ context.Context, _ string) (*cloud.IdempotencyKey, error) {
	return nil, nil
}
func (s *cloudMockStore) UpdateAuthProfile(_ context.Context, profile *cloud.AuthProfile) error {
	if _, ok := s.profiles[profile.ID]; !ok {
		return cloud.ErrNotFound
	}
	s.profiles[profile.ID] = profile
	return nil
}
func (s *cloudMockStore) AcquireAuthLock(_ context.Context, _ *cloud.AuthProfileLock) error {
	return nil
}
func (s *cloudMockStore) RenewAuthLock(_ context.Context, _, _ string, _, _ time.Time) error {
	return nil
}
func (s *cloudMockStore) ReleaseAuthLock(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}
func (s *cloudMockStore) GetActiveAuthLock(_ context.Context, authProfileID string) (*cloud.AuthProfileLock, error) {
	if s.getAuthLockErr != nil {
		return nil, s.getAuthLockErr
	}
	lock, ok := s.locks[authProfileID]
	if !ok {
		return nil, cloud.ErrNotFound
	}
	return lock, nil
}
func (s *cloudMockStore) PutSnapshot(_ context.Context, _ *cloud.RunStateSnapshot) error { return nil }
func (s *cloudMockStore) GetSnapshot(_ context.Context, _ string) (*cloud.RunStateSnapshot, error) {
	return nil, nil
}
func (s *cloudMockStore) GetLatestSnapshot(_ context.Context, runID string) (*cloud.RunStateSnapshot, error) {
	if s.getSnapshotErr != nil {
		return nil, s.getSnapshotErr
	}
	snap, ok := s.snapshots[runID]
	if !ok {
		return nil, cloud.ErrNotFound
	}
	return snap, nil
}
func (s *cloudMockStore) UpdateRunSnapshotRefs(_ context.Context, _ string, _, _ *string, _ int) error {
	return nil
}

func linkedCloudProfile(id, provider string) *cloud.AuthProfile {
	return &cloud.AuthProfile{
		ID:                id,
		OwnerID:           "owner-1",
		Provider:          provider,
		Mode:              "session",
		Status:            cloud.AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
}

func TestCloudDefaultFactoriesIncludeSubmitConfig(t *testing.T) {
	if cloudSubmitStoreFactory == nil {
		t.Fatal("cloudSubmitStoreFactory should be initialized")
	}
	if cloudSubmitConfigFactory == nil {
		t.Fatal("cloudSubmitConfigFactory should be initialized")
	}
	if cloudRunStoreFactory == nil {
		t.Fatal("cloudRunStoreFactory should be initialized")
	}
	if cloudRunConfigFactory == nil {
		t.Fatal("cloudRunConfigFactory should be initialized")
	}

	submitCfg := cloudSubmitConfigFactory()
	if submitCfg.IDFunc == nil {
		t.Fatal("cloudSubmitConfigFactory must provide IDFunc")
	}
	submitID := submitCfg.IDFunc()
	if submitID == "" {
		t.Fatal("cloudSubmitConfigFactory IDFunc returned empty ID")
	}
	if !strings.HasPrefix(submitID, "run-") {
		t.Fatalf("submit ID = %q, want run- prefix", submitID)
	}

	runCfg := cloudRunConfigFactory()
	if runCfg.IDFunc == nil {
		t.Fatal("cloudRunConfigFactory must provide IDFunc")
	}
	runID := runCfg.IDFunc()
	if runID == "" {
		t.Fatal("cloudRunConfigFactory IDFunc returned empty ID")
	}
	if !strings.HasPrefix(runID, "run-") {
		t.Fatalf("run ID = %q, want run- prefix", runID)
	}
}

func TestRunCloudSubmit(t *testing.T) {
	tests := []struct {
		name       string
		repo       string
		base       string
		engine     string
		authProf   string
		scope      string
		jsonOutput bool
		store      func() *cloudMockStore
		config     func() cloud.SubmitConfig
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name:     "successful submit with human output",
			repo:     "org/repo",
			base:     "main",
			engine:   "claude",
			authProf: "profile-1",
			scope:    "prd-123",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{IDFunc: func() string { return "run-001" }}
			},
			wantOutput: []string{"Run submitted successfully", "run_id:", "run-001", "status:", "queued", "engine:", "claude", "auth_profile:", "profile-1", "submitted_at:"},
		},
		{
			name:       "successful submit with JSON output",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{IDFunc: func() string { return "run-002" }}
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.RunID != "run-002" {
					t.Errorf("run_id = %q, want %q", resp.RunID, "run-002")
				}
				if resp.Status != "queued" {
					t.Errorf("status = %q, want %q", resp.Status, "queued")
				}
				if resp.Engine != "claude" {
					t.Errorf("engine = %q, want %q", resp.Engine, "claude")
				}
				if resp.AuthProfile != "profile-1" {
					t.Errorf("auth_profile = %q, want %q", resp.AuthProfile, "profile-1")
				}
				if resp.SubmittedAt == "" {
					t.Error("submitted_at should not be empty")
				}
			},
		},
		{
			name:       "validation error missing repo in JSON",
			repo:       "",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "validation_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "validation_error")
				}
				if resp.Error == "" {
					t.Error("error message should not be empty")
				}
			},
		},
		{
			name:     "validation error missing repo in human output",
			repo:     "",
			base:     "main",
			engine:   "claude",
			authProf: "profile-1",
			scope:    "prd-123",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			wantErr: "submit failed",
		},
		{
			name:       "auth profile not found in JSON",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "missing-profile",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "not_found" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "not_found")
				}
			},
		},
		{
			name:       "auth profile not linked in JSON",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				p := linkedCloudProfile("profile-1", "anthropic")
				p.Status = cloud.AuthProfileStatusPendingLink
				s.profiles["profile-1"] = p
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "auth_profile_not_linked" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "auth_profile_not_linked")
				}
			},
		},
		{
			name:       "engine provider mismatch in JSON",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "openai")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{
					EngineProviders: cloud.EngineProviderMap{
						"claude": {"anthropic": true},
					},
				}
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "engine_provider_mismatch" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "engine_provider_mismatch")
				}
			},
		},
		{
			name:       "provider policy blocked in JSON",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{
					ProviderPolicy: cloud.ProviderPolicy{
						DenyList: []string{"anthropic"},
					},
				}
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "policy_blocked" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "policy_blocked")
				}
			},
		},
		{
			name:       "enqueue failure in JSON",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				s.enqErr = fmt.Errorf("db connection failed")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "store_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "store_error")
				}
			},
		},
		{
			name:       "nil store factory returns error",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store:      nil,
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:     "nil store factory in human output",
			repo:     "org/repo",
			base:     "main",
			engine:   "claude",
			authProf: "profile-1",
			scope:    "prd-123",
			store:    nil,
			wantErr:  "store not configured",
		},
		{
			name:       "store factory error in JSON",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return nil // signal store factory error
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:     "default output includes all required fields",
			repo:     "org/repo",
			base:     "develop",
			engine:   "codex",
			authProf: "prof-x",
			scope:    "scope-456",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-x"] = linkedCloudProfile("prof-x", "openai")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{IDFunc: func() string { return "run-xyz" }}
			},
			wantOutput: []string{"run-xyz", "queued", "codex", "prof-x", "submitted_at:"},
		},
		{
			name:       "JSON output includes all required fields",
			repo:       "org/repo",
			base:       "develop",
			engine:     "codex",
			authProf:   "prof-x",
			scope:      "scope-456",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["prof-x"] = linkedCloudProfile("prof-x", "openai")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{IDFunc: func() string { return "run-xyz" }}
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.RunID == "" {
					t.Error("run_id should not be empty")
				}
				if resp.Status == "" {
					t.Error("status should not be empty")
				}
				if resp.Engine == "" {
					t.Error("engine should not be empty")
				}
				if resp.AuthProfile == "" {
					t.Error("auth_profile should not be empty")
				}
				if resp.SubmittedAt == "" {
					t.Error("submitted_at should not be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storeFactory func() (cloud.Store, error)
			if tt.store != nil {
				mockStore := tt.store()
				if mockStore == nil {
					storeFactory = func() (cloud.Store, error) {
						return nil, fmt.Errorf("store factory error")
					}
				} else {
					storeFactory = func() (cloud.Store, error) {
						return mockStore, nil
					}
				}
			}

			var configFactory func() cloud.SubmitConfig
			if tt.config != nil {
				configFactory = tt.config
			}

			var out bytes.Buffer
			err := runCloudSubmit(
				tt.repo, tt.base, tt.engine, tt.authProf, tt.scope,
				cloud.WorkflowKindRun,
				tt.jsonOutput,
				storeFactory,
				configFactory,
				&out,
			)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := out.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output %q does not contain %q", output, want)
				}
			}

			if tt.checkJSON != nil {
				tt.checkJSON(t, strings.TrimSpace(output))
			}
		})
	}
}

func TestClassifySubmitError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "nil error", err: nil, wantCode: ""},
		{name: "validation error", err: fmt.Errorf("validation failed: repo must not be empty"), wantCode: "validation_error"},
		{name: "not linked", err: fmt.Errorf("auth profile \"p1\" is not linked (status: pending_link)"), wantCode: "auth_profile_not_linked"},
		{name: "not found", err: fmt.Errorf("auth profile \"p1\" not found"), wantCode: "not_found"},
		{name: "not compatible", err: fmt.Errorf("engine \"claude\" is not compatible with provider \"openai\""), wantCode: "engine_provider_mismatch"},
		{name: "not allowed", err: fmt.Errorf("provider \"openai\" is not allowed by policy"), wantCode: "policy_blocked"},
		{name: "enqueue failure", err: fmt.Errorf("failed to enqueue run: db error"), wantCode: "store_error"},
		{name: "unknown error", err: fmt.Errorf("something unexpected"), wantCode: "unknown_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySubmitError(tt.err)
			if got != tt.wantCode {
				t.Errorf("classifySubmitError(%v) = %q, want %q", tt.err, got, tt.wantCode)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	err := writeJSON(&buf, cloudSubmitResponse{
		RunID:       "run-001",
		Status:      "queued",
		Engine:      "claude",
		AuthProfile: "profile-1",
		SubmittedAt: "2026-02-10T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("writeJSON failed: %v", err)
	}

	var resp cloudSubmitResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}
	if resp.RunID != "run-001" {
		t.Errorf("run_id = %q, want %q", resp.RunID, "run-001")
	}
}

func validCloudRun(id string) *cloud.Run {
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(time.Hour)
	return &cloud.Run{
		ID:            id,
		Repo:          "org/repo",
		BaseBranch:    "main",
		WorkflowKind:  cloud.WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        cloud.RunStatusRunning,
		AttemptCount:  1,
		MaxAttempts:   3,
		DeadlineAt:    &deadline,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestRunCloudStatus(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		jsonOutput bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name:  "successful status with human output and active attempt",
			runID: "run-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.activeAttempts["run-001"] = &cloud.Attempt{
					ID:             "att-001",
					RunID:          "run-001",
					AttemptNumber:  1,
					WorkerID:       "worker-1",
					Status:         cloud.AttemptStatusActive,
					StartedAt:      time.Now().UTC(),
					HeartbeatAt:    time.Now().UTC().Add(-10 * time.Second),
					LeaseExpiresAt: time.Now().UTC().Add(20 * time.Second),
				}
				return s
			},
			wantOutput: []string{"Run status:", "run_id:", "run-001", "status:", "running", "attempt_count:", "1", "max_attempts:", "3", "current_attempt:", "1", "last_heartbeat:", "ago", "deadline_at:"},
		},
		{
			name:       "successful status with JSON output and active attempt",
			runID:      "run-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.activeAttempts["run-001"] = &cloud.Attempt{
					ID:             "att-001",
					RunID:          "run-001",
					AttemptNumber:  1,
					WorkerID:       "worker-1",
					Status:         cloud.AttemptStatusActive,
					StartedAt:      time.Now().UTC(),
					HeartbeatAt:    time.Now().UTC().Add(-5 * time.Second),
					LeaseExpiresAt: time.Now().UTC().Add(25 * time.Second),
				}
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.RunID != "run-001" {
					t.Errorf("run_id = %q, want %q", resp.RunID, "run-001")
				}
				if resp.Status != "running" {
					t.Errorf("status = %q, want %q", resp.Status, "running")
				}
				if resp.AttemptCount != 1 {
					t.Errorf("attempt_count = %d, want 1", resp.AttemptCount)
				}
				if resp.MaxAttempts != 3 {
					t.Errorf("max_attempts = %d, want 3", resp.MaxAttempts)
				}
				if resp.CurrentAttempt == nil || *resp.CurrentAttempt != 1 {
					t.Errorf("current_attempt = %v, want 1", resp.CurrentAttempt)
				}
				if resp.LastHeartbeatAgeSeconds == nil {
					t.Error("last_heartbeat_age_seconds should not be nil")
				}
				if resp.DeadlineAt == nil || *resp.DeadlineAt == "" {
					t.Error("deadline_at should not be nil or empty")
				}
				if resp.Engine != "claude" {
					t.Errorf("engine = %q, want %q", resp.Engine, "claude")
				}
				if resp.AuthProfileID != "profile-1" {
					t.Errorf("auth_profile_id = %q, want %q", resp.AuthProfileID, "profile-1")
				}
			},
		},
		{
			name:  "status with no active attempt shows none",
			runID: "run-002",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-002")
				run.Status = cloud.RunStatusQueued
				run.AttemptCount = 0
				s.runsByID["run-002"] = run
				return s
			},
			wantOutput: []string{"current_attempt: none", "last_heartbeat:  n/a"},
		},
		{
			name:       "JSON status with no active attempt has null fields",
			runID:      "run-002",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-002")
				run.Status = cloud.RunStatusQueued
				run.AttemptCount = 0
				s.runsByID["run-002"] = run
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.CurrentAttempt != nil {
					t.Errorf("current_attempt should be nil, got %v", resp.CurrentAttempt)
				}
				if resp.LastHeartbeatAgeSeconds != nil {
					t.Errorf("last_heartbeat_age_seconds should be nil, got %v", resp.LastHeartbeatAgeSeconds)
				}
			},
		},
		{
			name:  "unknown run_id returns error in human output",
			runID: "non-existent",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "not found",
		},
		{
			name:       "unknown run_id returns not_found in JSON",
			runID:      "non-existent",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "not found",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "not_found" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "not_found")
				}
			},
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			runID:      "run-001",
			jsonOutput: true,
			store:      nil,
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:    "nil store factory returns error in human output",
			runID:   "run-001",
			store:   nil,
			wantErr: "store not configured",
		},
		{
			name:       "store factory error in JSON",
			runID:      "run-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return nil // signals store factory error
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:       "store error on GetRun in JSON",
			runID:      "run-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.getRErr = fmt.Errorf("db connection failed")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "store_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "store_error")
				}
			},
		},
		{
			name:  "run with no deadline shows none",
			runID: "run-003",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-003")
				run.DeadlineAt = nil
				s.runsByID["run-003"] = run
				return s
			},
			wantOutput: []string{"deadline_at:     none"},
		},
		{
			name:       "JSON output with no deadline has null deadline_at",
			runID:      "run-003",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-003")
				run.DeadlineAt = nil
				s.runsByID["run-003"] = run
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudStatusResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.DeadlineAt != nil {
					t.Errorf("deadline_at should be nil, got %v", resp.DeadlineAt)
				}
			},
		},
		{
			name:       "JSON output contains exactly required fields",
			runID:      "run-004",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-004"] = validCloudRun("run-004")
				s.activeAttempts["run-004"] = &cloud.Attempt{
					ID:             "att-004",
					RunID:          "run-004",
					AttemptNumber:  2,
					WorkerID:       "worker-2",
					Status:         cloud.AttemptStatusActive,
					StartedAt:      time.Now().UTC(),
					HeartbeatAt:    time.Now().UTC(),
					LeaseExpiresAt: time.Now().UTC().Add(30 * time.Second),
				}
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				// Verify the required fields exist in JSON by unmarshaling to a map.
				var raw map[string]interface{}
				if err := json.Unmarshal([]byte(output), &raw); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				requiredKeys := []string{
					"run_id", "status", "attempt_count", "max_attempts",
					"current_attempt", "last_heartbeat_age_seconds",
					"deadline_at", "engine", "auth_profile_id",
				}
				for _, key := range requiredKeys {
					if _, ok := raw[key]; !ok {
						t.Errorf("missing required JSON key %q", key)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storeFactory func() (cloud.Store, error)
			if tt.store != nil {
				mockStore := tt.store()
				if mockStore == nil {
					storeFactory = func() (cloud.Store, error) {
						return nil, fmt.Errorf("store factory error")
					}
				} else {
					storeFactory = func() (cloud.Store, error) {
						return mockStore, nil
					}
				}
			}

			var out bytes.Buffer
			err := runCloudStatus(
				tt.runID,
				tt.jsonOutput,
				storeFactory,
				&out,
			)

			output := out.String()

			// For JSON not_found case, we check JSON first then error.
			if tt.checkJSON != nil && output != "" {
				tt.checkJSON(t, strings.TrimSpace(output))
			}

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output %q does not contain %q", output, want)
				}
			}

			if tt.checkJSON != nil {
				tt.checkJSON(t, strings.TrimSpace(output))
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{name: "seconds", d: 30 * time.Second, want: "30s"},
		{name: "minutes and seconds", d: 2*time.Minute + 15*time.Second, want: "2m15s"},
		{name: "hours and minutes", d: 3*time.Hour + 42*time.Minute, want: "3h42m"},
		{name: "zero", d: 0, want: "0s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.d)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestRunCloudLogs(t *testing.T) {
	now := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	payload := `{"message":"sandbox created"}`

	tests := []struct {
		name       string
		runID      string
		follow     bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		notOutput  []string
	}{
		{
			name:  "returns events ordered by timestamp",
			runID: "run-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.events["run-001"] = []*cloud.Event{
					{ID: "e1", RunID: "run-001", EventType: "sandbox_created", PayloadJSON: &payload, CreatedAt: now},
					{ID: "e2", RunID: "run-001", EventType: "bootstrap_started", CreatedAt: now.Add(time.Second)},
					{ID: "e3", RunID: "run-001", EventType: "execution_started", CreatedAt: now.Add(2 * time.Second)},
				}
				return s
			},
			wantOutput: []string{
				"sandbox_created",
				"bootstrap_started",
				"execution_started",
				`{"message":"sandbox created"}`,
				"2026-02-10T12:00:00Z",
			},
		},
		{
			name:  "empty events for existing run",
			runID: "run-002",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-002")
				run.Status = cloud.RunStatusQueued
				s.runsByID["run-002"] = run
				return s
			},
			wantOutput: []string{},
		},
		{
			name:  "unknown run_id returns not_found error",
			runID: "non-existent",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "not found",
		},
		{
			name:    "nil store factory returns error",
			runID:   "run-001",
			store:   nil,
			wantErr: "store not configured",
		},
		{
			name:  "store factory error returns error",
			runID: "run-001",
			store: func() *cloudMockStore {
				return nil // signals store factory error
			},
			wantErr: "failed to connect to store",
		},
		{
			name:  "list events error propagates",
			runID: "run-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.listEventsErr = fmt.Errorf("db error")
				return s
			},
			wantErr: "failed to list events",
		},
		{
			name:  "events with nil payload show only type",
			runID: "run-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				// Events are already redacted in the DB — the payload should not
				// contain raw secrets. This test confirms the output layer does
				// not re-introduce them.
				redactedPayload := `{"token":"[REDACTED]"}`
				s.events["run-001"] = []*cloud.Event{
					{ID: "e1", RunID: "run-001", EventType: "auth_materialized", PayloadJSON: &redactedPayload, Redacted: true, CreatedAt: now},
				}
				return s
			},
			wantOutput: []string{"[REDACTED]"},
			notOutput:  []string{"ghp_", "sk-ant-"},
		},
		{
			name:   "follow mode exits on terminal run status",
			runID:  "run-001",
			follow: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-001")
				run.Status = cloud.RunStatusSucceeded
				s.runsByID["run-001"] = run
				s.events["run-001"] = []*cloud.Event{
					{ID: "e1", RunID: "run-001", EventType: "run_succeeded", CreatedAt: now},
				}
				return s
			},
			wantOutput: []string{"run_succeeded"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storeFactory func() (cloud.Store, error)
			if tt.store != nil {
				mockStore := tt.store()
				if mockStore == nil {
					storeFactory = func() (cloud.Store, error) {
						return nil, fmt.Errorf("store factory error")
					}
				} else {
					storeFactory = func() (cloud.Store, error) {
						return mockStore, nil
					}
				}
			}

			var out bytes.Buffer
			ctx := context.Background()
			err := runCloudLogs(
				tt.runID,
				tt.follow,
				storeFactory,
				&out,
				ctx,
			)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := out.String()
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output %q does not contain %q", output, want)
				}
			}
			for _, notWant := range tt.notOutput {
				if strings.Contains(output, notWant) {
					t.Errorf("output should not contain %q but does", notWant)
				}
			}
		})
	}
}

func TestRunCloudLogs_FollowWithContextCancel(t *testing.T) {
	// Test that --follow mode respects context cancellation.
	s := newCloudMockStore()
	run := validCloudRun("run-001")
	run.Status = cloud.RunStatusRunning
	s.runsByID["run-001"] = run
	s.events["run-001"] = []*cloud.Event{
		{ID: "e1", RunID: "run-001", EventType: "execution_started", CreatedAt: time.Now().UTC()},
	}

	storeFactory := func() (cloud.Store, error) { return s, nil }

	// Set a very short poll interval for the test.
	origInterval := cloudLogsFollowPollInterval
	cloudLogsFollowPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { cloudLogsFollowPollInterval = origInterval })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var out bytes.Buffer
	err := runCloudLogs("run-001", true, storeFactory, &out, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "execution_started") {
		t.Errorf("output should contain initial event, got %q", output)
	}
}

func TestRunCloudLogs_FollowNewEvents(t *testing.T) {
	// Test that --follow mode picks up new events.
	s := newCloudMockStore()
	run := validCloudRun("run-001")
	run.Status = cloud.RunStatusRunning
	s.runsByID["run-001"] = run
	s.events["run-001"] = []*cloud.Event{
		{ID: "e1", RunID: "run-001", EventType: "execution_started", CreatedAt: time.Now().UTC()},
	}

	storeFactory := func() (cloud.Store, error) { return s, nil }

	origInterval := cloudLogsFollowPollInterval
	cloudLogsFollowPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { cloudLogsFollowPollInterval = origInterval })

	// After a short delay, add a new event and mark the run as succeeded.
	go func() {
		time.Sleep(30 * time.Millisecond)
		s.events["run-001"] = append(s.events["run-001"],
			&cloud.Event{ID: "e2", RunID: "run-001", EventType: "run_succeeded", CreatedAt: time.Now().UTC()},
		)
		run.Status = cloud.RunStatusSucceeded
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var out bytes.Buffer
	err := runCloudLogs("run-001", true, storeFactory, &out, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "execution_started") {
		t.Errorf("output should contain initial event, got %q", output)
	}
	if !strings.Contains(output, "run_succeeded") {
		t.Errorf("output should contain follow event, got %q", output)
	}
}

func TestFormatEvent(t *testing.T) {
	now := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	payload := `{"key":"value"}`

	tests := []struct {
		name       string
		event      *cloud.Event
		wantOutput string
	}{
		{
			name: "event with payload",
			event: &cloud.Event{
				ID: "e1", RunID: "run-001", EventType: "sandbox_created",
				PayloadJSON: &payload, CreatedAt: now,
			},
			wantOutput: `2026-02-10T12:00:00Z  sandbox_created           {"key":"value"}` + "\n",
		},
		{
			name: "event without payload",
			event: &cloud.Event{
				ID: "e2", RunID: "run-001", EventType: "teardown_done",
				CreatedAt: now,
			},
			wantOutput: "2026-02-10T12:00:00Z  teardown_done           \n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			formatEvent(&out, tt.event)
			if out.String() != tt.wantOutput {
				t.Errorf("formatEvent output = %q, want %q", out.String(), tt.wantOutput)
			}
		})
	}
}

func TestRunCloudCancel(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		jsonOutput bool
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name:  "successful cancel with human output",
			runID: "run-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				return s
			},
			wantOutput: []string{
				"Cancel requested.",
				"run_id:",
				"run-001",
				"cancel_requested: true",
				"status:",
				"running",
				"canceled_at:",
				"pending",
			},
		},
		{
			name:       "successful cancel with JSON output",
			runID:      "run-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudCancelResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.RunID != "run-001" {
					t.Errorf("run_id = %q, want %q", resp.RunID, "run-001")
				}
				if !resp.CancelRequested {
					t.Error("cancel_requested should be true")
				}
				if resp.Status != "running" {
					t.Errorf("status = %q, want %q", resp.Status, "running")
				}
				// Run is not yet canceled by worker, so canceled_at should be nil.
				if resp.CanceledAt != nil {
					t.Errorf("canceled_at should be nil when status is not canceled, got %v", resp.CanceledAt)
				}
			},
		},
		{
			name:       "cancel on already canceled run shows canceled_at",
			runID:      "run-002",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-002")
				run.Status = cloud.RunStatusCanceled
				run.CancelRequested = true
				s.runsByID["run-002"] = run
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudCancelResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.RunID != "run-002" {
					t.Errorf("run_id = %q, want %q", resp.RunID, "run-002")
				}
				if resp.Status != "canceled" {
					t.Errorf("status = %q, want %q", resp.Status, "canceled")
				}
				if resp.CanceledAt == nil {
					t.Error("canceled_at should not be nil for canceled run")
				}
			},
		},
		{
			name:  "unknown run_id returns error in human output",
			runID: "non-existent",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "not found",
		},
		{
			name:       "unknown run_id returns not_found in JSON",
			runID:      "non-existent",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "not found",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "not_found" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "not_found")
				}
			},
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			runID:      "run-001",
			jsonOutput: true,
			store:      nil,
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:    "nil store factory returns error in human output",
			runID:   "run-001",
			store:   nil,
			wantErr: "store not configured",
		},
		{
			name:       "store factory error in JSON",
			runID:      "run-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return nil // signals store factory error
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:       "JSON output contains exactly required fields",
			runID:      "run-003",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-003")
				run.Status = cloud.RunStatusCanceled
				run.CancelRequested = true
				s.runsByID["run-003"] = run
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var raw map[string]interface{}
				if err := json.Unmarshal([]byte(output), &raw); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				requiredKeys := []string{
					"run_id", "cancel_requested", "status", "canceled_at",
				}
				for _, key := range requiredKeys {
					if _, ok := raw[key]; !ok {
						t.Errorf("missing required JSON key %q", key)
					}
				}
			},
		},
		{
			name:  "cancel on already canceled run with human output shows timestamp",
			runID: "run-004",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				run := validCloudRun("run-004")
				run.Status = cloud.RunStatusCanceled
				run.CancelRequested = true
				s.runsByID["run-004"] = run
				return s
			},
			wantOutput: []string{
				"Cancel requested.",
				"run-004",
				"cancel_requested: true",
				"status:",
				"canceled",
				"canceled_at:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storeFactory func() (cloud.Store, error)
			if tt.store != nil {
				mockStore := tt.store()
				if mockStore == nil {
					storeFactory = func() (cloud.Store, error) {
						return nil, fmt.Errorf("store factory error")
					}
				} else {
					storeFactory = func() (cloud.Store, error) {
						return mockStore, nil
					}
				}
			}

			var out bytes.Buffer
			err := runCloudCancel(
				tt.runID,
				tt.jsonOutput,
				storeFactory,
				&out,
			)

			output := out.String()

			// For JSON not_found case, check JSON first then error.
			if tt.checkJSON != nil && output != "" {
				tt.checkJSON(t, strings.TrimSpace(output))
			}

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output %q does not contain %q", output, want)
				}
			}

			if tt.checkJSON != nil {
				tt.checkJSON(t, strings.TrimSpace(output))
			}
		})
	}
}

// --- Tests for the cloud run command ---

func setupHalDir(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create .hal dir: %v", err)
	}
	for name, content := range files {
		fullPath := filepath.Join(halDir, name)
		// Create parent dirs if needed (e.g., standards/foo.md).
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create dir for %s: %v", name, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}
}

func TestRunCloudRun(t *testing.T) {
	tests := []struct {
		name       string
		repo       string
		base       string
		engine     string
		authProf   string
		scope      string
		dryRun     bool
		jsonOutput bool
		files      map[string]string
		store      func() *cloudMockStore
		config     func() cloud.SubmitConfig
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
	}{
		{
			name:   "dry-run lists files and total bytes in human output",
			dryRun: true,
			files: map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
			},
			wantOutput: []string{"Dry run", ".hal/prd.json", ".hal/progress.txt", "Total:", "Bundle hash:"},
		},
		{
			name:       "dry-run lists files in JSON output",
			dryRun:     true,
			jsonOutput: true,
			files: map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudRunDryRunResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if len(resp.Files) != 2 {
					t.Errorf("expected 2 files, got %d", len(resp.Files))
				}
				if resp.TotalBytes <= 0 {
					t.Error("total_bytes should be > 0")
				}
				if resp.BundleHash == "" {
					t.Error("bundle_hash should not be empty")
				}
			},
		},
		{
			name:       "dry-run does not make network requests (no store needed)",
			dryRun:     true,
			jsonOutput: true,
			files: map[string]string{
				"prd.json": `{"project":"test"}`,
			},
			store: nil, // no store factory — should succeed in dry-run
			checkJSON: func(t *testing.T, output string) {
				var resp cloudRunDryRunResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if len(resp.Files) != 1 {
					t.Errorf("expected 1 file, got %d", len(resp.Files))
				}
			},
		},
		{
			name:     "successful run with human output",
			repo:     "org/repo",
			base:     "main",
			engine:   "claude",
			authProf: "profile-1",
			scope:    "prd-123",
			files: map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
			},
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{IDFunc: func() string { return "run-100" }}
			},
			wantOutput: []string{"Run submitted successfully", "run_id:", "run-100", "status:", "queued", "bundle_hash:"},
		},
		{
			name:       "successful run with JSON output returns run_id, status, bundle_hash",
			repo:       "org/repo",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			files: map[string]string{
				"prd.json": `{"project":"test"}`,
			},
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			config: func() cloud.SubmitConfig {
				return cloud.SubmitConfig{IDFunc: func() string { return "run-200" }}
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudRunResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.RunID != "run-200" {
					t.Errorf("run_id = %q, want %q", resp.RunID, "run-200")
				}
				if resp.Status != "queued" {
					t.Errorf("status = %q, want %q", resp.Status, "queued")
				}
				if resp.BundleHash == "" {
					t.Error("bundle_hash should not be empty")
				}
			},
		},
		{
			name:     "no .hal directory returns error",
			repo:     "org/repo",
			base:     "main",
			engine:   "claude",
			authProf: "profile-1",
			scope:    "prd-123",
			files:    nil, // no files = no .hal dir
			wantErr:  "failed to collect bundle files",
		},
		{
			name:     "empty .hal directory with no allowlisted files returns error",
			repo:     "org/repo",
			base:     "main",
			engine:   "claude",
			authProf: "profile-1",
			scope:    "prd-123",
			files: map[string]string{
				"skills/foo.txt": "not allowlisted",
			},
			wantErr: "no allowlisted files found",
		},
		{
			name:     "nil store factory returns configuration error",
			repo:     "org/repo",
			base:     "main",
			engine:   "claude",
			authProf: "profile-1",
			scope:    "prd-123",
			files: map[string]string{
				"prd.json": `{"project":"test"}`,
			},
			store:   nil,
			wantErr: "store not configured",
		},
		{
			name:       "validation error returned as JSON error code",
			repo:       "",
			base:       "main",
			engine:     "claude",
			authProf:   "profile-1",
			scope:      "prd-123",
			jsonOutput: true,
			files: map[string]string{
				"prd.json": `{"project":"test"}`,
			},
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudSubmitErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "validation_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "validation_error")
				}
			},
		},
		{
			name:   "denylisted files are excluded from bundle",
			dryRun: true,
			files: map[string]string{
				"prd.json":         `{"project":"test"}`,
				"archive/old.json": "archived",
				"reports/r1.txt":   "report",
				"skills/s1.md":     "skill",
			},
			wantOutput: []string{".hal/prd.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.files != nil {
				setupHalDir(t, dir, tt.files)
			}

			var storeFactory func() (cloud.Store, error)
			if tt.store != nil {
				mockStore := tt.store()
				if mockStore == nil {
					storeFactory = func() (cloud.Store, error) {
						return nil, fmt.Errorf("store factory error")
					}
				} else {
					storeFactory = func() (cloud.Store, error) {
						return mockStore, nil
					}
				}
			}

			var configFactory func() cloud.SubmitConfig
			if tt.config != nil {
				configFactory = tt.config
			}

			var out bytes.Buffer
			err := runCloudRun(
				tt.repo, tt.base, tt.engine, tt.authProf, tt.scope,
				tt.dryRun, tt.jsonOutput,
				storeFactory,
				configFactory,
				dir,
				&out,
			)

			output := out.String()

			if tt.wantErr != "" {
				if err == nil {
					// Some errors are written to output (JSON mode).
					if !strings.Contains(output, tt.wantErr) {
						t.Fatalf("expected error containing %q, got nil error and output %q", tt.wantErr, output)
					}
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output does not contain %q\noutput: %s", want, output)
				}
			}

			if tt.checkJSON != nil {
				tt.checkJSON(t, strings.TrimSpace(output))
			}
		})
	}
}

func TestCollectBundleFiles(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		wantPaths []string
		wantErr   string
	}{
		{
			name:    "no .hal directory",
			files:   nil,
			wantErr: ".hal directory not found",
		},
		{
			name: "collects allowlisted files only",
			files: map[string]string{
				"prd.json":         `{"project":"test"}`,
				"auto-prd.json":    `{"auto":"test"}`,
				"progress.txt":     "progress",
				"prompt.md":        "prompt",
				"config.yaml":      "config: true",
				"skills/s1.md":     "skill content",
				"archive/old.json": "old archive",
			},
			wantPaths: []string{
				".hal/auto-prd.json",
				".hal/config.yaml",
				".hal/prd.json",
				".hal/progress.txt",
				".hal/prompt.md",
			},
		},
		{
			name: "includes standards recursive glob",
			files: map[string]string{
				"prd.json":              `{"project":"test"}`,
				"standards/coding.md":   "coding standards",
				"standards/sub/deep.md": "deep standards",
			},
			wantPaths: []string{
				".hal/prd.json",
				".hal/standards/coding.md",
				".hal/standards/sub/deep.md",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.files != nil {
				setupHalDir(t, dir, tt.files)
			}

			records, contents, err := collectBundleFiles(dir)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check that all expected paths are present.
			gotPaths := make([]string, len(records))
			for i, r := range records {
				gotPaths[i] = r.Path
			}
			// Sort for stable comparison.
			for _, want := range tt.wantPaths {
				found := false
				for _, got := range gotPaths {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected path %q not found in %v", want, gotPaths)
				}
			}
			if len(gotPaths) != len(tt.wantPaths) {
				t.Errorf("got %d paths, want %d: got %v", len(gotPaths), len(tt.wantPaths), gotPaths)
			}

			// Verify contents map matches records.
			for _, r := range records {
				if _, ok := contents[r.Path]; !ok {
					t.Errorf("contents map missing key %q", r.Path)
				}
			}
		})
	}
}

// --- Tests for the cloud pull command ---

// makeBundleSnapshot creates a RunStateSnapshot with compressed bundle files.
func makeBundleSnapshot(t *testing.T, runID string, version int, files map[string]string) *cloud.RunStateSnapshot {
	t.Helper()
	var records []cloud.BundleManifestRecord
	fileContents := make(map[string][]byte)
	for name, content := range files {
		r := cloud.NewBundleManifestRecord(name, []byte(content))
		records = append(records, r)
		fileContents[r.Path] = []byte(content)
	}
	compressed, err := compressBundleFiles(records, fileContents)
	if err != nil {
		t.Fatalf("failed to compress test bundle: %v", err)
	}
	manifest := cloud.NewBundleManifest(records)
	return &cloud.RunStateSnapshot{
		ID:              fmt.Sprintf("snap-%s-%d", runID, version),
		RunID:           runID,
		SnapshotKind:    cloud.SnapshotKindFinal,
		Version:         version,
		SHA256:          manifest.SHA256,
		SizeBytes:       int64(len(compressed)),
		ContentEncoding: "application/gzip",
		ContentBlob:     compressed,
		CreatedAt:       time.Now().UTC(),
	}
}

func TestRunCloudPull(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		force      bool
		jsonOutput bool
		setupDir   func(t *testing.T, dir string)
		store      func() *cloudMockStore
		wantErr    string
		wantOutput []string
		checkJSON  func(t *testing.T, output string)
		checkDir   func(t *testing.T, dir string)
	}{
		{
			name:  "successful pull with human output",
			runID: "run-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.snapshots["run-001"] = makeBundleSnapshot(t, "run-001", 3, map[string]string{
					".hal/prd.json":     `{"project":"test"}`,
					".hal/progress.txt": "## done",
				})
				return s
			},
			wantOutput: []string{
				"Snapshot restored successfully.",
				"snapshot_version: 3",
				"sha256:",
				"files restored:",
				".hal/prd.json",
				".hal/progress.txt",
			},
			checkDir: func(t *testing.T, dir string) {
				content, err := os.ReadFile(filepath.Join(dir, ".hal", "prd.json"))
				if err != nil {
					t.Fatalf("failed to read prd.json: %v", err)
				}
				if string(content) != `{"project":"test"}` {
					t.Errorf("prd.json content = %q, want %q", string(content), `{"project":"test"}`)
				}
				content, err = os.ReadFile(filepath.Join(dir, ".hal", "progress.txt"))
				if err != nil {
					t.Fatalf("failed to read progress.txt: %v", err)
				}
				if string(content) != "## done" {
					t.Errorf("progress.txt content = %q, want %q", string(content), "## done")
				}
			},
		},
		{
			name:       "successful pull with JSON output",
			runID:      "run-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.snapshots["run-001"] = makeBundleSnapshot(t, "run-001", 5, map[string]string{
					".hal/prd.json": `{"project":"test"}`,
				})
				return s
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudPullResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.RunID != "run-001" {
					t.Errorf("run_id = %q, want %q", resp.RunID, "run-001")
				}
				if resp.SnapshotVersion != 5 {
					t.Errorf("snapshot_version = %d, want 5", resp.SnapshotVersion)
				}
				if resp.SHA256 == "" {
					t.Error("sha256 should not be empty")
				}
				if len(resp.FilesRestored) != 1 {
					t.Errorf("files_restored length = %d, want 1", len(resp.FilesRestored))
				}
			},
		},
		{
			name:  "unknown run_id returns not_found in human output",
			runID: "non-existent",
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "not found",
		},
		{
			name:       "unknown run_id returns not_found in JSON",
			runID:      "non-existent",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return newCloudMockStore()
			},
			wantErr: "not found",
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "not_found" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "not_found")
				}
			},
		},
		{
			name:  "no snapshot returns not_found error",
			runID: "run-001",
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				// no snapshot added
				return s
			},
			wantErr: "no snapshot found",
		},
		{
			name:  "refuses overwrite when local files changed without --force",
			runID: "run-001",
			setupDir: func(t *testing.T, dir string) {
				t.Helper()
				halDir := filepath.Join(dir, ".hal")
				os.MkdirAll(halDir, 0755)
				os.WriteFile(filepath.Join(halDir, "prd.json"), []byte(`{"local":"changes"}`), 0644)
			},
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.snapshots["run-001"] = makeBundleSnapshot(t, "run-001", 1, map[string]string{
					".hal/prd.json": `{"project":"remote"}`,
				})
				return s
			},
			wantErr: "local files changed",
		},
		{
			name:  "force overwrite when local files changed",
			runID: "run-001",
			force: true,
			setupDir: func(t *testing.T, dir string) {
				t.Helper()
				halDir := filepath.Join(dir, ".hal")
				os.MkdirAll(halDir, 0755)
				os.WriteFile(filepath.Join(halDir, "prd.json"), []byte(`{"local":"changes"}`), 0644)
			},
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.snapshots["run-001"] = makeBundleSnapshot(t, "run-001", 2, map[string]string{
					".hal/prd.json": `{"project":"remote"}`,
				})
				return s
			},
			wantOutput: []string{"Snapshot restored successfully."},
			checkDir: func(t *testing.T, dir string) {
				content, err := os.ReadFile(filepath.Join(dir, ".hal", "prd.json"))
				if err != nil {
					t.Fatalf("failed to read prd.json: %v", err)
				}
				if string(content) != `{"project":"remote"}` {
					t.Errorf("prd.json = %q, want %q", string(content), `{"project":"remote"}`)
				}
			},
		},
		{
			name:       "nil store factory returns configuration error in JSON",
			runID:      "run-001",
			jsonOutput: true,
			store:      nil,
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:    "nil store factory returns error in human output",
			runID:   "run-001",
			store:   nil,
			wantErr: "store not configured",
		},
		{
			name:       "store factory error in JSON",
			runID:      "run-001",
			jsonOutput: true,
			store: func() *cloudMockStore {
				return nil // signals store factory error
			},
			checkJSON: func(t *testing.T, output string) {
				var resp cloudErrorResponse
				if err := json.Unmarshal([]byte(output), &resp); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if resp.ErrorCode != "configuration_error" {
					t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
				}
			},
		},
		{
			name:  "identical local files are overwritten without --force",
			runID: "run-001",
			setupDir: func(t *testing.T, dir string) {
				t.Helper()
				halDir := filepath.Join(dir, ".hal")
				os.MkdirAll(halDir, 0755)
				// Write the same content as the snapshot — no change detected.
				os.WriteFile(filepath.Join(halDir, "prd.json"), []byte(`{"project":"test"}`), 0644)
			},
			store: func() *cloudMockStore {
				s := newCloudMockStore()
				s.runsByID["run-001"] = validCloudRun("run-001")
				s.snapshots["run-001"] = makeBundleSnapshot(t, "run-001", 1, map[string]string{
					".hal/prd.json": `{"project":"test"}`,
				})
				return s
			},
			wantOutput: []string{"Snapshot restored successfully."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setupDir != nil {
				tt.setupDir(t, dir)
			}

			var storeFactory func() (cloud.Store, error)
			if tt.store != nil {
				mockStore := tt.store()
				if mockStore == nil {
					storeFactory = func() (cloud.Store, error) {
						return nil, fmt.Errorf("store factory error")
					}
				} else {
					storeFactory = func() (cloud.Store, error) {
						return mockStore, nil
					}
				}
			}

			var out bytes.Buffer
			err := runCloudPull(
				tt.runID,
				tt.force,
				tt.jsonOutput,
				storeFactory,
				dir,
				&out,
			)

			output := out.String()

			// For JSON error cases, check JSON first then error.
			if tt.checkJSON != nil && output != "" {
				tt.checkJSON(t, strings.TrimSpace(output))
			}

			if tt.wantErr != "" {
				if err == nil {
					if !strings.Contains(output, tt.wantErr) {
						t.Fatalf("expected error containing %q, got nil error and output %q", tt.wantErr, output)
					}
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output does not contain %q\noutput: %s", want, output)
				}
			}

			if tt.checkJSON != nil {
				tt.checkJSON(t, strings.TrimSpace(output))
			}

			if tt.checkDir != nil {
				tt.checkDir(t, dir)
			}
		})
	}
}

func TestDecompressBundleFiles(t *testing.T) {
	// Create a compressed bundle and verify decompression roundtrip.
	records := []cloud.BundleManifestRecord{
		cloud.NewBundleManifestRecord(".hal/prd.json", []byte(`{"project":"test"}`)),
		cloud.NewBundleManifestRecord(".hal/progress.txt", []byte("## progress")),
	}
	fileContents := map[string][]byte{
		".hal/prd.json":     []byte(`{"project":"test"}`),
		".hal/progress.txt": []byte("## progress"),
	}

	compressed, err := compressBundleFiles(records, fileContents)
	if err != nil {
		t.Fatalf("compressBundleFiles failed: %v", err)
	}

	files, err := decompressBundleFiles(compressed)
	if err != nil {
		t.Fatalf("decompressBundleFiles failed: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	found := make(map[string]string)
	for _, f := range files {
		found[f.Path] = string(f.Content)
	}

	if found[".hal/prd.json"] != `{"project":"test"}` {
		t.Errorf("prd.json = %q, want %q", found[".hal/prd.json"], `{"project":"test"}`)
	}
	if found[".hal/progress.txt"] != "## progress" {
		t.Errorf("progress.txt = %q, want %q", found[".hal/progress.txt"], "## progress")
	}
}

func TestDecompressBundleFiles_InvalidData(t *testing.T) {
	_, err := decompressBundleFiles([]byte("not gzip data"))
	if err == nil {
		t.Fatal("expected error for invalid gzip data, got nil")
	}
}
