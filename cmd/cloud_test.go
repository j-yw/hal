package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

// cloudMockStore is a minimal mock store for cloud submit tests.
type cloudMockStore struct {
	profiles map[string]*cloud.AuthProfile
	runs     []*cloud.Run
	enqErr   error
}

func newCloudMockStore() *cloudMockStore {
	return &cloudMockStore{
		profiles: make(map[string]*cloud.AuthProfile),
	}
}

func (s *cloudMockStore) EnqueueRun(_ context.Context, run *cloud.Run) error {
	if s.enqErr != nil {
		return s.enqErr
	}
	s.runs = append(s.runs, run)
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
func (s *cloudMockStore) GetRun(_ context.Context, _ string) (*cloud.Run, error) { return nil, nil }
func (s *cloudMockStore) ListOverdueRuns(_ context.Context, _ time.Time) ([]*cloud.Run, error) {
	return nil, nil
}
func (s *cloudMockStore) SetCancelIntent(_ context.Context, _ string) error       { return nil }
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
func (s *cloudMockStore) InsertEvent(_ context.Context, _ *cloud.Event) error { return nil }
func (s *cloudMockStore) ListEvents(_ context.Context, _ string) ([]*cloud.Event, error) {
	return nil, nil
}
func (s *cloudMockStore) PutIdempotencyKey(_ context.Context, _ *cloud.IdempotencyKey) error {
	return nil
}
func (s *cloudMockStore) GetIdempotencyKey(_ context.Context, _ string) (*cloud.IdempotencyKey, error) {
	return nil, nil
}
func (s *cloudMockStore) UpdateAuthProfile(_ context.Context, _ *cloud.AuthProfile) error { return nil }
func (s *cloudMockStore) AcquireAuthLock(_ context.Context, _ *cloud.AuthProfileLock) error {
	return nil
}
func (s *cloudMockStore) RenewAuthLock(_ context.Context, _, _ string, _, _ time.Time) error {
	return nil
}
func (s *cloudMockStore) ReleaseAuthLock(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}
func (s *cloudMockStore) PutSnapshot(_ context.Context, _ *cloud.RunStateSnapshot) error { return nil }
func (s *cloudMockStore) GetSnapshot(_ context.Context, _ string) (*cloud.RunStateSnapshot, error) {
	return nil, nil
}
func (s *cloudMockStore) GetLatestSnapshot(_ context.Context, _ string) (*cloud.RunStateSnapshot, error) {
	return nil, nil
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
