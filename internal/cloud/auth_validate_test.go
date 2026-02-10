package cloud

import (
	"context"
	"strings"
	"testing"
	"time"
)

type authValidateMockStore struct {
	mockStore
	profiles     map[string]*AuthProfile
	events       []*Event
	updateErr    error
	updatedProfs []*AuthProfile
}

func newAuthValidateMockStore() *authValidateMockStore {
	return &authValidateMockStore{
		profiles: make(map[string]*AuthProfile),
	}
}

func (s *authValidateMockStore) GetAuthProfile(_ context.Context, id string) (*AuthProfile, error) {
	p, ok := s.profiles[id]
	if !ok {
		return nil, ErrNotFound
	}
	return p, nil
}

func (s *authValidateMockStore) UpdateAuthProfile(_ context.Context, profile *AuthProfile) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.updatedProfs = append(s.updatedProfs, profile)
	s.profiles[profile.ID] = profile
	return nil
}

func (s *authValidateMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.events = append(s.events, event)
	return nil
}

func linkedProfileForValidation(id, provider string) *AuthProfile {
	secret := "encrypted:test-secret"
	return &AuthProfile{
		ID:                id,
		OwnerID:           "owner-1",
		Provider:          provider,
		Mode:              "session",
		SecretRef:         &secret,
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
}

func TestAuthValidateService_Validate(t *testing.T) {
	tests := []struct {
		name       string
		profileID  string
		setup      func(s *authValidateMockStore)
		wantErr    string
		checkStore func(t *testing.T, s *authValidateMockStore)
		check      func(t *testing.T, result *AuthValidateResult, s *authValidateMockStore)
	}{
		{
			name:      "successful validation updates last_validated_at",
			profileID: "prof-001",
			setup: func(s *authValidateMockStore) {
				s.profiles["prof-001"] = linkedProfileForValidation("prof-001", "anthropic")
			},
			check: func(t *testing.T, result *AuthValidateResult, s *authValidateMockStore) {
				t.Helper()
				if result.ProfileID != "prof-001" {
					t.Errorf("profile_id = %q, want %q", result.ProfileID, "prof-001")
				}
				if result.Provider != "anthropic" {
					t.Errorf("provider = %q, want %q", result.Provider, "anthropic")
				}
				if result.Status != "linked" {
					t.Errorf("status = %q, want %q", result.Status, "linked")
				}
				if result.ValidatedAt.IsZero() {
					t.Error("validated_at should not be zero")
				}
				p := s.profiles["prof-001"]
				if p.LastValidatedAt == nil {
					t.Fatal("expected last_validated_at to be set")
				}
				if p.LastErrorCode != nil {
					t.Errorf("expected last_error_code to be nil, got %v", *p.LastErrorCode)
				}
			},
		},
		{
			name:      "successful validation clears previous error code",
			profileID: "prof-002",
			setup: func(s *authValidateMockStore) {
				p := linkedProfileForValidation("prof-002", "anthropic")
				errCode := "auth_invalid"
				p.LastErrorCode = &errCode
				s.profiles["prof-002"] = p
			},
			checkStore: func(t *testing.T, s *authValidateMockStore) {
				t.Helper()
				p := s.profiles["prof-002"]
				if p.LastErrorCode != nil {
					t.Errorf("expected last_error_code to be nil, got %v", *p.LastErrorCode)
				}
				if p.LastValidatedAt == nil {
					t.Fatal("expected last_validated_at to be set")
				}
			},
		},
		{
			name:      "revoked profile sets auth_invalid error code",
			profileID: "prof-003",
			setup: func(s *authValidateMockStore) {
				p := linkedProfileForValidation("prof-003", "anthropic")
				p.Status = AuthProfileStatusRevoked
				s.profiles["prof-003"] = p
			},
			wantErr: "revoked",
			checkStore: func(t *testing.T, s *authValidateMockStore) {
				t.Helper()
				p := s.profiles["prof-003"]
				if p.LastErrorCode == nil || *p.LastErrorCode != string(FailureAuthInvalid) {
					t.Errorf("expected last_error_code = %q, got %v", FailureAuthInvalid, p.LastErrorCode)
				}
			},
		},
		{
			name:      "profile without credentials sets auth_invalid",
			profileID: "prof-004",
			setup: func(s *authValidateMockStore) {
				p := linkedProfileForValidation("prof-004", "anthropic")
				p.SecretRef = nil
				s.profiles["prof-004"] = p
			},
			wantErr: "no linked credentials",
			checkStore: func(t *testing.T, s *authValidateMockStore) {
				t.Helper()
				p := s.profiles["prof-004"]
				if p.LastErrorCode == nil || *p.LastErrorCode != string(FailureAuthInvalid) {
					t.Errorf("expected last_error_code = %q, got %v", FailureAuthInvalid, p.LastErrorCode)
				}
			},
		},
		{
			name:      "profile with empty secret_ref sets auth_invalid",
			profileID: "prof-005",
			setup: func(s *authValidateMockStore) {
				p := linkedProfileForValidation("prof-005", "anthropic")
				empty := ""
				p.SecretRef = &empty
				s.profiles["prof-005"] = p
			},
			wantErr: "no linked credentials",
		},
		{
			name:      "invalid runtime metadata sets auth_profile_incompatible",
			profileID: "prof-006",
			setup: func(s *authValidateMockStore) {
				p := linkedProfileForValidation("prof-006", "anthropic")
				badJSON := "not json"
				p.RuntimeMetadataJSON = &badJSON
				s.profiles["prof-006"] = p
			},
			wantErr: "failed to parse runtime metadata",
			checkStore: func(t *testing.T, s *authValidateMockStore) {
				t.Helper()
				p := s.profiles["prof-006"]
				if p.LastErrorCode == nil || *p.LastErrorCode != string(FailureAuthProfileIncompatible) {
					t.Errorf("expected last_error_code = %q, got %v", FailureAuthProfileIncompatible, p.LastErrorCode)
				}
			},
		},
		{
			name:      "valid runtime metadata passes validation",
			profileID: "prof-007",
			setup: func(s *authValidateMockStore) {
				p := linkedProfileForValidation("prof-007", "anthropic")
				meta := `{"os":"linux","arch":"amd64","cli_version":"1.2"}`
				p.RuntimeMetadataJSON = &meta
				s.profiles["prof-007"] = p
			},
			checkStore: func(t *testing.T, s *authValidateMockStore) {
				t.Helper()
				p := s.profiles["prof-007"]
				if p.LastValidatedAt == nil {
					t.Fatal("expected last_validated_at to be set")
				}
				if p.LastErrorCode != nil {
					t.Errorf("expected last_error_code to be nil, got %v", *p.LastErrorCode)
				}
			},
		},
		{
			name:      "missing profile returns not_found error",
			profileID: "no-such-profile",
			setup:     func(s *authValidateMockStore) {},
			wantErr:   "failed to get auth profile",
		},
		{
			name:      "empty profile ID returns validation error",
			profileID: "",
			setup:     func(s *authValidateMockStore) {},
			wantErr:   "validation failed",
		},
		{
			name:      "emits audit event on success",
			profileID: "prof-008",
			setup: func(s *authValidateMockStore) {
				s.profiles["prof-008"] = linkedProfileForValidation("prof-008", "anthropic")
			},
			checkStore: func(t *testing.T, s *authValidateMockStore) {
				t.Helper()
				if len(s.events) == 0 {
					t.Fatal("expected at least one audit event")
				}
				last := s.events[len(s.events)-1]
				if last.EventType != "auth_profile_validated" {
					t.Errorf("event type = %q, want %q", last.EventType, "auth_profile_validated")
				}
			},
		},
		{
			name:      "emits audit event on failure with error code",
			profileID: "prof-009",
			setup: func(s *authValidateMockStore) {
				p := linkedProfileForValidation("prof-009", "anthropic")
				p.Status = AuthProfileStatusRevoked
				s.profiles["prof-009"] = p
			},
			wantErr: "revoked",
			checkStore: func(t *testing.T, s *authValidateMockStore) {
				t.Helper()
				if len(s.events) == 0 {
					t.Fatal("expected at least one audit event")
				}
				last := s.events[len(s.events)-1]
				if last.EventType != "auth_profile_validated" {
					t.Errorf("event type = %q, want %q", last.EventType, "auth_profile_validated")
				}
				if last.PayloadJSON == nil || !strings.Contains(*last.PayloadJSON, "auth_invalid") {
					t.Errorf("expected audit event payload to contain auth_invalid error_code")
				}
			},
		},
		{
			name:      "update failure propagates error",
			profileID: "prof-010",
			setup: func(s *authValidateMockStore) {
				s.profiles["prof-010"] = linkedProfileForValidation("prof-010", "anthropic")
				s.updateErr = ErrConflict
			},
			wantErr: "failed to update auth profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newAuthValidateMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewAuthValidateService(store, AuthValidateConfig{})
			req := &AuthValidateRequest{ProfileID: tt.profileID}

			result, err := svc.Validate(context.Background(), req)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				if tt.checkStore != nil {
					tt.checkStore(t, store)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}

			if tt.check != nil {
				tt.check(t, result, store)
			}
			if tt.checkStore != nil {
				tt.checkStore(t, store)
			}
		})
	}
}
