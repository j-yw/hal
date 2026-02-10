package cloud

import (
	"context"
	"strings"
	"testing"
	"time"
)

type authRevokeMockStore struct {
	mockStore
	profiles     map[string]*AuthProfile
	events       []*Event
	updateErr    error
	updatedProfs []*AuthProfile
}

func newAuthRevokeMockStore() *authRevokeMockStore {
	return &authRevokeMockStore{
		profiles: make(map[string]*AuthProfile),
	}
}

func (s *authRevokeMockStore) GetAuthProfile(_ context.Context, id string) (*AuthProfile, error) {
	p, ok := s.profiles[id]
	if !ok {
		return nil, ErrNotFound
	}
	return p, nil
}

func (s *authRevokeMockStore) UpdateAuthProfile(_ context.Context, profile *AuthProfile) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.updatedProfs = append(s.updatedProfs, profile)
	s.profiles[profile.ID] = profile
	return nil
}

func (s *authRevokeMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.events = append(s.events, event)
	return nil
}

func linkedProfileForRevoke(id, provider string) *AuthProfile {
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

func TestAuthRevokeService_Revoke(t *testing.T) {
	tests := []struct {
		name       string
		profileID  string
		setup      func(s *authRevokeMockStore)
		wantErr    string
		checkStore func(t *testing.T, s *authRevokeMockStore)
		check      func(t *testing.T, result *AuthRevokeResult, s *authRevokeMockStore)
	}{
		{
			name:      "successful revoke transitions to revoked status",
			profileID: "prof-001",
			setup: func(s *authRevokeMockStore) {
				s.profiles["prof-001"] = linkedProfileForRevoke("prof-001", "anthropic")
			},
			check: func(t *testing.T, result *AuthRevokeResult, s *authRevokeMockStore) {
				t.Helper()
				if result.ProfileID != "prof-001" {
					t.Errorf("profile_id = %q, want %q", result.ProfileID, "prof-001")
				}
				if result.Provider != "anthropic" {
					t.Errorf("provider = %q, want %q", result.Provider, "anthropic")
				}
				if result.Status != "revoked" {
					t.Errorf("status = %q, want %q", result.Status, "revoked")
				}
				if result.RevokedAt.IsZero() {
					t.Error("revoked_at should not be zero")
				}
				p := s.profiles["prof-001"]
				if p.Status != AuthProfileStatusRevoked {
					t.Errorf("stored status = %q, want %q", p.Status, AuthProfileStatusRevoked)
				}
			},
		},
		{
			name:      "revoking already-revoked profile succeeds (idempotent)",
			profileID: "prof-002",
			setup: func(s *authRevokeMockStore) {
				p := linkedProfileForRevoke("prof-002", "anthropic")
				p.Status = AuthProfileStatusRevoked
				s.profiles["prof-002"] = p
			},
			check: func(t *testing.T, result *AuthRevokeResult, s *authRevokeMockStore) {
				t.Helper()
				if result.Status != "revoked" {
					t.Errorf("status = %q, want %q", result.Status, "revoked")
				}
			},
		},
		{
			name:      "missing profile returns not_found error",
			profileID: "no-such-profile",
			setup:     func(s *authRevokeMockStore) {},
			wantErr:   "failed to get auth profile",
		},
		{
			name:      "empty profile ID returns validation error",
			profileID: "",
			setup:     func(s *authRevokeMockStore) {},
			wantErr:   "validation failed",
		},
		{
			name:      "emits audit event on success",
			profileID: "prof-003",
			setup: func(s *authRevokeMockStore) {
				s.profiles["prof-003"] = linkedProfileForRevoke("prof-003", "openai")
			},
			checkStore: func(t *testing.T, s *authRevokeMockStore) {
				t.Helper()
				if len(s.events) == 0 {
					t.Fatal("expected at least one audit event")
				}
				last := s.events[len(s.events)-1]
				if last.EventType != "auth_profile_revoked" {
					t.Errorf("event type = %q, want %q", last.EventType, "auth_profile_revoked")
				}
				if last.PayloadJSON == nil || !strings.Contains(*last.PayloadJSON, "openai") {
					t.Errorf("expected audit event payload to contain provider")
				}
				if !strings.Contains(*last.PayloadJSON, "prof-003") {
					t.Errorf("expected audit event payload to contain profile ID")
				}
			},
		},
		{
			name:      "update failure propagates error",
			profileID: "prof-004",
			setup: func(s *authRevokeMockStore) {
				s.profiles["prof-004"] = linkedProfileForRevoke("prof-004", "anthropic")
				s.updateErr = ErrConflict
			},
			wantErr: "failed to update auth profile",
		},
		{
			name:      "revoke updates stored profile status",
			profileID: "prof-005",
			setup: func(s *authRevokeMockStore) {
				s.profiles["prof-005"] = linkedProfileForRevoke("prof-005", "anthropic")
			},
			checkStore: func(t *testing.T, s *authRevokeMockStore) {
				t.Helper()
				p := s.profiles["prof-005"]
				if p.Status != AuthProfileStatusRevoked {
					t.Errorf("stored status = %q, want %q", p.Status, AuthProfileStatusRevoked)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newAuthRevokeMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewAuthRevokeService(store, AuthRevokeConfig{})
			req := &AuthRevokeRequest{ProfileID: tt.profileID}

			result, err := svc.Revoke(context.Background(), req)

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
