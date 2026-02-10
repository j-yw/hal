package cloud

import (
	"context"
	"strings"
	"testing"
)

type authLinkMockStore struct {
	mockStore
	profiles       map[string]*AuthProfile
	events         []*Event
	createErr      error
	insertEventErr error
}

func newAuthLinkMockStore() *authLinkMockStore {
	return &authLinkMockStore{
		profiles: make(map[string]*AuthProfile),
	}
}

func (s *authLinkMockStore) CreateAuthProfile(_ context.Context, profile *AuthProfile) error {
	if s.createErr != nil {
		return s.createErr
	}
	if _, ok := s.profiles[profile.ID]; ok {
		return ErrDuplicateKey
	}
	s.profiles[profile.ID] = profile
	return nil
}

func (s *authLinkMockStore) InsertEvent(_ context.Context, event *Event) error {
	if s.insertEventErr != nil {
		return s.insertEventErr
	}
	s.events = append(s.events, event)
	return nil
}

func TestAuthLinkService_Link(t *testing.T) {
	tests := []struct {
		name    string
		req     *AuthLinkRequest
		store   func() *authLinkMockStore
		wantErr string
		check   func(t *testing.T, result *AuthLinkResult, store *authLinkMockStore)
	}{
		{
			name: "successful link creates profile and emits audit event",
			req: &AuthLinkRequest{
				Provider:  "anthropic",
				ProfileID: "prof-001",
				SecretRef: "encrypted:abc123",
			},
			store: func() *authLinkMockStore {
				return newAuthLinkMockStore()
			},
			check: func(t *testing.T, result *AuthLinkResult, store *authLinkMockStore) {
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
				if result.LinkedAt.IsZero() {
					t.Error("linked_at should not be zero")
				}
				// Verify profile was stored.
				p, ok := store.profiles["prof-001"]
				if !ok {
					t.Fatal("profile not found in store")
				}
				if p.Status != AuthProfileStatusLinked {
					t.Errorf("stored status = %q, want %q", p.Status, AuthProfileStatusLinked)
				}
				if p.SecretRef == nil || *p.SecretRef != "encrypted:abc123" {
					t.Errorf("stored secret_ref = %v, want %q", p.SecretRef, "encrypted:abc123")
				}
				if p.OwnerID != "operator" {
					t.Errorf("stored owner_id = %q, want %q", p.OwnerID, "operator")
				}
				if p.Mode != "session" {
					t.Errorf("stored mode = %q, want %q", p.Mode, "session")
				}
				// Verify audit event was emitted.
				if len(store.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(store.events))
				}
				evt := store.events[0]
				if evt.EventType != "auth_profile_linked" {
					t.Errorf("event_type = %q, want %q", evt.EventType, "auth_profile_linked")
				}
				if evt.PayloadJSON == nil {
					t.Fatal("event payload should not be nil")
				}
				if !strings.Contains(*evt.PayloadJSON, "anthropic") {
					t.Errorf("event payload should contain provider, got %q", *evt.PayloadJSON)
				}
				if !strings.Contains(*evt.PayloadJSON, "prof-001") {
					t.Errorf("event payload should contain profile_id, got %q", *evt.PayloadJSON)
				}
			},
		},
		{
			name: "custom owner_id and mode are preserved",
			req: &AuthLinkRequest{
				Provider:  "openai",
				ProfileID: "prof-002",
				OwnerID:   "user-42",
				Mode:      "api_key",
				SecretRef: "encrypted:xyz",
			},
			store: func() *authLinkMockStore {
				return newAuthLinkMockStore()
			},
			check: func(t *testing.T, result *AuthLinkResult, store *authLinkMockStore) {
				t.Helper()
				p := store.profiles["prof-002"]
				if p.OwnerID != "user-42" {
					t.Errorf("owner_id = %q, want %q", p.OwnerID, "user-42")
				}
				if p.Mode != "api_key" {
					t.Errorf("mode = %q, want %q", p.Mode, "api_key")
				}
			},
		},
		{
			name: "missing provider returns validation error",
			req: &AuthLinkRequest{
				Provider:  "",
				ProfileID: "prof-001",
			},
			store: func() *authLinkMockStore {
				return newAuthLinkMockStore()
			},
			wantErr: "provider must not be empty",
		},
		{
			name: "missing profile returns validation error",
			req: &AuthLinkRequest{
				Provider:  "anthropic",
				ProfileID: "",
			},
			store: func() *authLinkMockStore {
				return newAuthLinkMockStore()
			},
			wantErr: "profile must not be empty",
		},
		{
			name: "duplicate profile returns error",
			req: &AuthLinkRequest{
				Provider:  "anthropic",
				ProfileID: "prof-001",
				SecretRef: "encrypted:new",
			},
			store: func() *authLinkMockStore {
				s := newAuthLinkMockStore()
				s.profiles["prof-001"] = &AuthProfile{ID: "prof-001"}
				return s
			},
			wantErr: "already exists",
		},
		{
			name: "store error propagates",
			req: &AuthLinkRequest{
				Provider:  "anthropic",
				ProfileID: "prof-001",
				SecretRef: "encrypted:abc",
			},
			store: func() *authLinkMockStore {
				s := newAuthLinkMockStore()
				s.createErr = ErrConflict
				return s
			},
			wantErr: "failed to create auth profile",
		},
		{
			name: "audit event failure does not fail the link",
			req: &AuthLinkRequest{
				Provider:  "anthropic",
				ProfileID: "prof-003",
				SecretRef: "encrypted:abc",
			},
			store: func() *authLinkMockStore {
				s := newAuthLinkMockStore()
				s.insertEventErr = ErrNotFound // simulate event insertion failure
				return s
			},
			check: func(t *testing.T, result *AuthLinkResult, store *authLinkMockStore) {
				t.Helper()
				// Profile should still be created despite event failure.
				if _, ok := store.profiles["prof-003"]; !ok {
					t.Fatal("profile should exist despite event failure")
				}
				if result.Status != "linked" {
					t.Errorf("status = %q, want %q", result.Status, "linked")
				}
			},
		},
		{
			name: "link without secret_ref stores nil",
			req: &AuthLinkRequest{
				Provider:  "anthropic",
				ProfileID: "prof-004",
			},
			store: func() *authLinkMockStore {
				return newAuthLinkMockStore()
			},
			check: func(t *testing.T, result *AuthLinkResult, store *authLinkMockStore) {
				t.Helper()
				p := store.profiles["prof-004"]
				if p.SecretRef != nil {
					t.Errorf("secret_ref = %v, want nil", p.SecretRef)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.store()
			svc := NewAuthLinkService(store, AuthLinkConfig{})

			result, err := svc.Link(context.Background(), tt.req)

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

			if tt.check != nil {
				tt.check(t, result, store)
			}
		})
	}
}
