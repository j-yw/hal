package cloud

import (
	"context"
	"strings"
	"testing"
)

type authImportMockStore struct {
	mockStore
	profiles       map[string]*AuthProfile
	events         []*Event
	createErr      error
	insertEventErr error
}

func newAuthImportMockStore() *authImportMockStore {
	return &authImportMockStore{
		profiles: make(map[string]*AuthProfile),
	}
}

func (s *authImportMockStore) CreateAuthProfile(_ context.Context, profile *AuthProfile) error {
	if s.createErr != nil {
		return s.createErr
	}
	if _, ok := s.profiles[profile.ID]; ok {
		return ErrDuplicateKey
	}
	s.profiles[profile.ID] = profile
	return nil
}

func (s *authImportMockStore) InsertEvent(_ context.Context, event *Event) error {
	if s.insertEventErr != nil {
		return s.insertEventErr
	}
	s.events = append(s.events, event)
	return nil
}

func TestAuthImportService_Import(t *testing.T) {
	tests := []struct {
		name    string
		req     *AuthImportRequest
		store   func() *authImportMockStore
		wantErr string
		check   func(t *testing.T, result *AuthImportResult, store *authImportMockStore)
	}{
		{
			name: "successful import creates profile and emits audit event",
			req: &AuthImportRequest{
				Provider:  "anthropic",
				ProfileID: "prof-001",
				Source:    "/home/user/.config/anthropic/auth.json",
			},
			store: func() *authImportMockStore {
				return newAuthImportMockStore()
			},
			check: func(t *testing.T, result *AuthImportResult, store *authImportMockStore) {
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
				if result.ImportedAt.IsZero() {
					t.Error("imported_at should not be zero")
				}
				// Verify profile was stored.
				p, ok := store.profiles["prof-001"]
				if !ok {
					t.Fatal("profile not found in store")
				}
				if p.Status != AuthProfileStatusLinked {
					t.Errorf("stored status = %q, want %q", p.Status, AuthProfileStatusLinked)
				}
				if p.SecretRef == nil || !strings.HasPrefix(*p.SecretRef, "encrypted:") {
					t.Errorf("stored secret_ref = %v, want encrypted prefix", p.SecretRef)
				}
				if p.OwnerID != "operator" {
					t.Errorf("stored owner_id = %q, want %q", p.OwnerID, "operator")
				}
				if p.Mode != "imported" {
					t.Errorf("stored mode = %q, want %q", p.Mode, "imported")
				}
				// Verify audit event was emitted.
				if len(store.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(store.events))
				}
				evt := store.events[0]
				if evt.EventType != "auth_profile_imported" {
					t.Errorf("event_type = %q, want %q", evt.EventType, "auth_profile_imported")
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
				if !strings.Contains(*evt.PayloadJSON, "import") {
					t.Errorf("event payload should contain action import, got %q", *evt.PayloadJSON)
				}
			},
		},
		{
			name: "custom owner_id and mode are preserved",
			req: &AuthImportRequest{
				Provider:  "openai",
				ProfileID: "prof-002",
				Source:    "/path/to/creds",
				OwnerID:   "user-42",
				Mode:      "api_key",
			},
			store: func() *authImportMockStore {
				return newAuthImportMockStore()
			},
			check: func(t *testing.T, result *AuthImportResult, store *authImportMockStore) {
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
			req: &AuthImportRequest{
				Provider:  "",
				ProfileID: "prof-001",
				Source:    "/path/to/creds",
			},
			store: func() *authImportMockStore {
				return newAuthImportMockStore()
			},
			wantErr: "provider must not be empty",
		},
		{
			name: "missing profile returns validation error",
			req: &AuthImportRequest{
				Provider:  "anthropic",
				ProfileID: "",
				Source:    "/path/to/creds",
			},
			store: func() *authImportMockStore {
				return newAuthImportMockStore()
			},
			wantErr: "profile must not be empty",
		},
		{
			name: "missing source returns validation error",
			req: &AuthImportRequest{
				Provider:  "anthropic",
				ProfileID: "prof-001",
				Source:    "",
			},
			store: func() *authImportMockStore {
				return newAuthImportMockStore()
			},
			wantErr: "source must not be empty",
		},
		{
			name: "duplicate profile returns error",
			req: &AuthImportRequest{
				Provider:  "anthropic",
				ProfileID: "prof-001",
				Source:    "/path/to/creds",
			},
			store: func() *authImportMockStore {
				s := newAuthImportMockStore()
				s.profiles["prof-001"] = &AuthProfile{ID: "prof-001"}
				return s
			},
			wantErr: "already exists",
		},
		{
			name: "store error propagates",
			req: &AuthImportRequest{
				Provider:  "anthropic",
				ProfileID: "prof-001",
				Source:    "/path/to/creds",
			},
			store: func() *authImportMockStore {
				s := newAuthImportMockStore()
				s.createErr = ErrConflict
				return s
			},
			wantErr: "failed to create auth profile",
		},
		{
			name: "audit event failure does not fail the import",
			req: &AuthImportRequest{
				Provider:  "anthropic",
				ProfileID: "prof-003",
				Source:    "/path/to/creds",
			},
			store: func() *authImportMockStore {
				s := newAuthImportMockStore()
				s.insertEventErr = ErrNotFound // simulate event insertion failure
				return s
			},
			check: func(t *testing.T, result *AuthImportResult, store *authImportMockStore) {
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
			name: "source is encrypted as secret reference",
			req: &AuthImportRequest{
				Provider:  "anthropic",
				ProfileID: "prof-004",
				Source:    "/home/user/.anthropic/creds.json",
			},
			store: func() *authImportMockStore {
				return newAuthImportMockStore()
			},
			check: func(t *testing.T, result *AuthImportResult, store *authImportMockStore) {
				t.Helper()
				p := store.profiles["prof-004"]
				if p.SecretRef == nil {
					t.Fatal("secret_ref should not be nil")
				}
				want := "encrypted:/home/user/.anthropic/creds.json"
				if *p.SecretRef != want {
					t.Errorf("secret_ref = %q, want %q", *p.SecretRef, want)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.store()
			svc := NewAuthImportService(store, AuthImportConfig{})

			result, err := svc.Import(context.Background(), tt.req)

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
