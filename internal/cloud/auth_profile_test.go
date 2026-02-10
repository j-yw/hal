package cloud

import (
	"strings"
	"testing"
	"time"
)

func TestAuthProfileStatus_IsValid(t *testing.T) {
	tests := []struct {
		status AuthProfileStatus
		want   bool
	}{
		{AuthProfileStatusPendingLink, true},
		{AuthProfileStatusLinked, true},
		{AuthProfileStatusInvalid, true},
		{AuthProfileStatusRevoked, true},
		{"", false},
		{"invalid_status", false},
		{"LINKED", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsValid()
			if got != tt.want {
				t.Errorf("AuthProfileStatus(%q).IsValid() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestAuthProfileStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status   AuthProfileStatus
		terminal bool
	}{
		{AuthProfileStatusPendingLink, false},
		{AuthProfileStatusLinked, false},
		{AuthProfileStatusInvalid, false},
		{AuthProfileStatusRevoked, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsTerminal()
			if got != tt.terminal {
				t.Errorf("AuthProfileStatus(%q).IsTerminal() = %v, want %v", tt.status, got, tt.terminal)
			}
		})
	}
}

func TestAuthProfileStatus_ExhaustiveSet(t *testing.T) {
	expected := []AuthProfileStatus{
		AuthProfileStatusPendingLink,
		AuthProfileStatusLinked,
		AuthProfileStatusInvalid,
		AuthProfileStatusRevoked,
	}

	if len(validAuthProfileStatuses) != len(expected) {
		t.Fatalf("validAuthProfileStatuses has %d entries, expected %d", len(validAuthProfileStatuses), len(expected))
	}

	for _, s := range expected {
		if !validAuthProfileStatuses[s] {
			t.Errorf("expected status %q in validAuthProfileStatuses", s)
		}
	}
}

func validAuthProfile() AuthProfile {
	now := time.Now()
	return AuthProfile{
		ID:                "auth-001",
		OwnerID:           "owner-001",
		Provider:          "claude",
		Mode:              "oauth",
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func TestAuthProfile_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(p *AuthProfile)
		wantErr string
	}{
		{
			name:   "valid auth profile passes",
			modify: func(p *AuthProfile) {},
		},
		{
			name:    "empty id",
			modify:  func(p *AuthProfile) { p.ID = "" },
			wantErr: "auth_profile.id must not be empty",
		},
		{
			name:    "empty owner_id",
			modify:  func(p *AuthProfile) { p.OwnerID = "" },
			wantErr: "auth_profile.owner_id must not be empty",
		},
		{
			name:    "empty provider",
			modify:  func(p *AuthProfile) { p.Provider = "" },
			wantErr: "auth_profile.provider must not be empty",
		},
		{
			name:    "empty mode",
			modify:  func(p *AuthProfile) { p.Mode = "" },
			wantErr: "auth_profile.mode must not be empty",
		},
		{
			name:    "invalid status",
			modify:  func(p *AuthProfile) { p.Status = "bogus" },
			wantErr: `auth_profile.status "bogus" is not a valid status`,
		},
		{
			name:    "max_concurrent_runs zero",
			modify:  func(p *AuthProfile) { p.MaxConcurrentRuns = 0 },
			wantErr: "auth_profile.max_concurrent_runs must be >= 1",
		},
		{
			name:    "max_concurrent_runs negative",
			modify:  func(p *AuthProfile) { p.MaxConcurrentRuns = -1 },
			wantErr: "auth_profile.max_concurrent_runs must be >= 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validAuthProfile()
			tt.modify(&p)
			err := p.Validate()

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
		})
	}
}

func TestAuthProfilesSchema_ContainsRequiredColumns(t *testing.T) {
	requiredColumns := []string{
		"id",
		"owner_id",
		"provider",
		"mode",
		"secret_ref",
		"status",
		"max_concurrent_runs",
		"runtime_metadata_json",
		"last_validated_at",
		"expires_at",
		"last_error_code",
		"version",
		"created_at",
		"updated_at",
	}

	for _, col := range requiredColumns {
		if !strings.Contains(AuthProfilesSchema, col) {
			t.Errorf("AuthProfilesSchema missing column %q", col)
		}
	}
}

func TestAuthProfilesSchema_StatusConstraint(t *testing.T) {
	statuses := []string{
		"pending_link", "linked", "invalid", "revoked",
	}
	for _, s := range statuses {
		if !strings.Contains(AuthProfilesSchema, "'"+s+"'") {
			t.Errorf("AuthProfilesSchema CHECK constraint missing status %q", s)
		}
	}
}

func TestAuthProfilesSchema_MaxConcurrentRunsConstraint(t *testing.T) {
	if !strings.Contains(AuthProfilesSchema, "max_concurrent_runs >= 1") {
		t.Error("AuthProfilesSchema missing CHECK constraint on max_concurrent_runs >= 1")
	}
}

func TestAuthProfile_OptionalFields(t *testing.T) {
	p := validAuthProfile()
	if p.SecretRef != nil {
		t.Error("SecretRef should be nil by default")
	}
	if p.RuntimeMetadataJSON != nil {
		t.Error("RuntimeMetadataJSON should be nil by default")
	}
	if p.LastValidatedAt != nil {
		t.Error("LastValidatedAt should be nil by default")
	}
	if p.ExpiresAt != nil {
		t.Error("ExpiresAt should be nil by default")
	}
	if p.LastErrorCode != nil {
		t.Error("LastErrorCode should be nil by default")
	}

	now := time.Now()
	secret := "vault://secret/auth-001"
	metadata := `{"os":"linux","arch":"amd64"}`
	errorCode := "auth_expired"
	p.SecretRef = &secret
	p.RuntimeMetadataJSON = &metadata
	p.LastValidatedAt = &now
	p.ExpiresAt = &now
	p.LastErrorCode = &errorCode

	if err := p.Validate(); err != nil {
		t.Fatalf("valid auth profile with optional fields set: unexpected error: %v", err)
	}
}
