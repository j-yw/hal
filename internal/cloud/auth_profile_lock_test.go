package cloud

import (
	"strings"
	"testing"
	"time"
)

func validAuthProfileLock() AuthProfileLock {
	now := time.Now()
	return AuthProfileLock{
		AuthProfileID:  "auth-001",
		RunID:          "run-001",
		WorkerID:       "worker-001",
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(5 * time.Minute),
	}
}

func TestAuthProfileLock_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(l *AuthProfileLock)
		wantErr string
	}{
		{
			name:   "valid lock passes",
			modify: func(l *AuthProfileLock) {},
		},
		{
			name:    "empty auth_profile_id",
			modify:  func(l *AuthProfileLock) { l.AuthProfileID = "" },
			wantErr: "auth_profile_lock.auth_profile_id must not be empty",
		},
		{
			name:    "empty run_id",
			modify:  func(l *AuthProfileLock) { l.RunID = "" },
			wantErr: "auth_profile_lock.run_id must not be empty",
		},
		{
			name:    "empty worker_id",
			modify:  func(l *AuthProfileLock) { l.WorkerID = "" },
			wantErr: "auth_profile_lock.worker_id must not be empty",
		},
		{
			name: "valid lock with released_at set",
			modify: func(l *AuthProfileLock) {
				now := time.Now()
				l.ReleasedAt = &now
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := validAuthProfileLock()
			tt.modify(&l)
			err := l.Validate()

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

func TestAuthProfileLocksSchema_ContainsRequiredColumns(t *testing.T) {
	requiredColumns := []string{
		"auth_profile_id",
		"run_id",
		"worker_id",
		"acquired_at",
		"heartbeat_at",
		"lease_expires_at",
		"released_at",
	}

	for _, col := range requiredColumns {
		if !strings.Contains(AuthProfileLocksSchema, col) {
			t.Errorf("AuthProfileLocksSchema missing column %q", col)
		}
	}
}

func TestAuthProfileLocksSchema_ForeignKeys(t *testing.T) {
	fks := []string{
		"REFERENCES auth_profiles(id)",
		"REFERENCES runs(id)",
	}
	for _, fk := range fks {
		if !strings.Contains(AuthProfileLocksSchema, fk) {
			t.Errorf("AuthProfileLocksSchema missing foreign key %q", fk)
		}
	}
}

func TestAuthProfileLocksLeaseIndex_Columns(t *testing.T) {
	if !strings.Contains(AuthProfileLocksLeaseIndex, "auth_profile_id") {
		t.Error("AuthProfileLocksLeaseIndex missing auth_profile_id")
	}
	if !strings.Contains(AuthProfileLocksLeaseIndex, "lease_expires_at") {
		t.Error("AuthProfileLocksLeaseIndex missing lease_expires_at")
	}
}

func TestAuthProfileLocksOneActiveIndex_UniqueConstraint(t *testing.T) {
	if !strings.Contains(AuthProfileLocksOneActiveIndex, "UNIQUE") {
		t.Error("AuthProfileLocksOneActiveIndex must be a UNIQUE index")
	}
	if !strings.Contains(AuthProfileLocksOneActiveIndex, "auth_profile_id") {
		t.Error("AuthProfileLocksOneActiveIndex missing auth_profile_id")
	}
	if !strings.Contains(AuthProfileLocksOneActiveIndex, "run_id") {
		t.Error("AuthProfileLocksOneActiveIndex missing run_id")
	}
	if !strings.Contains(AuthProfileLocksOneActiveIndex, "released_at IS NULL") {
		t.Error("AuthProfileLocksOneActiveIndex must filter on released_at IS NULL for active-only constraint")
	}
}

func TestAuthProfileLock_OptionalFields(t *testing.T) {
	l := validAuthProfileLock()
	if l.ReleasedAt != nil {
		t.Error("ReleasedAt should be nil by default")
	}

	now := time.Now()
	l.ReleasedAt = &now
	if err := l.Validate(); err != nil {
		t.Fatalf("valid lock with released_at set: unexpected error: %v", err)
	}
}
