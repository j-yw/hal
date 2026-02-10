package cloud

import (
	"strings"
	"testing"
	"time"
)

func TestAttemptStatus_IsValid(t *testing.T) {
	tests := []struct {
		status AttemptStatus
		want   bool
	}{
		{AttemptStatusActive, true},
		{AttemptStatusSucceeded, true},
		{AttemptStatusFailed, true},
		{AttemptStatusCanceled, true},
		{"", false},
		{"invalid", false},
		{"ACTIVE", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsValid()
			if got != tt.want {
				t.Errorf("AttemptStatus(%q).IsValid() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestAttemptStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status   AttemptStatus
		terminal bool
	}{
		{AttemptStatusActive, false},
		{AttemptStatusSucceeded, true},
		{AttemptStatusFailed, true},
		{AttemptStatusCanceled, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsTerminal()
			if got != tt.terminal {
				t.Errorf("AttemptStatus(%q).IsTerminal() = %v, want %v", tt.status, got, tt.terminal)
			}
		})
	}
}

func TestAttemptStatus_ExhaustiveSet(t *testing.T) {
	expected := []AttemptStatus{
		AttemptStatusActive,
		AttemptStatusSucceeded,
		AttemptStatusFailed,
		AttemptStatusCanceled,
	}

	if len(validAttemptStatuses) != len(expected) {
		t.Fatalf("validAttemptStatuses has %d entries, expected %d", len(validAttemptStatuses), len(expected))
	}

	for _, s := range expected {
		if !validAttemptStatuses[s] {
			t.Errorf("expected status %q in validAttemptStatuses", s)
		}
	}
}

func validAttempt() Attempt {
	now := time.Now()
	return Attempt{
		ID:             "attempt-001",
		RunID:          "run-001",
		AttemptNumber:  1,
		WorkerID:       "worker-001",
		Status:         AttemptStatusActive,
		StartedAt:      now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(5 * time.Minute),
	}
}

func TestAttempt_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(a *Attempt)
		wantErr string
	}{
		{
			name:   "valid attempt passes",
			modify: func(a *Attempt) {},
		},
		{
			name:    "empty id",
			modify:  func(a *Attempt) { a.ID = "" },
			wantErr: "attempt.id must not be empty",
		},
		{
			name:    "empty run_id",
			modify:  func(a *Attempt) { a.RunID = "" },
			wantErr: "attempt.run_id must not be empty",
		},
		{
			name:    "attempt_number zero",
			modify:  func(a *Attempt) { a.AttemptNumber = 0 },
			wantErr: "attempt.attempt_number must be >= 1",
		},
		{
			name:    "attempt_number negative",
			modify:  func(a *Attempt) { a.AttemptNumber = -1 },
			wantErr: "attempt.attempt_number must be >= 1",
		},
		{
			name:    "empty worker_id",
			modify:  func(a *Attempt) { a.WorkerID = "" },
			wantErr: "attempt.worker_id must not be empty",
		},
		{
			name:    "invalid status",
			modify:  func(a *Attempt) { a.Status = "bogus" },
			wantErr: `attempt.status "bogus" is not a valid status`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validAttempt()
			tt.modify(&a)
			err := a.Validate()

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

func TestAttemptsSchema_ContainsRequiredColumns(t *testing.T) {
	requiredColumns := []string{
		"id",
		"run_id",
		"attempt_number",
		"worker_id",
		"sandbox_id",
		"status",
		"started_at",
		"heartbeat_at",
		"lease_expires_at",
		"ended_at",
		"error_code",
		"error_message",
	}

	for _, col := range requiredColumns {
		if !strings.Contains(AttemptsSchema, col) {
			t.Errorf("AttemptsSchema missing column %q", col)
		}
	}
}

func TestAttemptsSchema_StatusConstraint(t *testing.T) {
	statuses := []string{"active", "succeeded", "failed", "canceled"}
	for _, s := range statuses {
		if !strings.Contains(AttemptsSchema, "'"+s+"'") {
			t.Errorf("AttemptsSchema CHECK constraint missing status %q", s)
		}
	}
}

func TestAttemptsSchema_RunIDForeignKey(t *testing.T) {
	if !strings.Contains(AttemptsSchema, "REFERENCES runs(id)") {
		t.Error("AttemptsSchema missing foreign key reference to runs(id)")
	}
}

func TestAttemptsIndexes(t *testing.T) {
	tests := []struct {
		name  string
		index string
		want  []string
	}{
		{
			name:  "run_id index",
			index: AttemptsRunIDIndex,
			want:  []string{"idx_attempts_run_id", "run_id"},
		},
		{
			name:  "status index",
			index: AttemptsStatusIndex,
			want:  []string{"idx_attempts_status", "status"},
		},
		{
			name:  "lease_expires_at index",
			index: AttemptsLeaseIndex,
			want:  []string{"idx_attempts_lease_expires_at", "lease_expires_at"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, w := range tt.want {
				if !strings.Contains(tt.index, w) {
					t.Errorf("index DDL missing %q", w)
				}
			}
		})
	}
}

func TestAttemptsOneActiveIndex(t *testing.T) {
	if !strings.Contains(AttemptsOneActiveIndex, "UNIQUE") {
		t.Error("AttemptsOneActiveIndex must be a UNIQUE index")
	}
	if !strings.Contains(AttemptsOneActiveIndex, "run_id") {
		t.Error("AttemptsOneActiveIndex missing run_id column")
	}
	if !strings.Contains(AttemptsOneActiveIndex, "WHERE status = 'active'") {
		t.Error("AttemptsOneActiveIndex missing partial index filter on active status")
	}
}

func TestAttempt_OptionalFields(t *testing.T) {
	a := validAttempt()
	if a.SandboxID != nil {
		t.Error("SandboxID should be nil by default")
	}
	if a.EndedAt != nil {
		t.Error("EndedAt should be nil by default")
	}
	if a.ErrorCode != nil {
		t.Error("ErrorCode should be nil by default")
	}
	if a.ErrorMessage != nil {
		t.Error("ErrorMessage should be nil by default")
	}

	now := time.Now()
	sid := "sandbox-001"
	errCode := "stale_attempt"
	errMsg := "lease expired"
	a.SandboxID = &sid
	a.EndedAt = &now
	a.ErrorCode = &errCode
	a.ErrorMessage = &errMsg

	if err := a.Validate(); err != nil {
		t.Fatalf("valid attempt with optional fields set: unexpected error: %v", err)
	}
}
