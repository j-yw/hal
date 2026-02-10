package cloud

import (
	"strings"
	"testing"
	"time"
)

func TestRunStatus_IsValid(t *testing.T) {
	tests := []struct {
		status RunStatus
		want   bool
	}{
		{RunStatusQueued, true},
		{RunStatusClaimed, true},
		{RunStatusRunning, true},
		{RunStatusRetrying, true},
		{RunStatusSucceeded, true},
		{RunStatusFailed, true},
		{RunStatusCanceled, true},
		{"", false},
		{"invalid", false},
		{"QUEUED", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsValid()
			if got != tt.want {
				t.Errorf("RunStatus(%q).IsValid() = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestRunStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status   RunStatus
		terminal bool
	}{
		{RunStatusQueued, false},
		{RunStatusClaimed, false},
		{RunStatusRunning, false},
		{RunStatusRetrying, false},
		{RunStatusSucceeded, true},
		{RunStatusFailed, true},
		{RunStatusCanceled, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsTerminal()
			if got != tt.terminal {
				t.Errorf("RunStatus(%q).IsTerminal() = %v, want %v", tt.status, got, tt.terminal)
			}
		})
	}
}

func TestRunStatus_ExhaustiveSet(t *testing.T) {
	expected := []RunStatus{
		RunStatusQueued,
		RunStatusClaimed,
		RunStatusRunning,
		RunStatusRetrying,
		RunStatusSucceeded,
		RunStatusFailed,
		RunStatusCanceled,
	}

	if len(validRunStatuses) != len(expected) {
		t.Fatalf("validRunStatuses has %d entries, expected %d", len(validRunStatuses), len(expected))
	}

	for _, s := range expected {
		if !validRunStatuses[s] {
			t.Errorf("expected status %q in validRunStatuses", s)
		}
	}
}

func validRun() Run {
	now := time.Now()
	return Run{
		ID:            "run-001",
		Repo:          "owner/repo",
		BaseBranch:    "main",
		Engine:        "claude",
		AuthProfileID: "auth-001",
		ScopeRef:      "prd-001",
		Status:        RunStatusQueued,
		AttemptCount:  0,
		MaxAttempts:   3,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestRun_Validate(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(r *Run)
		wantErr   string
	}{
		{
			name:   "valid run passes",
			modify: func(r *Run) {},
		},
		{
			name:    "empty id",
			modify:  func(r *Run) { r.ID = "" },
			wantErr: "run.id must not be empty",
		},
		{
			name:    "empty repo",
			modify:  func(r *Run) { r.Repo = "" },
			wantErr: "run.repo must not be empty",
		},
		{
			name:    "empty base_branch",
			modify:  func(r *Run) { r.BaseBranch = "" },
			wantErr: "run.base_branch must not be empty",
		},
		{
			name:    "empty engine",
			modify:  func(r *Run) { r.Engine = "" },
			wantErr: "run.engine must not be empty",
		},
		{
			name:    "empty auth_profile_id",
			modify:  func(r *Run) { r.AuthProfileID = "" },
			wantErr: "run.auth_profile_id must not be empty",
		},
		{
			name:    "empty scope_ref",
			modify:  func(r *Run) { r.ScopeRef = "" },
			wantErr: "run.scope_ref must not be empty",
		},
		{
			name:    "invalid status",
			modify:  func(r *Run) { r.Status = "bogus" },
			wantErr: `run.status "bogus" is not a valid status`,
		},
		{
			name:    "max_attempts zero",
			modify:  func(r *Run) { r.MaxAttempts = 0 },
			wantErr: "run.max_attempts must be >= 1",
		},
		{
			name:    "max_attempts negative",
			modify:  func(r *Run) { r.MaxAttempts = -1 },
			wantErr: "run.max_attempts must be >= 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRun()
			tt.modify(&r)
			err := r.Validate()

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

func TestRunsSchema_ContainsRequiredColumns(t *testing.T) {
	requiredColumns := []string{
		"id",
		"repo",
		"base_branch",
		"engine",
		"auth_profile_id",
		"scope_ref",
		"status",
		"attempt_count",
		"max_attempts",
		"deadline_at",
		"input_snapshot_id",
		"latest_snapshot_id",
		"latest_snapshot_version",
		"created_at",
		"updated_at",
	}

	for _, col := range requiredColumns {
		if !strings.Contains(RunsSchema, col) {
			t.Errorf("RunsSchema missing column %q", col)
		}
	}
}

func TestRunsSchema_StatusConstraint(t *testing.T) {
	statuses := []string{
		"queued", "claimed", "running", "retrying",
		"succeeded", "failed", "canceled",
	}
	for _, s := range statuses {
		if !strings.Contains(RunsSchema, "'"+s+"'") {
			t.Errorf("RunsSchema CHECK constraint missing status %q", s)
		}
	}
}

func TestRunsQueueIndex_Format(t *testing.T) {
	if !strings.Contains(RunsQueueIndex, "idx_runs_queue") {
		t.Error("RunsQueueIndex missing index name idx_runs_queue")
	}
	if !strings.Contains(RunsQueueIndex, "status") {
		t.Error("RunsQueueIndex missing status column")
	}
	if !strings.Contains(RunsQueueIndex, "created_at") {
		t.Error("RunsQueueIndex missing created_at column")
	}
}

func TestRun_OptionalFields(t *testing.T) {
	r := validRun()
	if r.DeadlineAt != nil {
		t.Error("DeadlineAt should be nil by default")
	}
	if r.InputSnapshotID != nil {
		t.Error("InputSnapshotID should be nil by default")
	}
	if r.LatestSnapshotID != nil {
		t.Error("LatestSnapshotID should be nil by default")
	}

	now := time.Now()
	sid := "snap-001"
	r.DeadlineAt = &now
	r.InputSnapshotID = &sid
	r.LatestSnapshotID = &sid

	if err := r.Validate(); err != nil {
		t.Fatalf("valid run with optional fields set: unexpected error: %v", err)
	}
}
