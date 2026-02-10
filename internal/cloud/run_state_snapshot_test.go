package cloud

import (
	"strings"
	"testing"
	"time"
)

func validRunStateSnapshot() RunStateSnapshot {
	return RunStateSnapshot{
		ID:              "snap-001",
		RunID:           "run-001",
		SnapshotKind:    SnapshotKindInput,
		Version:         1,
		SHA256:          "abc123def456",
		SizeBytes:       1024,
		ContentEncoding: "gzip",
		ContentBlob:     []byte("compressed-data"),
		CreatedAt:       time.Now(),
	}
}

func TestRunStateSnapshot_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(s *RunStateSnapshot)
		wantErr string
	}{
		{
			name:   "valid snapshot passes",
			modify: func(s *RunStateSnapshot) {},
		},
		{
			name:    "empty id",
			modify:  func(s *RunStateSnapshot) { s.ID = "" },
			wantErr: "run_state_snapshot.id must not be empty",
		},
		{
			name:    "empty run_id",
			modify:  func(s *RunStateSnapshot) { s.RunID = "" },
			wantErr: "run_state_snapshot.run_id must not be empty",
		},
		{
			name:    "invalid snapshot_kind",
			modify:  func(s *RunStateSnapshot) { s.SnapshotKind = "bogus" },
			wantErr: "run_state_snapshot.snapshot_kind \"bogus\" is not a valid kind",
		},
		{
			name:    "version zero",
			modify:  func(s *RunStateSnapshot) { s.Version = 0 },
			wantErr: "run_state_snapshot.version must be >= 1",
		},
		{
			name:    "negative version",
			modify:  func(s *RunStateSnapshot) { s.Version = -1 },
			wantErr: "run_state_snapshot.version must be >= 1",
		},
		{
			name:    "empty sha256",
			modify:  func(s *RunStateSnapshot) { s.SHA256 = "" },
			wantErr: "run_state_snapshot.sha256 must not be empty",
		},
		{
			name:    "negative size_bytes",
			modify:  func(s *RunStateSnapshot) { s.SizeBytes = -1 },
			wantErr: "run_state_snapshot.size_bytes must be >= 0",
		},
		{
			name:    "empty content_encoding",
			modify:  func(s *RunStateSnapshot) { s.ContentEncoding = "" },
			wantErr: "run_state_snapshot.content_encoding must not be empty",
		},
		{
			name: "valid with attempt_id set",
			modify: func(s *RunStateSnapshot) {
				aid := "attempt-001"
				s.AttemptID = &aid
			},
		},
		{
			name:   "valid checkpoint kind",
			modify: func(s *RunStateSnapshot) { s.SnapshotKind = SnapshotKindCheckpoint },
		},
		{
			name:   "valid final kind",
			modify: func(s *RunStateSnapshot) { s.SnapshotKind = SnapshotKindFinal },
		},
		{
			name:   "zero size_bytes is valid",
			modify: func(s *RunStateSnapshot) { s.SizeBytes = 0 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validRunStateSnapshot()
			tt.modify(&s)
			err := s.Validate()

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

func TestSnapshotKind_IsValid(t *testing.T) {
	tests := []struct {
		kind SnapshotKind
		want bool
	}{
		{SnapshotKindInput, true},
		{SnapshotKindCheckpoint, true},
		{SnapshotKindFinal, true},
		{"bogus", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			if got := tt.kind.IsValid(); got != tt.want {
				t.Errorf("SnapshotKind(%q).IsValid() = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}

func TestRunStateSnapshotsSchema_ContainsRequiredColumns(t *testing.T) {
	requiredColumns := []string{
		"id",
		"run_id",
		"attempt_id",
		"snapshot_kind",
		"version",
		"sha256",
		"size_bytes",
		"content_encoding",
		"content_blob",
		"created_at",
	}

	for _, col := range requiredColumns {
		if !strings.Contains(RunStateSnapshotsSchema, col) {
			t.Errorf("RunStateSnapshotsSchema missing column %q", col)
		}
	}
}

func TestRunStateSnapshotsSchema_ForeignKeys(t *testing.T) {
	fks := []string{
		"REFERENCES runs(id)",
		"REFERENCES attempts(id)",
	}
	for _, fk := range fks {
		if !strings.Contains(RunStateSnapshotsSchema, fk) {
			t.Errorf("RunStateSnapshotsSchema missing foreign key %q", fk)
		}
	}
}

func TestRunStateSnapshotsSchema_CheckConstraints(t *testing.T) {
	checks := []string{
		"CHECK (snapshot_kind IN ('input','checkpoint','final'))",
		"CHECK (version >= 1)",
	}
	for _, chk := range checks {
		if !strings.Contains(RunStateSnapshotsSchema, chk) {
			t.Errorf("RunStateSnapshotsSchema missing check constraint %q", chk)
		}
	}
}

func TestRunStateSnapshotsRunVersionUniqueIndex(t *testing.T) {
	if !strings.Contains(RunStateSnapshotsRunVersionUniqueIndex, "UNIQUE") {
		t.Error("RunStateSnapshotsRunVersionUniqueIndex must be a UNIQUE index")
	}
	if !strings.Contains(RunStateSnapshotsRunVersionUniqueIndex, "run_id") {
		t.Error("RunStateSnapshotsRunVersionUniqueIndex missing run_id")
	}
	if !strings.Contains(RunStateSnapshotsRunVersionUniqueIndex, "version") {
		t.Error("RunStateSnapshotsRunVersionUniqueIndex missing version")
	}
}

func TestRunStateSnapshotsRunIDCreatedAtIndex(t *testing.T) {
	if !strings.Contains(RunStateSnapshotsRunIDCreatedAtIndex, "run_id") {
		t.Error("RunStateSnapshotsRunIDCreatedAtIndex missing run_id")
	}
	if !strings.Contains(RunStateSnapshotsRunIDCreatedAtIndex, "created_at") {
		t.Error("RunStateSnapshotsRunIDCreatedAtIndex missing created_at")
	}
}

func TestRunStateSnapshot_OptionalFields(t *testing.T) {
	s := validRunStateSnapshot()
	if s.AttemptID != nil {
		t.Error("AttemptID should be nil by default")
	}

	aid := "attempt-001"
	s.AttemptID = &aid
	if err := s.Validate(); err != nil {
		t.Fatalf("valid snapshot with attempt_id set: unexpected error: %v", err)
	}
}
