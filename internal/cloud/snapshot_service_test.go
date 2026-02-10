package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// snapshotMockStore extends mockStore for snapshot service tests.
type snapshotMockStore struct {
	mockStore

	// GetRun tracking
	getRun    *Run
	getRunErr error

	// PutSnapshot tracking
	putSnapshotCalls []*RunStateSnapshot
	putSnapshotErr   error

	// UpdateRunSnapshotRefs tracking
	updateRefsCalls []updateRefsCall
	updateRefsErr   error

	// InsertEvent tracking
	insertedEvents []*Event
	insertEventErr error
}

type updateRefsCall struct {
	RunID                 string
	InputSnapshotID       *string
	LatestSnapshotID      *string
	LatestSnapshotVersion int
}

func (s *snapshotMockStore) GetRun(_ context.Context, runID string) (*Run, error) {
	if s.getRunErr != nil {
		return nil, s.getRunErr
	}
	if s.getRun != nil {
		return s.getRun, nil
	}
	return nil, ErrNotFound
}

func (s *snapshotMockStore) PutSnapshot(_ context.Context, snapshot *RunStateSnapshot) error {
	s.putSnapshotCalls = append(s.putSnapshotCalls, snapshot)
	return s.putSnapshotErr
}

func (s *snapshotMockStore) UpdateRunSnapshotRefs(_ context.Context, runID string, inputSnapshotID, latestSnapshotID *string, latestSnapshotVersion int) error {
	s.updateRefsCalls = append(s.updateRefsCalls, updateRefsCall{
		RunID:                 runID,
		InputSnapshotID:       inputSnapshotID,
		LatestSnapshotID:      latestSnapshotID,
		LatestSnapshotVersion: latestSnapshotVersion,
	})
	return s.updateRefsErr
}

func (s *snapshotMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

// validSnapshotRun returns a valid run with latest_snapshot_version set.
func validSnapshotRun(version int) *Run {
	now := time.Now().UTC().Truncate(time.Second)
	return &Run{
		ID:                    "run-001",
		Repo:                  "owner/repo",
		BaseBranch:            "main",
		Engine:                "claude",
		AuthProfileID:         "auth-001",
		ScopeRef:              "prd-001",
		Status:                RunStatusRunning,
		AttemptCount:          1,
		MaxAttempts:           3,
		LatestSnapshotVersion: version,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
}

func TestSnapshotRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *SnapshotRequest)
		wantErr string
	}{
		{
			name:    "valid_checkpoint",
			modify:  func(r *SnapshotRequest) {},
			wantErr: "",
		},
		{
			name:    "valid_final",
			modify:  func(r *SnapshotRequest) { r.Kind = SnapshotKindFinal },
			wantErr: "",
		},
		{
			name:    "empty_runID",
			modify:  func(r *SnapshotRequest) { r.RunID = "" },
			wantErr: "runID must not be empty",
		},
		{
			name:    "empty_attemptID",
			modify:  func(r *SnapshotRequest) { r.AttemptID = "" },
			wantErr: "attemptID must not be empty",
		},
		{
			name:    "invalid_kind_input",
			modify:  func(r *SnapshotRequest) { r.Kind = SnapshotKindInput },
			wantErr: "kind must be checkpoint or final",
		},
		{
			name:    "invalid_kind_empty",
			modify:  func(r *SnapshotRequest) { r.Kind = "" },
			wantErr: "kind must be checkpoint or final",
		},
		{
			name:    "empty_sha256",
			modify:  func(r *SnapshotRequest) { r.SHA256 = "" },
			wantErr: "sha256 must not be empty",
		},
		{
			name:    "empty_content_encoding",
			modify:  func(r *SnapshotRequest) { r.ContentEncoding = "" },
			wantErr: "contentEncoding must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &SnapshotRequest{
				RunID:           "run-001",
				AttemptID:       "att-001",
				Kind:            SnapshotKindCheckpoint,
				Content:         []byte("bundle-data"),
				SHA256:          "abc123def456",
				ContentEncoding: "application/gzip",
			}
			tt.modify(req)

			err := req.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestStoreSnapshot(t *testing.T) {
	t.Run("successful_checkpoint_first_snapshot", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(1), // input snapshot was version 1
		}

		idCounter := 0
		svc := NewSnapshotService(store, SnapshotServiceConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("id-%d", idCounter)
			},
		})

		result, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("checkpoint-data"),
			SHA256:          "sha256-checkpoint",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Version should be input_version + 1.
		if result.Version != 2 {
			t.Errorf("Version = %d, want 2", result.Version)
		}
		if result.SnapshotID != "id-1" {
			t.Errorf("SnapshotID = %q, want %q", result.SnapshotID, "id-1")
		}

		// Verify PutSnapshot was called correctly.
		if len(store.putSnapshotCalls) != 1 {
			t.Fatalf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
		}
		snap := store.putSnapshotCalls[0]
		if snap.ID != "id-1" {
			t.Errorf("snapshot.ID = %q, want %q", snap.ID, "id-1")
		}
		if snap.RunID != "run-001" {
			t.Errorf("snapshot.RunID = %q, want %q", snap.RunID, "run-001")
		}
		if snap.AttemptID == nil || *snap.AttemptID != "att-001" {
			t.Errorf("snapshot.AttemptID = %v, want %q", snap.AttemptID, "att-001")
		}
		if snap.SnapshotKind != SnapshotKindCheckpoint {
			t.Errorf("snapshot.Kind = %q, want %q", snap.SnapshotKind, SnapshotKindCheckpoint)
		}
		if snap.Version != 2 {
			t.Errorf("snapshot.Version = %d, want 2", snap.Version)
		}
		if snap.SHA256 != "sha256-checkpoint" {
			t.Errorf("snapshot.SHA256 = %q, want %q", snap.SHA256, "sha256-checkpoint")
		}
		if snap.SizeBytes != int64(len("checkpoint-data")) {
			t.Errorf("snapshot.SizeBytes = %d, want %d", snap.SizeBytes, len("checkpoint-data"))
		}
		if snap.ContentEncoding != "application/gzip" {
			t.Errorf("snapshot.ContentEncoding = %q, want %q", snap.ContentEncoding, "application/gzip")
		}
		if string(snap.ContentBlob) != "checkpoint-data" {
			t.Errorf("snapshot.ContentBlob = %q, want %q", string(snap.ContentBlob), "checkpoint-data")
		}

		// Verify UpdateRunSnapshotRefs was called correctly.
		if len(store.updateRefsCalls) != 1 {
			t.Fatalf("UpdateRunSnapshotRefs calls = %d, want 1", len(store.updateRefsCalls))
		}
		refs := store.updateRefsCalls[0]
		if refs.RunID != "run-001" {
			t.Errorf("refs.RunID = %q, want %q", refs.RunID, "run-001")
		}
		if refs.InputSnapshotID != nil {
			t.Errorf("refs.InputSnapshotID = %v, want nil (checkpoint does not update input)", refs.InputSnapshotID)
		}
		if refs.LatestSnapshotID == nil || *refs.LatestSnapshotID != "id-1" {
			t.Errorf("refs.LatestSnapshotID = %v, want %q", refs.LatestSnapshotID, "id-1")
		}
		if refs.LatestSnapshotVersion != 2 {
			t.Errorf("refs.LatestSnapshotVersion = %d, want 2", refs.LatestSnapshotVersion)
		}

		// Verify snapshot_stored event was emitted.
		if len(store.insertedEvents) != 1 {
			t.Fatalf("insertedEvents = %d, want 1", len(store.insertedEvents))
		}
		evt := store.insertedEvents[0]
		if evt.EventType != "snapshot_stored" {
			t.Errorf("event type = %q, want %q", evt.EventType, "snapshot_stored")
		}
		if evt.RunID != "run-001" {
			t.Errorf("event run_id = %q, want %q", evt.RunID, "run-001")
		}
		if evt.AttemptID == nil || *evt.AttemptID != "att-001" {
			t.Errorf("event attempt_id = %v, want %q", evt.AttemptID, "att-001")
		}
		if evt.PayloadJSON != nil {
			var payload snapshotEventPayload
			if err := json.Unmarshal([]byte(*evt.PayloadJSON), &payload); err != nil {
				t.Fatalf("payload unmarshal: %v", err)
			}
			if payload.Kind != "checkpoint" {
				t.Errorf("payload kind = %q, want %q", payload.Kind, "checkpoint")
			}
			if payload.Version != 2 {
				t.Errorf("payload version = %d, want 2", payload.Version)
			}
			if payload.SHA256 != "sha256-checkpoint" {
				t.Errorf("payload sha256 = %q, want %q", payload.SHA256, "sha256-checkpoint")
			}
		} else {
			t.Error("event payload_json is nil")
		}
	})

	t.Run("successful_final_snapshot", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(3), // 3 previous snapshots
		}

		idCounter := 0
		svc := NewSnapshotService(store, SnapshotServiceConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("final-%d", idCounter)
			},
		})

		result, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindFinal,
			Content:         []byte("final-state"),
			SHA256:          "sha256-final",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Version != 4 {
			t.Errorf("Version = %d, want 4", result.Version)
		}
		if result.SnapshotID != "final-1" {
			t.Errorf("SnapshotID = %q, want %q", result.SnapshotID, "final-1")
		}

		// Verify snapshot kind is final.
		if len(store.putSnapshotCalls) != 1 {
			t.Fatalf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
		}
		if store.putSnapshotCalls[0].SnapshotKind != SnapshotKindFinal {
			t.Errorf("snapshot kind = %q, want %q", store.putSnapshotCalls[0].SnapshotKind, SnapshotKindFinal)
		}
	})

	t.Run("version_monotonically_increases", func(t *testing.T) {
		currentVersion := 0
		store := &snapshotMockStore{
			getRun: validSnapshotRun(0), // no snapshots yet (0 means none)
		}

		idCounter := 0
		svc := NewSnapshotService(store, SnapshotServiceConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("snap-%d", idCounter)
			},
		})

		// First checkpoint: version should be 1.
		result1, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data1"),
			SHA256:          "sha256-1",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("snapshot 1: %v", err)
		}
		if result1.Version != 1 {
			t.Errorf("snapshot 1 version = %d, want 1", result1.Version)
		}

		// Simulate run now has version 1.
		currentVersion = 1
		store.getRun = validSnapshotRun(currentVersion)
		store.putSnapshotCalls = nil
		store.updateRefsCalls = nil
		store.insertedEvents = nil

		// Second checkpoint: version should be 2.
		result2, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data2"),
			SHA256:          "sha256-2",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("snapshot 2: %v", err)
		}
		if result2.Version != 2 {
			t.Errorf("snapshot 2 version = %d, want 2", result2.Version)
		}

		// Simulate run now has version 2.
		currentVersion = 2
		store.getRun = validSnapshotRun(currentVersion)
		store.putSnapshotCalls = nil
		store.updateRefsCalls = nil
		store.insertedEvents = nil

		// Final: version should be 3.
		result3, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindFinal,
			Content:         []byte("data3"),
			SHA256:          "sha256-3",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("snapshot 3: %v", err)
		}
		if result3.Version != 3 {
			t.Errorf("snapshot 3 version = %d, want 3", result3.Version)
		}
		_ = currentVersion
	})

	t.Run("get_run_failure", func(t *testing.T) {
		store := &snapshotMockStore{
			getRunErr: fmt.Errorf("db connection lost"),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err == nil || !strings.Contains(err.Error(), "failed to get run") {
			t.Errorf("expected get run error, got: %v", err)
		}

		// No snapshot or refs should be created.
		if len(store.putSnapshotCalls) != 0 {
			t.Errorf("PutSnapshot calls = %d, want 0", len(store.putSnapshotCalls))
		}
	})

	t.Run("get_run_not_found", func(t *testing.T) {
		store := &snapshotMockStore{
			getRunErr: ErrNotFound,
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-missing",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err == nil || !strings.Contains(err.Error(), "failed to get run") {
			t.Errorf("expected get run error, got: %v", err)
		}
	})

	t.Run("put_snapshot_failure", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun:         validSnapshotRun(1),
			putSnapshotErr: fmt.Errorf("db write failed"),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err == nil || !strings.Contains(err.Error(), "failed to store snapshot") {
			t.Errorf("expected store snapshot error, got: %v", err)
		}

		// No refs update should occur.
		if len(store.updateRefsCalls) != 0 {
			t.Errorf("UpdateRunSnapshotRefs calls = %d, want 0", len(store.updateRefsCalls))
		}
	})

	t.Run("put_snapshot_version_conflict", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun:         validSnapshotRun(1),
			putSnapshotErr: ErrConflict,
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err == nil || !strings.Contains(err.Error(), "failed to store snapshot") {
			t.Errorf("expected store snapshot error, got: %v", err)
		}
	})

	t.Run("update_refs_failure", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun:        validSnapshotRun(1),
			updateRefsErr: fmt.Errorf("db write failed"),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err == nil || !strings.Contains(err.Error(), "failed to update run snapshot refs") {
			t.Errorf("expected update refs error, got: %v", err)
		}

		// Snapshot was stored but refs update failed — snapshot exists.
		if len(store.putSnapshotCalls) != 1 {
			t.Errorf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
		}
	})

	t.Run("event_failure_does_not_block", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun:         validSnapshotRun(1),
			insertEventErr: fmt.Errorf("event insert failed"),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		result, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Version != 2 {
			t.Errorf("Version = %d, want 2", result.Version)
		}

		// Snapshot and refs should still succeed.
		if len(store.putSnapshotCalls) != 1 {
			t.Errorf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
		}
		if len(store.updateRefsCalls) != 1 {
			t.Errorf("UpdateRunSnapshotRefs calls = %d, want 1", len(store.updateRefsCalls))
		}
	})

	t.Run("nil_IDFunc_uses_empty_ids", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(1),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		result, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.SnapshotID != "" {
			t.Errorf("SnapshotID = %q, want empty (nil IDFunc)", result.SnapshotID)
		}

		// Verify event ID is also empty.
		if len(store.insertedEvents) != 1 {
			t.Fatalf("insertedEvents = %d, want 1", len(store.insertedEvents))
		}
		if store.insertedEvents[0].ID != "" {
			t.Errorf("event ID = %q, want empty", store.insertedEvents[0].ID)
		}
	})

	t.Run("IDFunc_generates_unique_ids", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(1),
		}

		idCounter := 0
		svc := NewSnapshotService(store, SnapshotServiceConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("custom-%d", idCounter)
			},
		})

		result, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// First ID call is for the snapshot.
		if result.SnapshotID != "custom-1" {
			t.Errorf("SnapshotID = %q, want %q", result.SnapshotID, "custom-1")
		}

		// Second ID call is for the event.
		if len(store.insertedEvents) != 1 {
			t.Fatalf("insertedEvents = %d, want 1", len(store.insertedEvents))
		}
		if store.insertedEvents[0].ID != "custom-2" {
			t.Errorf("event ID = %q, want %q", store.insertedEvents[0].ID, "custom-2")
		}
	})

	t.Run("content_size_bytes_computed_from_content", func(t *testing.T) {
		content := []byte("0123456789abcdef") // 16 bytes
		store := &snapshotMockStore{
			getRun: validSnapshotRun(0),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         content,
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(store.putSnapshotCalls) != 1 {
			t.Fatalf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
		}
		if store.putSnapshotCalls[0].SizeBytes != 16 {
			t.Errorf("SizeBytes = %d, want 16", store.putSnapshotCalls[0].SizeBytes)
		}
	})

	t.Run("empty_content_has_zero_size", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(0),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte{},
			SHA256:          "sha256-empty",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if store.putSnapshotCalls[0].SizeBytes != 0 {
			t.Errorf("SizeBytes = %d, want 0", store.putSnapshotCalls[0].SizeBytes)
		}
	})

	t.Run("updates_only_latest_not_input", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(1),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{
			IDFunc: func() string { return "snap-id" },
		})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		refs := store.updateRefsCalls[0]
		// input_snapshot_id should be nil (not updated by checkpoint/final).
		if refs.InputSnapshotID != nil {
			t.Errorf("InputSnapshotID = %v, want nil", refs.InputSnapshotID)
		}
		// latest_snapshot_id should be set.
		if refs.LatestSnapshotID == nil || *refs.LatestSnapshotID != "snap-id" {
			t.Errorf("LatestSnapshotID = %v, want %q", refs.LatestSnapshotID, "snap-id")
		}
	})

	t.Run("final_snapshot_same_pattern", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(5),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{
			IDFunc: func() string { return "final-snap" },
		})

		result, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindFinal,
			Content:         []byte("final-data"),
			SHA256:          "sha256-final",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Version != 6 {
			t.Errorf("Version = %d, want 6", result.Version)
		}

		snap := store.putSnapshotCalls[0]
		if snap.SnapshotKind != SnapshotKindFinal {
			t.Errorf("SnapshotKind = %q, want %q", snap.SnapshotKind, SnapshotKindFinal)
		}

		refs := store.updateRefsCalls[0]
		if refs.LatestSnapshotVersion != 6 {
			t.Errorf("LatestSnapshotVersion = %d, want 6", refs.LatestSnapshotVersion)
		}
	})

	t.Run("validation_errors_stop_early", func(t *testing.T) {
		store := &snapshotMockStore{}

		svc := NewSnapshotService(store, SnapshotServiceConfig{})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "",
			AttemptID:       "att-001",
			Kind:            SnapshotKindCheckpoint,
			Content:         []byte("data"),
			SHA256:          "sha256",
			ContentEncoding: "application/gzip",
		})
		if err == nil || !strings.Contains(err.Error(), "runID must not be empty") {
			t.Errorf("expected validation error, got: %v", err)
		}

		// No store calls should be made.
		if len(store.putSnapshotCalls) != 0 {
			t.Errorf("PutSnapshot calls = %d, want 0", len(store.putSnapshotCalls))
		}
	})

	t.Run("defaults", func(t *testing.T) {
		store := &snapshotMockStore{}
		svc := NewSnapshotService(store, SnapshotServiceConfig{})
		if svc.store == nil {
			t.Error("store is nil")
		}
	})

	t.Run("snapshot_event_payload_structure", func(t *testing.T) {
		store := &snapshotMockStore{
			getRun: validSnapshotRun(2),
		}

		svc := NewSnapshotService(store, SnapshotServiceConfig{
			IDFunc: func() string { return "test-id" },
		})

		_, err := svc.StoreSnapshot(context.Background(), &SnapshotRequest{
			RunID:           "run-001",
			AttemptID:       "att-001",
			Kind:            SnapshotKindFinal,
			Content:         []byte("final-content"),
			SHA256:          "sha256-value",
			ContentEncoding: "application/gzip",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(store.insertedEvents) != 1 {
			t.Fatalf("insertedEvents = %d, want 1", len(store.insertedEvents))
		}

		evt := store.insertedEvents[0]
		if evt.PayloadJSON == nil {
			t.Fatal("event payload_json is nil")
		}

		var payload snapshotEventPayload
		if err := json.Unmarshal([]byte(*evt.PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}

		if payload.SnapshotID != "test-id" {
			t.Errorf("payload snapshot_id = %q, want %q", payload.SnapshotID, "test-id")
		}
		if payload.RunID != "run-001" {
			t.Errorf("payload run_id = %q, want %q", payload.RunID, "run-001")
		}
		if payload.Kind != "final" {
			t.Errorf("payload kind = %q, want %q", payload.Kind, "final")
		}
		if payload.Version != 3 {
			t.Errorf("payload version = %d, want 3", payload.Version)
		}
		if payload.SHA256 != "sha256-value" {
			t.Errorf("payload sha256 = %q, want %q", payload.SHA256, "sha256-value")
		}
		if payload.SizeBytes != int64(len("final-content")) {
			t.Errorf("payload size_bytes = %d, want %d", payload.SizeBytes, len("final-content"))
		}
	})
}
