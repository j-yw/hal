package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// SnapshotServiceConfig holds configuration for the snapshot service.
type SnapshotServiceConfig struct {
	// IDFunc generates unique IDs for snapshots and events. If nil, IDs will be empty.
	IDFunc func() string
}

// SnapshotService manages run state snapshot persistence. It stores checkpoint
// snapshots after completed story transitions and final snapshots on terminal
// states (succeeded, failed, canceled). Snapshot versions increase monotonically
// per run.
type SnapshotService struct {
	store  Store
	config SnapshotServiceConfig
}

// NewSnapshotService creates a new SnapshotService with the given store and config.
func NewSnapshotService(store Store, config SnapshotServiceConfig) *SnapshotService {
	return &SnapshotService{
		store:  store,
		config: config,
	}
}

// SnapshotRequest contains the parameters for storing a state snapshot.
type SnapshotRequest struct {
	// RunID is the run this snapshot belongs to.
	RunID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// Kind is the snapshot kind (checkpoint or final).
	Kind SnapshotKind
	// Content is the compressed bundle content.
	Content []byte
	// SHA256 is the hash of the bundle content.
	SHA256 string
	// ContentEncoding is the encoding of the content (e.g., "application/gzip").
	ContentEncoding string
}

// Validate checks required fields on SnapshotRequest.
func (r *SnapshotRequest) Validate() error {
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.Kind != SnapshotKindCheckpoint && r.Kind != SnapshotKindFinal {
		return fmt.Errorf("kind must be checkpoint or final, got %q", r.Kind)
	}
	if r.SHA256 == "" {
		return fmt.Errorf("sha256 must not be empty")
	}
	if r.ContentEncoding == "" {
		return fmt.Errorf("contentEncoding must not be empty")
	}
	return nil
}

// SnapshotResult holds the outcome of a snapshot storage operation.
type SnapshotResult struct {
	// SnapshotID is the ID of the stored snapshot.
	SnapshotID string
	// Version is the monotonically increasing version number assigned.
	Version int
}

// snapshotEventPayload is the JSON payload for snapshot lifecycle events.
type snapshotEventPayload struct {
	SnapshotID string `json:"snapshot_id"`
	RunID      string `json:"run_id"`
	Kind       string `json:"kind"`
	Version    int    `json:"version"`
	SHA256     string `json:"sha256,omitempty"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	Error      string `json:"error,omitempty"`
}

// StoreSnapshot persists a checkpoint or final state snapshot for a run. It
// resolves the next monotonic version from the run's current latest_snapshot_version,
// stores the snapshot, updates the run's latest_snapshot_id and latest_snapshot_version,
// and emits a snapshot_stored event.
func (s *SnapshotService) StoreSnapshot(ctx context.Context, req *SnapshotRequest) (*SnapshotResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// Step 1: Get the current run to determine next version.
	run, err := s.store.GetRun(ctx, req.RunID)
	if err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}

	nextVersion := run.LatestSnapshotVersion + 1

	// Step 2: Generate snapshot ID.
	snapshotID := ""
	if s.config.IDFunc != nil {
		snapshotID = s.config.IDFunc()
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 3: Build and store the snapshot.
	snapshot := &RunStateSnapshot{
		ID:              snapshotID,
		RunID:           req.RunID,
		AttemptID:       &req.AttemptID,
		SnapshotKind:    req.Kind,
		Version:         nextVersion,
		SHA256:          req.SHA256,
		SizeBytes:       int64(len(req.Content)),
		ContentEncoding: req.ContentEncoding,
		ContentBlob:     req.Content,
		CreatedAt:       now,
	}

	if err := s.store.PutSnapshot(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("failed to store snapshot: %w", err)
	}

	// Step 4: Update run's latest snapshot references.
	if err := s.store.UpdateRunSnapshotRefs(ctx, req.RunID, nil, &snapshotID, nextVersion); err != nil {
		return nil, fmt.Errorf("failed to update run snapshot refs: %w", err)
	}

	// Step 5: Emit snapshot_stored event (best-effort).
	payload := &snapshotEventPayload{
		SnapshotID: snapshotID,
		RunID:      req.RunID,
		Kind:       string(req.Kind),
		Version:    nextVersion,
		SHA256:     req.SHA256,
		SizeBytes:  int64(len(req.Content)),
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "snapshot_stored", payload, now)

	return &SnapshotResult{
		SnapshotID: snapshotID,
		Version:    nextVersion,
	}, nil
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block snapshot operations.
func (s *SnapshotService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *snapshotEventPayload, now time.Time) {
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}

	var payloadJSON *string
	if payload != nil {
		data, err := json.Marshal(payload)
		if err == nil {
			str := string(data)
			payloadJSON = &str
		}
	}

	redacted, wasRedacted := redactPayload(payloadJSON)

	event := &Event{
		ID:          eventID,
		RunID:       runID,
		AttemptID:   &attemptID,
		EventType:   eventType,
		PayloadJSON: redacted,
		Redacted:    wasRedacted,
		CreatedAt:   now,
	}
	_ = s.store.InsertEvent(ctx, event)
}
