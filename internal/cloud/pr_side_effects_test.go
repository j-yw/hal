package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// --- mock store for PR side effect tests ---

type prSideEffectMockStore struct {
	mockStore
	putIdempotencyKeyFn func(ctx context.Context, key *IdempotencyKey) error
	getIdempotencyKeyFn func(ctx context.Context, key string) (*IdempotencyKey, error)
	insertEventFn       func(ctx context.Context, event *Event) error
	events              []*Event
}

func (m *prSideEffectMockStore) PutIdempotencyKey(ctx context.Context, key *IdempotencyKey) error {
	if m.putIdempotencyKeyFn != nil {
		return m.putIdempotencyKeyFn(ctx, key)
	}
	return nil
}

func (m *prSideEffectMockStore) GetIdempotencyKey(ctx context.Context, key string) (*IdempotencyKey, error) {
	if m.getIdempotencyKeyFn != nil {
		return m.getIdempotencyKeyFn(ctx, key)
	}
	return nil, ErrNotFound
}

func (m *prSideEffectMockStore) InsertEvent(ctx context.Context, event *Event) error {
	m.events = append(m.events, event)
	if m.insertEventFn != nil {
		return m.insertEventFn(ctx, event)
	}
	return nil
}

// --- helpers ---

func validPRUpdateRequest() *PRUpdateRequest {
	return &PRUpdateRequest{
		RunID:     "run-1",
		AttemptID: "attempt-1",
		PRRef:     "https://github.com/owner/repo/pull/42",
		Title:     "Updated title",
		Body:      "Updated body",
		Repo:      "owner/repo",
	}
}

func validPRCommentRequest() *PRCommentRequest {
	return &PRCommentRequest{
		RunID:     "run-1",
		AttemptID: "attempt-1",
		PRRef:     "https://github.com/owner/repo/pull/42",
		Body:      "Run completed successfully",
		Repo:      "owner/repo",
	}
}

func sideEffectEventsByType(events []*Event, eventType string) []*Event {
	var result []*Event
	for _, e := range events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}

// ===================== PR Update Tests =====================

func TestPRUpdateRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *PRUpdateRequest)
		wantErr string
	}{
		{name: "valid", modify: func(r *PRUpdateRequest) {}},
		{name: "empty runID", modify: func(r *PRUpdateRequest) { r.RunID = "" }, wantErr: "runID must not be empty"},
		{name: "empty attemptID", modify: func(r *PRUpdateRequest) { r.AttemptID = "" }, wantErr: "attemptID must not be empty"},
		{name: "empty prRef", modify: func(r *PRUpdateRequest) { r.PRRef = "" }, wantErr: "prRef must not be empty"},
		{name: "empty repo", modify: func(r *PRUpdateRequest) { r.Repo = "" }, wantErr: "repo must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validPRUpdateRequest()
			tt.modify(req)
			err := req.Validate()
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

func TestUpdatePR(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRUpdateService(store, PRUpdateConfig{
			IDFunc: func() string { return "evt-1" },
		})

		var callCount int
		updater := func(ctx context.Context, req *PRUpdateRequest) error {
			callCount++
			return nil
		}

		result, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Updated {
			t.Error("expected Updated=true")
		}
		if callCount != 1 {
			t.Errorf("expected 1 updater call, got %d", callCount)
		}

		started := sideEffectEventsByType(store.events, "pr_update_started")
		if len(started) != 1 {
			t.Fatalf("expected 1 pr_update_started event, got %d", len(started))
		}
		completed := sideEffectEventsByType(store.events, "pr_update_completed")
		if len(completed) != 1 {
			t.Fatalf("expected 1 pr_update_completed event, got %d", len(completed))
		}

		var payload prSideEffectEventPayload
		if err := json.Unmarshal([]byte(*completed[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if payload.PRRef != "https://github.com/owner/repo/pull/42" {
			t.Errorf("payload PRRef=%q, want PR URL", payload.PRRef)
		}
	})

	t.Run("existing key returns without external call", func(t *testing.T) {
		storedRef := "https://github.com/owner/repo/pull/42"
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				return &IdempotencyKey{
					Key:            key,
					RunID:          "run-1",
					SideEffectType: sideEffectPRUpdate,
					ResultRef:      &storedRef,
				}, nil
			},
		}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		var callCount int
		updater := func(ctx context.Context, req *PRUpdateRequest) error {
			callCount++
			return nil
		}

		result, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Updated {
			t.Error("expected Updated=false for reused key")
		}
		if callCount != 0 {
			t.Errorf("expected 0 updater calls (reused), got %d", callCount)
		}

		reused := sideEffectEventsByType(store.events, "pr_update_reused")
		if len(reused) != 1 {
			t.Fatalf("expected 1 pr_update_reused event, got %d", len(reused))
		}
	})

	t.Run("retry verifies no duplicate update side effects", func(t *testing.T) {
		var updateCalls atomic.Int32
		var stored *IdempotencyKey
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				if stored != nil {
					return stored, nil
				}
				return nil, ErrNotFound
			},
			putIdempotencyKeyFn: func(_ context.Context, key *IdempotencyKey) error {
				stored = key
				return nil
			},
		}

		svc := NewPRUpdateService(store, PRUpdateConfig{
			IDFunc: func() string { return "evt" },
		})

		updater := func(ctx context.Context, req *PRUpdateRequest) error {
			updateCalls.Add(1)
			return nil
		}

		// First call — updates PR.
		result1, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("first call: unexpected error: %v", err)
		}
		if !result1.Updated {
			t.Error("first call: expected Updated=true")
		}

		// Second call — reuses stored key.
		result2, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("second call: unexpected error: %v", err)
		}
		if result2.Updated {
			t.Error("second call: expected Updated=false")
		}

		if updateCalls.Load() != 1 {
			t.Errorf("expected exactly 1 updater call, got %d", updateCalls.Load())
		}
	})

	t.Run("nil updater returns error", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		_, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), nil)
		if err == nil {
			t.Fatal("expected error for nil updater")
		}
		if !strings.Contains(err.Error(), "updater must not be nil") {
			t.Errorf("error %q does not mention nil updater", err.Error())
		}
	})

	t.Run("updater failure returns error", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		updater := func(ctx context.Context, req *PRUpdateRequest) error {
			return fmt.Errorf("GitHub API error")
		}

		_, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err == nil {
			t.Fatal("expected error for updater failure")
		}
		if !strings.Contains(err.Error(), "updating PR") {
			t.Errorf("error %q does not wrap updater error", err.Error())
		}

		failed := sideEffectEventsByType(store.events, "pr_update_failed")
		if len(failed) != 1 {
			t.Fatalf("expected 1 pr_update_failed event, got %d", len(failed))
		}
	})

	t.Run("get idempotency key error propagates", func(t *testing.T) {
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, _ string) (*IdempotencyKey, error) {
				return nil, fmt.Errorf("database unavailable")
			},
		}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		updater := func(ctx context.Context, req *PRUpdateRequest) error { return nil }

		_, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err == nil {
			t.Fatal("expected error for store failure")
		}
		if !strings.Contains(err.Error(), "checking idempotency key") {
			t.Errorf("error %q does not mention idempotency key check", err.Error())
		}
	})

	t.Run("put idempotency key error propagates", func(t *testing.T) {
		store := &prSideEffectMockStore{
			putIdempotencyKeyFn: func(_ context.Context, _ *IdempotencyKey) error {
				return fmt.Errorf("database write error")
			},
		}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		updater := func(ctx context.Context, req *PRUpdateRequest) error { return nil }

		_, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err == nil {
			t.Fatal("expected error for put failure")
		}
		if !strings.Contains(err.Error(), "storing idempotency key") {
			t.Errorf("error %q does not mention storing key", err.Error())
		}
	})

	t.Run("duplicate key race returns reused result", func(t *testing.T) {
		callCount := 0
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, _ string) (*IdempotencyKey, error) {
				callCount++
				if callCount == 1 {
					return nil, ErrNotFound
				}
				return nil, ErrNotFound // shouldn't be reached for update
			},
			putIdempotencyKeyFn: func(_ context.Context, _ *IdempotencyKey) error {
				return ErrDuplicateKey
			},
		}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		updater := func(ctx context.Context, req *PRUpdateRequest) error { return nil }

		result, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Updated {
			t.Error("expected Updated=false for race-recovered result")
		}
	})

	t.Run("event failure tolerance", func(t *testing.T) {
		store := &prSideEffectMockStore{
			insertEventFn: func(_ context.Context, _ *Event) error {
				return fmt.Errorf("event store down")
			},
		}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		updater := func(ctx context.Context, req *PRUpdateRequest) error { return nil }

		result, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("unexpected error (events are best-effort): %v", err)
		}
		if !result.Updated {
			t.Error("expected Updated=true")
		}
	})

	t.Run("IDFunc generates event IDs", func(t *testing.T) {
		var counter int
		store := &prSideEffectMockStore{}
		svc := NewPRUpdateService(store, PRUpdateConfig{
			IDFunc: func() string {
				counter++
				return fmt.Sprintf("evt-%d", counter)
			},
		})

		updater := func(ctx context.Context, req *PRUpdateRequest) error { return nil }

		_, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, e := range store.events {
			if e.ID == "" {
				t.Errorf("event %d has empty ID", i)
			}
		}
	})

	t.Run("nil IDFunc produces empty event IDs", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRUpdateService(store, PRUpdateConfig{})

		updater := func(ctx context.Context, req *PRUpdateRequest) error { return nil }

		_, err := svc.UpdatePR(context.Background(), validPRUpdateRequest(), updater)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, e := range store.events {
			if e.ID != "" {
				t.Errorf("event %d has non-empty ID %q with nil IDFunc", i, e.ID)
			}
		}
	})
}

func TestPRUpdateIdempotencyKey(t *testing.T) {
	key := prUpdateIdempotencyKey("run-abc")
	if key != "pr_update:run-abc" {
		t.Errorf("got key=%q, want %q", key, "pr_update:run-abc")
	}
}

func TestPRUpdateIdempotencyKeyDeterministic(t *testing.T) {
	key1 := prUpdateIdempotencyKey("run-1")
	key2 := prUpdateIdempotencyKey("run-1")
	if key1 != key2 {
		t.Errorf("idempotency key not deterministic: %q != %q", key1, key2)
	}
}

// ===================== PR Comment Tests =====================

func TestPRCommentRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *PRCommentRequest)
		wantErr string
	}{
		{name: "valid", modify: func(r *PRCommentRequest) {}},
		{name: "empty runID", modify: func(r *PRCommentRequest) { r.RunID = "" }, wantErr: "runID must not be empty"},
		{name: "empty attemptID", modify: func(r *PRCommentRequest) { r.AttemptID = "" }, wantErr: "attemptID must not be empty"},
		{name: "empty prRef", modify: func(r *PRCommentRequest) { r.PRRef = "" }, wantErr: "prRef must not be empty"},
		{name: "empty body", modify: func(r *PRCommentRequest) { r.Body = "" }, wantErr: "body must not be empty"},
		{name: "empty repo", modify: func(r *PRCommentRequest) { r.Repo = "" }, wantErr: "repo must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validPRCommentRequest()
			tt.modify(req)
			err := req.Validate()
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

func TestCommentPR(t *testing.T) {
	t.Run("successful comment", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRCommentService(store, PRCommentConfig{
			IDFunc: func() string { return "evt-1" },
		})

		var callCount int
		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			callCount++
			return "https://github.com/owner/repo/pull/42#issuecomment-123", nil
		}

		result, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Created {
			t.Error("expected Created=true")
		}
		if result.CommentRef != "https://github.com/owner/repo/pull/42#issuecomment-123" {
			t.Errorf("got CommentRef=%q, want comment URL", result.CommentRef)
		}
		if callCount != 1 {
			t.Errorf("expected 1 commenter call, got %d", callCount)
		}

		started := sideEffectEventsByType(store.events, "pr_comment_started")
		if len(started) != 1 {
			t.Fatalf("expected 1 pr_comment_started event, got %d", len(started))
		}
		completed := sideEffectEventsByType(store.events, "pr_comment_completed")
		if len(completed) != 1 {
			t.Fatalf("expected 1 pr_comment_completed event, got %d", len(completed))
		}

		var payload prSideEffectEventPayload
		if err := json.Unmarshal([]byte(*completed[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if payload.CommentRef != "https://github.com/owner/repo/pull/42#issuecomment-123" {
			t.Errorf("payload CommentRef=%q, want comment URL", payload.CommentRef)
		}
	})

	t.Run("existing key returns stored comment reference", func(t *testing.T) {
		storedRef := "https://github.com/owner/repo/pull/42#issuecomment-123"
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				return &IdempotencyKey{
					Key:            key,
					RunID:          "run-1",
					SideEffectType: sideEffectPRComment,
					ResultRef:      &storedRef,
				}, nil
			},
		}
		svc := NewPRCommentService(store, PRCommentConfig{})

		var callCount int
		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			callCount++
			return "", nil
		}

		result, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Created {
			t.Error("expected Created=false for reused key")
		}
		if result.CommentRef != storedRef {
			t.Errorf("got CommentRef=%q, want %q", result.CommentRef, storedRef)
		}
		if callCount != 0 {
			t.Errorf("expected 0 commenter calls (reused), got %d", callCount)
		}

		reused := sideEffectEventsByType(store.events, "pr_comment_reused")
		if len(reused) != 1 {
			t.Fatalf("expected 1 pr_comment_reused event, got %d", len(reused))
		}
	})

	t.Run("retry verifies no duplicate comment side effects", func(t *testing.T) {
		var commentCalls atomic.Int32
		storedRef := "https://github.com/owner/repo/pull/42#issuecomment-123"

		var stored *IdempotencyKey
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				if stored != nil {
					return stored, nil
				}
				return nil, ErrNotFound
			},
			putIdempotencyKeyFn: func(_ context.Context, key *IdempotencyKey) error {
				stored = key
				return nil
			},
		}

		svc := NewPRCommentService(store, PRCommentConfig{
			IDFunc: func() string { return "evt" },
		})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			commentCalls.Add(1)
			return storedRef, nil
		}

		// First call — creates comment.
		result1, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("first call: unexpected error: %v", err)
		}
		if !result1.Created {
			t.Error("first call: expected Created=true")
		}
		if result1.CommentRef != storedRef {
			t.Errorf("first call: CommentRef=%q, want %q", result1.CommentRef, storedRef)
		}

		// Second call — reuses stored key.
		result2, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("second call: unexpected error: %v", err)
		}
		if result2.Created {
			t.Error("second call: expected Created=false")
		}
		if result2.CommentRef != storedRef {
			t.Errorf("second call: CommentRef=%q, want %q", result2.CommentRef, storedRef)
		}

		if commentCalls.Load() != 1 {
			t.Errorf("expected exactly 1 commenter call, got %d", commentCalls.Load())
		}
	})

	t.Run("nil commenter returns error", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRCommentService(store, PRCommentConfig{})

		_, err := svc.CommentPR(context.Background(), validPRCommentRequest(), nil)
		if err == nil {
			t.Fatal("expected error for nil commenter")
		}
		if !strings.Contains(err.Error(), "commenter must not be nil") {
			t.Errorf("error %q does not mention nil commenter", err.Error())
		}
	})

	t.Run("commenter failure returns error", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRCommentService(store, PRCommentConfig{})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "", fmt.Errorf("GitHub API error")
		}

		_, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err == nil {
			t.Fatal("expected error for commenter failure")
		}
		if !strings.Contains(err.Error(), "commenting on PR") {
			t.Errorf("error %q does not wrap commenter error", err.Error())
		}

		failed := sideEffectEventsByType(store.events, "pr_comment_failed")
		if len(failed) != 1 {
			t.Fatalf("expected 1 pr_comment_failed event, got %d", len(failed))
		}
	})

	t.Run("get idempotency key error propagates", func(t *testing.T) {
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, _ string) (*IdempotencyKey, error) {
				return nil, fmt.Errorf("database unavailable")
			},
		}
		svc := NewPRCommentService(store, PRCommentConfig{})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err == nil {
			t.Fatal("expected error for store failure")
		}
		if !strings.Contains(err.Error(), "checking idempotency key") {
			t.Errorf("error %q does not mention idempotency key check", err.Error())
		}
	})

	t.Run("put idempotency key error propagates", func(t *testing.T) {
		store := &prSideEffectMockStore{
			putIdempotencyKeyFn: func(_ context.Context, _ *IdempotencyKey) error {
				return fmt.Errorf("database write error")
			},
		}
		svc := NewPRCommentService(store, PRCommentConfig{})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "https://github.com/owner/repo/pull/42#issuecomment-123", nil
		}

		_, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err == nil {
			t.Fatal("expected error for put failure")
		}
		if !strings.Contains(err.Error(), "storing idempotency key") {
			t.Errorf("error %q does not mention storing key", err.Error())
		}
	})

	t.Run("duplicate key race returns stored result", func(t *testing.T) {
		storedRef := "https://github.com/owner/repo/pull/42#issuecomment-99"
		callCount := 0
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				callCount++
				if callCount == 1 {
					return nil, ErrNotFound
				}
				return &IdempotencyKey{
					Key:       key,
					ResultRef: &storedRef,
				}, nil
			},
			putIdempotencyKeyFn: func(_ context.Context, _ *IdempotencyKey) error {
				return ErrDuplicateKey
			},
		}
		svc := NewPRCommentService(store, PRCommentConfig{})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "https://github.com/owner/repo/pull/42#issuecomment-123", nil
		}

		result, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Created {
			t.Error("expected Created=false for race-recovered result")
		}
		if result.CommentRef != storedRef {
			t.Errorf("got CommentRef=%q, want %q", result.CommentRef, storedRef)
		}
	})

	t.Run("duplicate key race get failure propagates", func(t *testing.T) {
		callCount := 0
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, _ string) (*IdempotencyKey, error) {
				callCount++
				if callCount == 1 {
					return nil, ErrNotFound
				}
				return nil, fmt.Errorf("race get failure")
			},
			putIdempotencyKeyFn: func(_ context.Context, _ *IdempotencyKey) error {
				return ErrDuplicateKey
			},
		}
		svc := NewPRCommentService(store, PRCommentConfig{})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err == nil {
			t.Fatal("expected error for race get failure")
		}
		if !strings.Contains(err.Error(), "retrieving raced idempotency key") {
			t.Errorf("error %q does not mention race recovery", err.Error())
		}
	})

	t.Run("event failure tolerance", func(t *testing.T) {
		store := &prSideEffectMockStore{
			insertEventFn: func(_ context.Context, _ *Event) error {
				return fmt.Errorf("event store down")
			},
		}
		svc := NewPRCommentService(store, PRCommentConfig{})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "https://github.com/owner/repo/pull/42#issuecomment-123", nil
		}

		result, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("unexpected error (events are best-effort): %v", err)
		}
		if !result.Created {
			t.Error("expected Created=true")
		}
	})

	t.Run("IDFunc generates event IDs", func(t *testing.T) {
		var counter int
		store := &prSideEffectMockStore{}
		svc := NewPRCommentService(store, PRCommentConfig{
			IDFunc: func() string {
				counter++
				return fmt.Sprintf("evt-%d", counter)
			},
		})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, e := range store.events {
			if e.ID == "" {
				t.Errorf("event %d has empty ID", i)
			}
		}
	})

	t.Run("nil IDFunc produces empty event IDs", func(t *testing.T) {
		store := &prSideEffectMockStore{}
		svc := NewPRCommentService(store, PRCommentConfig{})

		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, e := range store.events {
			if e.ID != "" {
				t.Errorf("event %d has non-empty ID %q with nil IDFunc", i, e.ID)
			}
		}
	})

	t.Run("existing key with nil result_ref", func(t *testing.T) {
		store := &prSideEffectMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				return &IdempotencyKey{
					Key:            key,
					RunID:          "run-1",
					SideEffectType: sideEffectPRComment,
					ResultRef:      nil,
				}, nil
			},
		}
		svc := NewPRCommentService(store, PRCommentConfig{})

		var callCount int
		commenter := func(ctx context.Context, req *PRCommentRequest) (string, error) {
			callCount++
			return "", nil
		}

		result, err := svc.CommentPR(context.Background(), validPRCommentRequest(), commenter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Created {
			t.Error("expected Created=false")
		}
		if result.CommentRef != "" {
			t.Errorf("expected empty CommentRef, got %q", result.CommentRef)
		}
		if callCount != 0 {
			t.Errorf("expected 0 commenter calls, got %d", callCount)
		}
	})
}

func TestPRCommentIdempotencyKey(t *testing.T) {
	key := prCommentIdempotencyKey("run-abc")
	if key != "pr_comment:run-abc" {
		t.Errorf("got key=%q, want %q", key, "pr_comment:run-abc")
	}
}

func TestPRCommentIdempotencyKeyDeterministic(t *testing.T) {
	key1 := prCommentIdempotencyKey("run-1")
	key2 := prCommentIdempotencyKey("run-1")
	if key1 != key2 {
		t.Errorf("idempotency key not deterministic: %q != %q", key1, key2)
	}
}
