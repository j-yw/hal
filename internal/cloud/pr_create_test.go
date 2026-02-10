package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// --- mock store for PR create tests ---

type prCreateMockStore struct {
	mockStore
	putIdempotencyKeyFn func(ctx context.Context, key *IdempotencyKey) error
	getIdempotencyKeyFn func(ctx context.Context, key string) (*IdempotencyKey, error)
	insertEventFn       func(ctx context.Context, event *Event) error
	events              []*Event
}

func (m *prCreateMockStore) PutIdempotencyKey(ctx context.Context, key *IdempotencyKey) error {
	if m.putIdempotencyKeyFn != nil {
		return m.putIdempotencyKeyFn(ctx, key)
	}
	return nil
}

func (m *prCreateMockStore) GetIdempotencyKey(ctx context.Context, key string) (*IdempotencyKey, error) {
	if m.getIdempotencyKeyFn != nil {
		return m.getIdempotencyKeyFn(ctx, key)
	}
	return nil, ErrNotFound
}

func (m *prCreateMockStore) InsertEvent(ctx context.Context, event *Event) error {
	m.events = append(m.events, event)
	if m.insertEventFn != nil {
		return m.insertEventFn(ctx, event)
	}
	return nil
}

// --- helpers ---

func validPRCreateRequest() *PRCreateRequest {
	return &PRCreateRequest{
		RunID:     "run-1",
		AttemptID: "attempt-1",
		Title:     "feat: add feature",
		Body:      "PR body",
		Head:      "feature-branch",
		Base:      "main",
		Repo:      "owner/repo",
	}
}

func prCreateEventsByType(events []*Event, eventType string) []*Event {
	var result []*Event
	for _, e := range events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}

// --- tests ---

func TestPRCreateRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *PRCreateRequest)
		wantErr string
	}{
		{name: "valid", modify: func(r *PRCreateRequest) {}},
		{name: "empty runID", modify: func(r *PRCreateRequest) { r.RunID = "" }, wantErr: "runID must not be empty"},
		{name: "empty attemptID", modify: func(r *PRCreateRequest) { r.AttemptID = "" }, wantErr: "attemptID must not be empty"},
		{name: "empty title", modify: func(r *PRCreateRequest) { r.Title = "" }, wantErr: "title must not be empty"},
		{name: "empty head", modify: func(r *PRCreateRequest) { r.Head = "" }, wantErr: "head must not be empty"},
		{name: "empty base", modify: func(r *PRCreateRequest) { r.Base = "" }, wantErr: "base must not be empty"},
		{name: "empty repo", modify: func(r *PRCreateRequest) { r.Repo = "" }, wantErr: "repo must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validPRCreateRequest()
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

func TestCreatePR(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		store := &prCreateMockStore{}
		svc := NewPRCreateService(store, PRCreateConfig{
			IDFunc: func() string { return "evt-1" },
		})

		var callCount int
		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			callCount++
			return "https://github.com/owner/repo/pull/42", nil
		}

		result, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Created {
			t.Error("expected Created=true")
		}
		if result.PRRef != "https://github.com/owner/repo/pull/42" {
			t.Errorf("got PRRef=%q, want https://github.com/owner/repo/pull/42", result.PRRef)
		}
		if callCount != 1 {
			t.Errorf("expected 1 creator call, got %d", callCount)
		}

		// Verify events
		started := prCreateEventsByType(store.events, "pr_create_started")
		if len(started) != 1 {
			t.Fatalf("expected 1 pr_create_started event, got %d", len(started))
		}
		completed := prCreateEventsByType(store.events, "pr_create_completed")
		if len(completed) != 1 {
			t.Fatalf("expected 1 pr_create_completed event, got %d", len(completed))
		}

		// Verify completed payload contains PR ref
		var payload prCreateEventPayload
		if err := json.Unmarshal([]byte(*completed[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if payload.PRRef != "https://github.com/owner/repo/pull/42" {
			t.Errorf("payload PRRef=%q, want PR URL", payload.PRRef)
		}
	})

	t.Run("existing key returns stored PR reference", func(t *testing.T) {
		storedRef := "https://github.com/owner/repo/pull/42"
		store := &prCreateMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				return &IdempotencyKey{
					Key:            key,
					RunID:          "run-1",
					SideEffectType: sideEffectPRCreate,
					ResultRef:      &storedRef,
				}, nil
			},
		}
		svc := NewPRCreateService(store, PRCreateConfig{})

		var callCount int
		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			callCount++
			return "", nil
		}

		result, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Created {
			t.Error("expected Created=false for reused key")
		}
		if result.PRRef != storedRef {
			t.Errorf("got PRRef=%q, want %q", result.PRRef, storedRef)
		}
		if callCount != 0 {
			t.Errorf("expected 0 creator calls (reused), got %d", callCount)
		}

		// Verify reuse event
		reused := prCreateEventsByType(store.events, "pr_create_reused")
		if len(reused) != 1 {
			t.Fatalf("expected 1 pr_create_reused event, got %d", len(reused))
		}
	})

	t.Run("retry verifies exactly one external create call", func(t *testing.T) {
		var createCalls atomic.Int32
		storedRef := "https://github.com/owner/repo/pull/42"

		// First call: no existing key → create PR.
		// Second call: key exists → reuse.
		var stored *IdempotencyKey
		store := &prCreateMockStore{
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

		svc := NewPRCreateService(store, PRCreateConfig{
			IDFunc: func() string { return "evt" },
		})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			createCalls.Add(1)
			return storedRef, nil
		}

		// First call — creates PR.
		result1, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err != nil {
			t.Fatalf("first call: unexpected error: %v", err)
		}
		if !result1.Created {
			t.Error("first call: expected Created=true")
		}
		if result1.PRRef != storedRef {
			t.Errorf("first call: PRRef=%q, want %q", result1.PRRef, storedRef)
		}

		// Second call — reuses stored key.
		result2, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err != nil {
			t.Fatalf("second call: unexpected error: %v", err)
		}
		if result2.Created {
			t.Error("second call: expected Created=false")
		}
		if result2.PRRef != storedRef {
			t.Errorf("second call: PRRef=%q, want %q", result2.PRRef, storedRef)
		}

		// Exactly one external create call.
		if createCalls.Load() != 1 {
			t.Errorf("expected exactly 1 creator call, got %d", createCalls.Load())
		}
	})

	t.Run("nil creator returns error", func(t *testing.T) {
		store := &prCreateMockStore{}
		svc := NewPRCreateService(store, PRCreateConfig{})

		_, err := svc.CreatePR(context.Background(), validPRCreateRequest(), nil)
		if err == nil {
			t.Fatal("expected error for nil creator")
		}
		if !strings.Contains(err.Error(), "creator must not be nil") {
			t.Errorf("error %q does not mention nil creator", err.Error())
		}
	})

	t.Run("creator failure returns error", func(t *testing.T) {
		store := &prCreateMockStore{}
		svc := NewPRCreateService(store, PRCreateConfig{})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "", fmt.Errorf("GitHub API error")
		}

		_, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err == nil {
			t.Fatal("expected error for creator failure")
		}
		if !strings.Contains(err.Error(), "creating PR") {
			t.Errorf("error %q does not wrap creator error", err.Error())
		}

		// Verify failure event
		failed := prCreateEventsByType(store.events, "pr_create_failed")
		if len(failed) != 1 {
			t.Fatalf("expected 1 pr_create_failed event, got %d", len(failed))
		}
	})

	t.Run("get idempotency key error propagates", func(t *testing.T) {
		store := &prCreateMockStore{
			getIdempotencyKeyFn: func(_ context.Context, _ string) (*IdempotencyKey, error) {
				return nil, fmt.Errorf("database unavailable")
			},
		}
		svc := NewPRCreateService(store, PRCreateConfig{})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err == nil {
			t.Fatal("expected error for store failure")
		}
		if !strings.Contains(err.Error(), "checking idempotency key") {
			t.Errorf("error %q does not mention idempotency key check", err.Error())
		}
	})

	t.Run("put idempotency key error propagates", func(t *testing.T) {
		store := &prCreateMockStore{
			putIdempotencyKeyFn: func(_ context.Context, _ *IdempotencyKey) error {
				return fmt.Errorf("database write error")
			},
		}
		svc := NewPRCreateService(store, PRCreateConfig{})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "https://github.com/owner/repo/pull/42", nil
		}

		_, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err == nil {
			t.Fatal("expected error for put failure")
		}
		if !strings.Contains(err.Error(), "storing idempotency key") {
			t.Errorf("error %q does not mention storing key", err.Error())
		}
	})

	t.Run("duplicate key race returns stored result", func(t *testing.T) {
		storedRef := "https://github.com/owner/repo/pull/99"
		store := &prCreateMockStore{
			putIdempotencyKeyFn: func(_ context.Context, _ *IdempotencyKey) error {
				return ErrDuplicateKey
			},
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				// First call returns not found (triggers create), race handler reads stored.
				// We simulate: GetIdempotencyKey returns not-found first time
				// (during step 1), then returns the key during race recovery.
				// Since putIdempotencyKeyFn returns ErrDuplicateKey, the service
				// re-reads the key.
				return &IdempotencyKey{
					Key:       key,
					ResultRef: &storedRef,
				}, nil
			},
		}
		svc := NewPRCreateService(store, PRCreateConfig{})

		// The first GetIdempotencyKey returns the key (simulating it already existed),
		// so the service takes the reuse path. To test the actual race path, we need
		// the first Get to return not-found and the Put to return duplicate.
		callCount := 0
		store.getIdempotencyKeyFn = func(_ context.Context, key string) (*IdempotencyKey, error) {
			callCount++
			if callCount == 1 {
				return nil, ErrNotFound // first check: key does not exist
			}
			return &IdempotencyKey{
				Key:       key,
				ResultRef: &storedRef,
			}, nil // race recovery: key now exists
		}

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "https://github.com/owner/repo/pull/42", nil
		}

		result, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Created {
			t.Error("expected Created=false for race-recovered result")
		}
		if result.PRRef != storedRef {
			t.Errorf("got PRRef=%q, want %q", result.PRRef, storedRef)
		}
	})

	t.Run("duplicate key race get failure propagates", func(t *testing.T) {
		callCount := 0
		store := &prCreateMockStore{
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
		svc := NewPRCreateService(store, PRCreateConfig{})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err == nil {
			t.Fatal("expected error for race get failure")
		}
		if !strings.Contains(err.Error(), "retrieving raced idempotency key") {
			t.Errorf("error %q does not mention race recovery", err.Error())
		}
	})

	t.Run("event failure tolerance", func(t *testing.T) {
		store := &prCreateMockStore{
			insertEventFn: func(_ context.Context, _ *Event) error {
				return fmt.Errorf("event store down")
			},
		}
		svc := NewPRCreateService(store, PRCreateConfig{})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "https://github.com/owner/repo/pull/42", nil
		}

		result, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err != nil {
			t.Fatalf("unexpected error (events are best-effort): %v", err)
		}
		if !result.Created {
			t.Error("expected Created=true")
		}
	})

	t.Run("IDFunc generates event IDs", func(t *testing.T) {
		var counter int
		store := &prCreateMockStore{}
		svc := NewPRCreateService(store, PRCreateConfig{
			IDFunc: func() string {
				counter++
				return fmt.Sprintf("evt-%d", counter)
			},
		})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
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
		store := &prCreateMockStore{}
		svc := NewPRCreateService(store, PRCreateConfig{})

		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			return "url", nil
		}

		_, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
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
		store := &prCreateMockStore{
			getIdempotencyKeyFn: func(_ context.Context, key string) (*IdempotencyKey, error) {
				return &IdempotencyKey{
					Key:            key,
					RunID:          "run-1",
					SideEffectType: sideEffectPRCreate,
					ResultRef:      nil,
				}, nil
			},
		}
		svc := NewPRCreateService(store, PRCreateConfig{})

		var callCount int
		creator := func(ctx context.Context, req *PRCreateRequest) (string, error) {
			callCount++
			return "", nil
		}

		result, err := svc.CreatePR(context.Background(), validPRCreateRequest(), creator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Created {
			t.Error("expected Created=false")
		}
		if result.PRRef != "" {
			t.Errorf("expected empty PRRef, got %q", result.PRRef)
		}
		if callCount != 0 {
			t.Errorf("expected 0 creator calls, got %d", callCount)
		}
	})
}

func TestPRCreateIdempotencyKey(t *testing.T) {
	key := prCreateIdempotencyKey("run-abc")
	if key != "pr_create:run-abc" {
		t.Errorf("got key=%q, want %q", key, "pr_create:run-abc")
	}
}

func TestPRCreateIdempotencyKeyDeterministic(t *testing.T) {
	key1 := prCreateIdempotencyKey("run-1")
	key2 := prCreateIdempotencyKey("run-1")
	if key1 != key2 {
		t.Errorf("idempotency key not deterministic: %q != %q", key1, key2)
	}
}
