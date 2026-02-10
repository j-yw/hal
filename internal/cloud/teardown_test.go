package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// teardownMockRunner implements runner.Runner for teardown service tests.
type teardownMockRunner struct {
	destroyErr    error
	destroyCalled bool
	destroyID     string
}

func (r *teardownMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, nil
}

func (r *teardownMockRunner) Exec(_ context.Context, _ string, _ *runner.ExecRequest) (*runner.ExecResult, error) {
	return nil, nil
}

func (r *teardownMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *teardownMockRunner) DestroySandbox(_ context.Context, sandboxID string) error {
	r.destroyCalled = true
	r.destroyID = sandboxID
	return r.destroyErr
}

func (r *teardownMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// teardownMockStore extends mockStore for teardown service tests.
type teardownMockStore struct {
	mockStore
	insertedEvents []*Event
	insertEventErr error
}

func (s *teardownMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

func TestTeardown(t *testing.T) {
	t.Run("successful_teardown", func(t *testing.T) {
		store := &teardownMockStore{}
		mockRunner := &teardownMockRunner{}

		idCounter := 0
		svc := NewTeardownService(store, mockRunner, TeardownConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		err := svc.Teardown(context.Background(), "sandbox-001", "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify runner was called with correct sandbox ID.
		if !mockRunner.destroyCalled {
			t.Fatal("DestroySandbox was not called")
		}
		if mockRunner.destroyID != "sandbox-001" {
			t.Errorf("destroyID = %q, want %q", mockRunner.destroyID, "sandbox-001")
		}

		// Verify two events were emitted: teardown_started and teardown_done.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		// teardown_started event.
		evt0 := store.insertedEvents[0]
		if evt0.EventType != "teardown_started" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "teardown_started")
		}
		if evt0.RunID != "run-001" {
			t.Errorf("event[0] run_id = %q, want %q", evt0.RunID, "run-001")
		}
		if evt0.AttemptID == nil || *evt0.AttemptID != "att-001" {
			t.Errorf("event[0] attempt_id = %v, want %q", evt0.AttemptID, "att-001")
		}
		if evt0.ID != "evt-1" {
			t.Errorf("event[0] id = %q, want %q", evt0.ID, "evt-1")
		}
		// Verify teardown_started payload.
		if evt0.PayloadJSON != nil {
			var payload teardownEventPayload
			if err := json.Unmarshal([]byte(*evt0.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[0] payload unmarshal: %v", err)
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[0] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.Error != "" {
				t.Errorf("event[0] payload error = %q, want empty", payload.Error)
			}
		} else {
			t.Error("event[0] payload_json is nil, want non-nil")
		}

		// teardown_done event.
		evt1 := store.insertedEvents[1]
		if evt1.EventType != "teardown_done" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "teardown_done")
		}
		if evt1.ID != "evt-2" {
			t.Errorf("event[1] id = %q, want %q", evt1.ID, "evt-2")
		}
		// Verify teardown_done payload has no error.
		if evt1.PayloadJSON != nil {
			var payload teardownEventPayload
			if err := json.Unmarshal([]byte(*evt1.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[1] payload unmarshal: %v", err)
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[1] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.Error != "" {
				t.Errorf("event[1] payload error = %q, want empty", payload.Error)
			}
		} else {
			t.Error("event[1] payload_json is nil, want non-nil")
		}
	})

	t.Run("empty_sandboxID", func(t *testing.T) {
		svc := NewTeardownService(&teardownMockStore{}, &teardownMockRunner{}, TeardownConfig{})
		err := svc.Teardown(context.Background(), "", "att-001", "run-001")
		if err == nil || !strings.Contains(err.Error(), "sandboxID must not be empty") {
			t.Errorf("expected sandboxID error, got: %v", err)
		}
	})

	t.Run("empty_attemptID", func(t *testing.T) {
		svc := NewTeardownService(&teardownMockStore{}, &teardownMockRunner{}, TeardownConfig{})
		err := svc.Teardown(context.Background(), "sandbox-001", "", "run-001")
		if err == nil || !strings.Contains(err.Error(), "attemptID must not be empty") {
			t.Errorf("expected attemptID error, got: %v", err)
		}
	})

	t.Run("empty_runID", func(t *testing.T) {
		svc := NewTeardownService(&teardownMockStore{}, &teardownMockRunner{}, TeardownConfig{})
		err := svc.Teardown(context.Background(), "sandbox-001", "att-001", "")
		if err == nil || !strings.Contains(err.Error(), "runID must not be empty") {
			t.Errorf("expected runID error, got: %v", err)
		}
	})

	t.Run("runner_destroy_failure_emits_error_in_done_event", func(t *testing.T) {
		store := &teardownMockStore{}
		mockRunner := &teardownMockRunner{
			destroyErr: fmt.Errorf("sandbox not reachable"),
		}

		idCounter := 0
		svc := NewTeardownService(store, mockRunner, TeardownConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		err := svc.Teardown(context.Background(), "sandbox-001", "att-001", "run-001")
		if err == nil || !strings.Contains(err.Error(), "failed to destroy sandbox") {
			t.Errorf("expected destroy sandbox error, got: %v", err)
		}
		if !strings.Contains(err.Error(), "sandbox not reachable") {
			t.Errorf("expected wrapped cause, got: %v", err)
		}

		// Both events should still be emitted.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		// teardown_started should have no error.
		evt0 := store.insertedEvents[0]
		if evt0.EventType != "teardown_started" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "teardown_started")
		}

		// teardown_done should carry the error.
		evt1 := store.insertedEvents[1]
		if evt1.EventType != "teardown_done" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "teardown_done")
		}
		if evt1.PayloadJSON == nil {
			t.Fatal("event[1] payload_json is nil, want non-nil")
		}
		var payload teardownEventPayload
		if err := json.Unmarshal([]byte(*evt1.PayloadJSON), &payload); err != nil {
			t.Fatalf("event[1] payload unmarshal: %v", err)
		}
		if !strings.Contains(payload.Error, "sandbox not reachable") {
			t.Errorf("event[1] payload error = %q, want contains %q", payload.Error, "sandbox not reachable")
		}
	})

	t.Run("event_emission_failure_does_not_block", func(t *testing.T) {
		store := &teardownMockStore{
			insertEventErr: fmt.Errorf("event insert failed"),
		}
		mockRunner := &teardownMockRunner{}

		svc := NewTeardownService(store, mockRunner, TeardownConfig{})

		err := svc.Teardown(context.Background(), "sandbox-001", "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Runner should still be called despite event failures.
		if !mockRunner.destroyCalled {
			t.Error("DestroySandbox was not called")
		}
	})

	t.Run("nil_IDFunc_uses_empty_event_id", func(t *testing.T) {
		store := &teardownMockStore{}
		mockRunner := &teardownMockRunner{}

		svc := NewTeardownService(store, mockRunner, TeardownConfig{})

		err := svc.Teardown(context.Background(), "sandbox-001", "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, evt := range store.insertedEvents {
			if evt.ID != "" {
				t.Errorf("event[%d] id = %q, want empty (nil IDFunc)", i, evt.ID)
			}
		}
	})

	t.Run("teardown_on_success_terminal_path", func(t *testing.T) {
		store := &teardownMockStore{}
		mockRunner := &teardownMockRunner{}

		svc := NewTeardownService(store, mockRunner, TeardownConfig{
			IDFunc: func() string { return "evt-success" },
		})

		// Simulate teardown after a successful run completion.
		err := svc.Teardown(context.Background(), "sandbox-success", "att-success", "run-success")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mockRunner.destroyID != "sandbox-success" {
			t.Errorf("destroyID = %q, want %q", mockRunner.destroyID, "sandbox-success")
		}

		// Verify events reference the correct run and attempt.
		for _, evt := range store.insertedEvents {
			if evt.RunID != "run-success" {
				t.Errorf("event run_id = %q, want %q", evt.RunID, "run-success")
			}
			if evt.AttemptID == nil || *evt.AttemptID != "att-success" {
				t.Errorf("event attempt_id = %v, want %q", evt.AttemptID, "att-success")
			}
		}
	})

	t.Run("teardown_on_failure_terminal_path", func(t *testing.T) {
		store := &teardownMockStore{}
		mockRunner := &teardownMockRunner{}

		svc := NewTeardownService(store, mockRunner, TeardownConfig{
			IDFunc: func() string { return "evt-failure" },
		})

		// Simulate teardown after a failed run.
		err := svc.Teardown(context.Background(), "sandbox-fail", "att-fail", "run-fail")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mockRunner.destroyID != "sandbox-fail" {
			t.Errorf("destroyID = %q, want %q", mockRunner.destroyID, "sandbox-fail")
		}

		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}
	})

	t.Run("defaults", func(t *testing.T) {
		svc := NewTeardownService(&teardownMockStore{}, &teardownMockRunner{}, TeardownConfig{})
		if svc.store == nil {
			t.Error("store is nil")
		}
		if svc.runner == nil {
			t.Error("runner is nil")
		}
	})
}
