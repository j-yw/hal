package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// provisionMockRunner implements runner.Runner for provision service tests.
type provisionMockRunner struct {
	sandbox   *runner.Sandbox
	createErr error
}

func (r *provisionMockRunner) CreateSandbox(_ context.Context, req *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	if r.createErr != nil {
		return nil, r.createErr
	}
	return r.sandbox, nil
}

func (r *provisionMockRunner) Exec(_ context.Context, _ string, _ *runner.ExecRequest) (*runner.ExecResult, error) {
	return nil, nil
}

func (r *provisionMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *provisionMockRunner) DestroySandbox(_ context.Context, _ string) error {
	return nil
}

func (r *provisionMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// provisionMockStore extends mockStore for provision service tests.
type provisionMockStore struct {
	mockStore

	// UpdateAttemptSandboxID tracking
	updateSandboxCalls []updateSandboxCall
	updateSandboxErr   error

	// InsertEvent tracking
	insertedEvents []*Event
	insertEventErr error
}

type updateSandboxCall struct {
	AttemptID string
	SandboxID string
}

func (s *provisionMockStore) UpdateAttemptSandboxID(_ context.Context, attemptID, sandboxID string) error {
	s.updateSandboxCalls = append(s.updateSandboxCalls, updateSandboxCall{
		AttemptID: attemptID,
		SandboxID: sandboxID,
	})
	return s.updateSandboxErr
}

func (s *provisionMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

func TestProvision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("successful_provision", func(t *testing.T) {
		store := &provisionMockStore{}
		mockRunner := &provisionMockRunner{
			sandbox: &runner.Sandbox{
				ID:        "sandbox-001",
				Status:    "running",
				CreatedAt: now,
			},
		}

		idCounter := 0
		svc := NewProvisionService(store, mockRunner, ProvisionConfig{
			Image: "ubuntu:22.04",
			EnvVars: map[string]string{
				"KEY": "val",
			},
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		result, err := svc.Provision(context.Background(), "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.SandboxID != "sandbox-001" {
			t.Errorf("SandboxID = %q, want %q", result.SandboxID, "sandbox-001")
		}
		if result.Status != "running" {
			t.Errorf("Status = %q, want %q", result.Status, "running")
		}

		// Verify sandbox_id was persisted.
		if len(store.updateSandboxCalls) != 1 {
			t.Fatalf("updateSandboxCalls = %d, want 1", len(store.updateSandboxCalls))
		}
		call := store.updateSandboxCalls[0]
		if call.AttemptID != "att-001" {
			t.Errorf("update attemptID = %q, want %q", call.AttemptID, "att-001")
		}
		if call.SandboxID != "sandbox-001" {
			t.Errorf("update sandboxID = %q, want %q", call.SandboxID, "sandbox-001")
		}

		// Verify events were emitted.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		// sandbox_created event.
		evt0 := store.insertedEvents[0]
		if evt0.EventType != "sandbox_created" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "sandbox_created")
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
		// Verify sandbox_created payload contains sandbox_id and image.
		if evt0.PayloadJSON != nil {
			var payload sandboxEventPayload
			if err := json.Unmarshal([]byte(*evt0.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[0] payload unmarshal: %v", err)
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[0] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.Image != "ubuntu:22.04" {
				t.Errorf("event[0] payload image = %q, want %q", payload.Image, "ubuntu:22.04")
			}
		} else {
			t.Error("event[0] payload_json is nil, want non-nil")
		}

		// sandbox_ready event.
		evt1 := store.insertedEvents[1]
		if evt1.EventType != "sandbox_ready" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "sandbox_ready")
		}
		if evt1.ID != "evt-2" {
			t.Errorf("event[1] id = %q, want %q", evt1.ID, "evt-2")
		}
		// Verify sandbox_ready payload contains sandbox_id and status.
		if evt1.PayloadJSON != nil {
			var payload sandboxEventPayload
			if err := json.Unmarshal([]byte(*evt1.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[1] payload unmarshal: %v", err)
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[1] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.Status != "running" {
				t.Errorf("event[1] payload status = %q, want %q", payload.Status, "running")
			}
		} else {
			t.Error("event[1] payload_json is nil, want non-nil")
		}
	})

	t.Run("empty_attemptID", func(t *testing.T) {
		svc := NewProvisionService(&provisionMockStore{}, &provisionMockRunner{}, ProvisionConfig{})
		_, err := svc.Provision(context.Background(), "", "run-001")
		if err == nil || !strings.Contains(err.Error(), "attemptID must not be empty") {
			t.Errorf("expected attemptID error, got: %v", err)
		}
	})

	t.Run("empty_runID", func(t *testing.T) {
		svc := NewProvisionService(&provisionMockStore{}, &provisionMockRunner{}, ProvisionConfig{})
		_, err := svc.Provision(context.Background(), "att-001", "")
		if err == nil || !strings.Contains(err.Error(), "runID must not be empty") {
			t.Errorf("expected runID error, got: %v", err)
		}
	})

	t.Run("runner_create_failure", func(t *testing.T) {
		store := &provisionMockStore{}
		mockRunner := &provisionMockRunner{
			createErr: fmt.Errorf("daytona API unavailable"),
		}

		svc := NewProvisionService(store, mockRunner, ProvisionConfig{
			Image: "ubuntu:22.04",
		})

		_, err := svc.Provision(context.Background(), "att-001", "run-001")
		if err == nil || !strings.Contains(err.Error(), "failed to create sandbox") {
			t.Errorf("expected create sandbox error, got: %v", err)
		}
		if !strings.Contains(err.Error(), "daytona API unavailable") {
			t.Errorf("expected wrapped cause, got: %v", err)
		}

		// No sandbox_id update or events should occur.
		if len(store.updateSandboxCalls) != 0 {
			t.Errorf("updateSandboxCalls = %d, want 0", len(store.updateSandboxCalls))
		}
		if len(store.insertedEvents) != 0 {
			t.Errorf("insertedEvents = %d, want 0", len(store.insertedEvents))
		}
	})

	t.Run("update_sandbox_id_failure", func(t *testing.T) {
		store := &provisionMockStore{
			updateSandboxErr: fmt.Errorf("db connection lost"),
		}
		mockRunner := &provisionMockRunner{
			sandbox: &runner.Sandbox{
				ID:        "sandbox-002",
				Status:    "running",
				CreatedAt: now,
			},
		}

		svc := NewProvisionService(store, mockRunner, ProvisionConfig{
			Image: "ubuntu:22.04",
		})

		_, err := svc.Provision(context.Background(), "att-001", "run-001")
		if err == nil || !strings.Contains(err.Error(), "failed to persist sandbox_id") {
			t.Errorf("expected persist sandbox_id error, got: %v", err)
		}

		// Sandbox was created but sandbox_id update failed — no events emitted.
		if len(store.insertedEvents) != 0 {
			t.Errorf("insertedEvents = %d, want 0", len(store.insertedEvents))
		}
	})

	t.Run("update_sandbox_id_not_found", func(t *testing.T) {
		store := &provisionMockStore{
			updateSandboxErr: ErrNotFound,
		}
		mockRunner := &provisionMockRunner{
			sandbox: &runner.Sandbox{
				ID:        "sandbox-003",
				Status:    "running",
				CreatedAt: now,
			},
		}

		svc := NewProvisionService(store, mockRunner, ProvisionConfig{
			Image: "ubuntu:22.04",
		})

		_, err := svc.Provision(context.Background(), "att-missing", "run-001")
		if err == nil || !strings.Contains(err.Error(), "failed to persist sandbox_id") {
			t.Errorf("expected persist sandbox_id error, got: %v", err)
		}
	})

	t.Run("event_emission_failure_does_not_block", func(t *testing.T) {
		store := &provisionMockStore{
			insertEventErr: fmt.Errorf("event insert failed"),
		}
		mockRunner := &provisionMockRunner{
			sandbox: &runner.Sandbox{
				ID:        "sandbox-004",
				Status:    "running",
				CreatedAt: now,
			},
		}

		svc := NewProvisionService(store, mockRunner, ProvisionConfig{
			Image: "ubuntu:22.04",
		})

		result, err := svc.Provision(context.Background(), "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.SandboxID != "sandbox-004" {
			t.Errorf("SandboxID = %q, want %q", result.SandboxID, "sandbox-004")
		}

		// sandbox_id should still be persisted.
		if len(store.updateSandboxCalls) != 1 {
			t.Errorf("updateSandboxCalls = %d, want 1", len(store.updateSandboxCalls))
		}
	})

	t.Run("nil_IDFunc_uses_empty_event_id", func(t *testing.T) {
		store := &provisionMockStore{}
		mockRunner := &provisionMockRunner{
			sandbox: &runner.Sandbox{
				ID:        "sandbox-005",
				Status:    "running",
				CreatedAt: now,
			},
		}

		svc := NewProvisionService(store, mockRunner, ProvisionConfig{
			Image: "ubuntu:22.04",
		})

		_, err := svc.Provision(context.Background(), "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, evt := range store.insertedEvents {
			if evt.ID != "" {
				t.Errorf("event[%d] id = %q, want empty (nil IDFunc)", i, evt.ID)
			}
		}
	})

	t.Run("config_env_vars_passed_to_runner", func(t *testing.T) {
		var capturedReq *runner.CreateSandboxRequest
		mockRunner := &captureRunner{
			sandbox: &runner.Sandbox{
				ID:        "sandbox-006",
				Status:    "running",
				CreatedAt: now,
			},
			captureReq: func(req *runner.CreateSandboxRequest) {
				capturedReq = req
			},
		}

		svc := NewProvisionService(&provisionMockStore{}, mockRunner, ProvisionConfig{
			Image: "custom:latest",
			EnvVars: map[string]string{
				"DB_URL": "postgres://...",
				"TOKEN":  "secret",
			},
		})

		_, err := svc.Provision(context.Background(), "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if capturedReq == nil {
			t.Fatal("runner did not receive request")
		}
		if capturedReq.Image != "custom:latest" {
			t.Errorf("image = %q, want %q", capturedReq.Image, "custom:latest")
		}
		if len(capturedReq.EnvVars) != 2 {
			t.Errorf("env_vars count = %d, want 2", len(capturedReq.EnvVars))
		}
		if capturedReq.EnvVars["DB_URL"] != "postgres://..." {
			t.Errorf("env_vars[DB_URL] = %q, want %q", capturedReq.EnvVars["DB_URL"], "postgres://...")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		svc := NewProvisionService(&provisionMockStore{}, &provisionMockRunner{}, ProvisionConfig{})
		if svc.store == nil {
			t.Error("store is nil")
		}
		if svc.runner == nil {
			t.Error("runner is nil")
		}
	})
}

// captureRunner captures the CreateSandboxRequest for inspection.
type captureRunner struct {
	sandbox    *runner.Sandbox
	captureReq func(req *runner.CreateSandboxRequest)
}

func (r *captureRunner) CreateSandbox(_ context.Context, req *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	if r.captureReq != nil {
		r.captureReq(req)
	}
	return r.sandbox, nil
}

func (r *captureRunner) Exec(_ context.Context, _ string, _ *runner.ExecRequest) (*runner.ExecResult, error) {
	return nil, nil
}

func (r *captureRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *captureRunner) DestroySandbox(_ context.Context, _ string) error {
	return nil
}

func (r *captureRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}
