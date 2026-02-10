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

func testStripeLikeKeyForPipeline(kind, mode string) string {
	return strings.Join([]string{kind, "_", mode, "_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"}, "")
}

// --- redactPayload unit tests ---

func TestRedactPayload(t *testing.T) {
	t.Run("nil_input_returns_nil", func(t *testing.T) {
		result, wasRedacted := redactPayload(nil)
		if result != nil {
			t.Fatalf("expected nil, got %q", *result)
		}
		if wasRedacted {
			t.Fatal("expected wasRedacted=false for nil input")
		}
	})

	t.Run("no_secrets_returns_unchanged", func(t *testing.T) {
		input := `{"sandbox_id":"sb-001","mode":"until_complete"}`
		result, wasRedacted := redactPayload(&input)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != input {
			t.Errorf("expected %q, got %q", input, *result)
		}
		if wasRedacted {
			t.Fatal("expected wasRedacted=false for input with no secrets")
		}
	})

	t.Run("bearer_token_redacted", func(t *testing.T) {
		input := `{"error":"failed with Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abc123"}`
		result, wasRedacted := redactPayload(&input)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if !wasRedacted {
			t.Fatal("expected wasRedacted=true for input with bearer token")
		}
		if strings.Contains(*result, "eyJhbGciOiJIUzI1NiJ9") {
			t.Errorf("raw token still present in output: %s", *result)
		}
		if !strings.Contains(*result, "[REDACTED]") {
			t.Errorf("expected [REDACTED] in output: %s", *result)
		}
		if !strings.Contains(*result, "Bearer ") {
			t.Errorf("expected Bearer prefix preserved: %s", *result)
		}
	})

	t.Run("github_pat_redacted", func(t *testing.T) {
		input := `{"error":"auth failed: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"}`
		result, wasRedacted := redactPayload(&input)
		if !wasRedacted {
			t.Fatal("expected wasRedacted=true for GitHub PAT")
		}
		if strings.Contains(*result, "ghp_ABCDEF") {
			t.Errorf("raw PAT still present in output: %s", *result)
		}
		if !strings.Contains(*result, "[REDACTED]") {
			t.Errorf("expected [REDACTED] in output: %s", *result)
		}
	})

	t.Run("stripe_key_redacted", func(t *testing.T) {
		stripeKey := testStripeLikeKeyForPipeline("sk", "live")
		input := fmt.Sprintf(`{"error":"payment failed: %s"}`, stripeKey)
		result, wasRedacted := redactPayload(&input)
		if !wasRedacted {
			t.Fatal("expected wasRedacted=true for Stripe key")
		}
		if strings.Contains(*result, stripeKey) {
			t.Errorf("raw key still present in output: %s", *result)
		}
	})

	t.Run("multiple_secrets_redacted", func(t *testing.T) {
		input := `{"error":"token Bearer abc123def456 and key ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"}`
		result, wasRedacted := redactPayload(&input)
		if !wasRedacted {
			t.Fatal("expected wasRedacted=true for multiple secrets")
		}
		if strings.Contains(*result, "abc123def456") {
			t.Errorf("raw bearer token still present: %s", *result)
		}
		if strings.Contains(*result, "ghp_ABCDEF") {
			t.Errorf("raw PAT still present: %s", *result)
		}
	})
}

// --- RedactingLogReader unit tests ---

func TestRedactingLogReader(t *testing.T) {
	t.Run("redacts_secrets_in_stream", func(t *testing.T) {
		input := "normal line\nBearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abc123\nmore output\n"
		source := io.NopCloser(strings.NewReader(input))
		reader := NewRedactingLogReader(source)
		defer reader.Close()

		output, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		result := string(output)

		if strings.Contains(result, "eyJhbGciOiJIUzI1NiJ9") {
			t.Errorf("raw token still present in stream output: %s", result)
		}
		if !strings.Contains(result, "[REDACTED]") {
			t.Errorf("expected [REDACTED] in output: %s", result)
		}
		if !strings.Contains(result, "normal line") {
			t.Errorf("expected normal line preserved: %s", result)
		}
		if !strings.Contains(result, "more output") {
			t.Errorf("expected non-secret line preserved: %s", result)
		}
	})

	t.Run("no_secrets_passes_through", func(t *testing.T) {
		input := "line 1\nline 2\nline 3\n"
		source := io.NopCloser(strings.NewReader(input))
		reader := NewRedactingLogReader(source)
		defer reader.Close()

		output, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		result := string(output)

		if !strings.Contains(result, "line 1") {
			t.Errorf("expected line 1 in output: %s", result)
		}
		if !strings.Contains(result, "line 2") {
			t.Errorf("expected line 2 in output: %s", result)
		}
		if !strings.Contains(result, "line 3") {
			t.Errorf("expected line 3 in output: %s", result)
		}
	})

	t.Run("empty_stream", func(t *testing.T) {
		source := io.NopCloser(strings.NewReader(""))
		reader := NewRedactingLogReader(source)
		defer reader.Close()

		output, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(output) != 0 {
			t.Errorf("expected empty output, got %q", string(output))
		}
	})

	t.Run("multiple_secret_types_in_stream", func(t *testing.T) {
		stripeKey := testStripeLikeKeyForPipeline("sk", "live")
		input := fmt.Sprintf("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc\nPAT: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\nStripe: %s\n", stripeKey)
		source := io.NopCloser(strings.NewReader(input))
		reader := NewRedactingLogReader(source)
		defer reader.Close()

		output, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		result := string(output)

		if strings.Contains(result, "eyJhbGciOiJIUzI1NiJ9") {
			t.Errorf("raw bearer token in stream: %s", result)
		}
		if strings.Contains(result, "ghp_ABCDEF") {
			t.Errorf("raw GitHub PAT in stream: %s", result)
		}
		if strings.Contains(result, stripeKey) {
			t.Errorf("raw Stripe key in stream: %s", result)
		}
	})

	t.Run("close_propagates", func(t *testing.T) {
		closed := false
		source := &trackingCloser{
			Reader: strings.NewReader("test\n"),
			onClose: func() {
				closed = true
			},
		}
		reader := NewRedactingLogReader(source)
		reader.Close()
		if !closed {
			t.Fatal("expected Close to propagate to source")
		}
	})

	t.Run("small_read_buffer", func(t *testing.T) {
		input := "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abc123\n"
		source := io.NopCloser(strings.NewReader(input))
		reader := NewRedactingLogReader(source)
		defer reader.Close()

		// Read with a very small buffer to exercise buffering logic.
		var result []byte
		buf := make([]byte, 5)
		for {
			n, err := reader.Read(buf)
			result = append(result, buf[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		if strings.Contains(string(result), "eyJhbGciOiJIUzI1NiJ9") {
			t.Errorf("raw token present with small buffer: %s", string(result))
		}
		if !strings.Contains(string(result), "[REDACTED]") {
			t.Errorf("expected [REDACTED] with small buffer: %s", string(result))
		}
	})
}

// trackingCloser is an io.ReadCloser that tracks whether Close was called.
type trackingCloser struct {
	io.Reader
	onClose func()
}

func (t *trackingCloser) Close() error {
	if t.onClose != nil {
		t.onClose()
	}
	return nil
}

// --- Integration tests: secrets never appear in DB rows ---

func TestRedactionIntegrationBootstrap(t *testing.T) {
	t.Run("bootstrap_error_with_bearer_token_is_redacted_in_event", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {
					ExitCode: 1,
					Stderr:   "fatal: Authentication failed: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.secret_signature",
				},
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{
			IDFunc: func() string { return "evt-001" },
		})

		_ = svc.Bootstrap(context.Background(), &BootstrapRequest{
			Repo:      "https://github.com/org/repo.git",
			Branch:    "main",
			SandboxID: "sb-001",
			AttemptID: "att-001",
			RunID:     "run-001",
		})

		// Check all events — no raw secret should appear in any payload.
		for _, event := range store.insertedEvents {
			if event.PayloadJSON != nil {
				if strings.Contains(*event.PayloadJSON, "eyJhbGciOiJIUzI1NiJ9") {
					t.Errorf("raw bearer token in %s event payload: %s", event.EventType, *event.PayloadJSON)
				}
				if strings.Contains(*event.PayloadJSON, "secret_signature") {
					t.Errorf("raw signature in %s event payload: %s", event.EventType, *event.PayloadJSON)
				}
			}
		}

		// Verify the bootstrap_failed event has redacted=true.
		failedEvents := filterEventsByType(store.insertedEvents, "bootstrap_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("expected 1 bootstrap_failed event, got %d", len(failedEvents))
		}
		if !failedEvents[0].Redacted {
			t.Error("expected bootstrap_failed event to have Redacted=true")
		}
	})
}

func TestRedactionIntegrationExecution(t *testing.T) {
	t.Run("execution_error_with_github_pat_is_redacted_in_event", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{
				ExitCode: 1,
				Stderr:   "error: failed to push using ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
			},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{
			IDFunc: func() string { return "evt-001" },
		})

		_, _ = svc.Execute(context.Background(), validExecutionRequest())

		for _, event := range store.insertedEvents {
			if event.PayloadJSON != nil {
				if strings.Contains(*event.PayloadJSON, "ghp_ABCDEF") {
					t.Errorf("raw GitHub PAT in %s event payload: %s", event.EventType, *event.PayloadJSON)
				}
			}
		}

		// execution_finished event should be redacted.
		finishedEvents := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(finishedEvents) != 1 {
			t.Fatalf("expected 1 execution_finished event, got %d", len(finishedEvents))
		}
		if !finishedEvents[0].Redacted {
			t.Error("expected execution_finished event to have Redacted=true")
		}
	})

	t.Run("execution_error_without_secrets_is_not_marked_redacted", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{
				ExitCode: 1,
				Stderr:   "error: compilation failed",
			},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{
			IDFunc: func() string { return "evt-001" },
		})

		_, _ = svc.Execute(context.Background(), validExecutionRequest())

		finishedEvents := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(finishedEvents) != 1 {
			t.Fatalf("expected 1 execution_finished event, got %d", len(finishedEvents))
		}
		if finishedEvents[0].Redacted {
			t.Error("expected execution_finished event to have Redacted=false when no secrets present")
		}
	})
}

func TestRedactionIntegrationPreflight(t *testing.T) {
	t.Run("preflight_error_with_api_key_is_redacted_in_event", func(t *testing.T) {
		secretRef := "test-secret"
		metadataJSON := `{"os":"linux","arch":"amd64"}`
		store := &preflightMockStore{
			authProfile: &AuthProfile{
				ID:                  "ap-001",
				OwnerID:             "owner-001",
				Provider:            "claude",
				Mode:                "session",
				Status:              AuthProfileStatusLinked,
				MaxConcurrentRuns:   1,
				Version:             1,
				SecretRef:           &secretRef,
				RuntimeMetadataJSON: &metadataJSON,
			},
		}
		stripeKey := testStripeLikeKeyForPipeline("sk", "live")
		mockRunner := &preflightMockRunner{
			execResults: map[string]*runner.ExecResult{
				"claude auth verify": {
					ExitCode: 1,
					Stderr:   fmt.Sprintf("error: X-Api-Key: %s invalid", stripeKey),
				},
			},
		}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{
			ProviderCommands: map[string]string{"claude": "claude auth verify"},
			IDFunc:           func() string { return "evt-001" },
		})

		_ = svc.Preflight(context.Background(), &PreflightRequest{
			AuthProfileID:     "ap-001",
			SandboxID:         "sb-001",
			AttemptID:         "att-001",
			RunID:             "run-001",
			SandboxOS:         "linux",
			SandboxArch:       "amd64",
			SandboxCLIVersion: "1.0",
		})

		for _, event := range store.insertedEvents {
			if event.PayloadJSON != nil {
				if strings.Contains(*event.PayloadJSON, stripeKey) {
					t.Errorf("raw Stripe key in %s event payload: %s", event.EventType, *event.PayloadJSON)
				}
			}
		}

		// preflight_failed should be redacted.
		failedEvents := filterEventsByType(store.insertedEvents, "preflight_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("expected 1 preflight_failed event, got %d", len(failedEvents))
		}
		if !failedEvents[0].Redacted {
			t.Error("expected preflight_failed event to have Redacted=true")
		}
	})
}

func TestRedactionIntegrationTeardown(t *testing.T) {
	t.Run("teardown_error_with_secret_is_redacted_in_event", func(t *testing.T) {
		store := &teardownMockStore{}
		mockRunner := &teardownMockRunner{
			destroyErr: fmt.Errorf("destroy failed: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.secretsig"),
		}

		svc := NewTeardownService(store, mockRunner, TeardownConfig{
			IDFunc: func() string { return "evt-001" },
		})

		_ = svc.Teardown(context.Background(), "sb-001", "att-001", "run-001")

		for _, event := range store.insertedEvents {
			if event.PayloadJSON != nil {
				if strings.Contains(*event.PayloadJSON, "eyJhbGciOiJIUzI1NiJ9") {
					t.Errorf("raw bearer token in %s event payload: %s", event.EventType, *event.PayloadJSON)
				}
			}
		}

		doneEvents := filterEventsByType(store.insertedEvents, "teardown_done")
		if len(doneEvents) != 1 {
			t.Fatalf("expected 1 teardown_done event, got %d", len(doneEvents))
		}
		if !doneEvents[0].Redacted {
			t.Error("expected teardown_done event to have Redacted=true")
		}
	})
}

func TestRedactionIntegrationWriteback(t *testing.T) {
	t.Run("writeback_error_with_secret_is_redacted_in_event", func(t *testing.T) {
		secretRef := "original-secret"
		store := &writebackMockStore{
			authProfile: &AuthProfile{
				ID:                "ap-001",
				OwnerID:           "owner-001",
				Provider:          "claude",
				Mode:              "session",
				Status:            AuthProfileStatusLinked,
				MaxConcurrentRuns: 1,
				Version:           1,
				SecretRef:         &secretRef,
			},
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {
					ExitCode: 1,
					Stderr:   "read failed: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn was rejected",
				},
			},
		}

		svc := NewWritebackService(store, mockRunner, WritebackConfig{
			IDFunc: func() string { return "evt-001" },
		})

		_, _ = svc.Writeback(context.Background(), &WritebackRequest{
			AuthProfileID: "ap-001",
			SandboxID:     "sb-001",
			AttemptID:     "att-001",
			RunID:         "run-001",
		})

		for _, event := range store.insertedEvents {
			if event.PayloadJSON != nil {
				if strings.Contains(*event.PayloadJSON, "ghp_ABCDEF") {
					t.Errorf("raw GitHub PAT in %s event payload: %s", event.EventType, *event.PayloadJSON)
				}
			}
		}

		failedEvents := filterEventsByType(store.insertedEvents, "writeback_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("expected 1 writeback_failed event, got %d", len(failedEvents))
		}
		if !failedEvents[0].Redacted {
			t.Error("expected writeback_failed event to have Redacted=true")
		}
	})
}

func TestRedactionIntegrationAuthMaterialization(t *testing.T) {
	t.Run("auth_materialize_error_with_secret_is_redacted_in_event", func(t *testing.T) {
		secretRef := "secret-credentials"
		store := &authMatMockStore{
			authProfile: &AuthProfile{
				ID:                "ap-001",
				OwnerID:           "owner-001",
				Provider:          "claude",
				Mode:              "session",
				Status:            AuthProfileStatusLinked,
				MaxConcurrentRuns: 1,
				Version:           1,
				SecretRef:         &secretRef,
			},
		}
		mockRunner := &authMatMockRunner{
			execResults: map[string]*runner.ExecResult{
				"mkdir": {ExitCode: 0},
				"printf": {
					ExitCode: 1,
					Stderr:   "write failed: Bearer eyJhbGciOiJIUzI1NiJ9.secret.credentials leaked",
				},
			},
		}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{
			IDFunc: func() string { return "evt-001" },
		})

		_ = svc.Materialize(context.Background(), &MaterializeRequest{
			AuthProfileID: "ap-001",
			SandboxID:     "sb-001",
			AttemptID:     "att-001",
			RunID:         "run-001",
		})

		for _, event := range store.insertedEvents {
			if event.PayloadJSON != nil {
				if strings.Contains(*event.PayloadJSON, "eyJhbGciOiJIUzI1NiJ9") {
					t.Errorf("raw bearer token in %s event payload: %s", event.EventType, *event.PayloadJSON)
				}
			}
		}

		failedEvents := filterEventsByType(store.insertedEvents, "auth_materialize_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("expected 1 auth_materialize_failed event, got %d", len(failedEvents))
		}
		if !failedEvents[0].Redacted {
			t.Error("expected auth_materialize_failed event to have Redacted=true")
		}
	})
}

// --- Cross-service integration: verify payload JSON structure after redaction ---

func TestRedactionPreservesPayloadStructure(t *testing.T) {
	t.Run("redacted_payload_is_valid_json", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{
				ExitCode: 1,
				Stderr:   "error: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abc123 rejected",
			},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{
			IDFunc: func() string { return "evt-001" },
		})

		_, _ = svc.Execute(context.Background(), validExecutionRequest())

		for _, event := range store.insertedEvents {
			if event.PayloadJSON == nil {
				continue
			}
			// Verify redacted payload is still valid JSON.
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(*event.PayloadJSON), &parsed); err != nil {
				t.Errorf("event %s has invalid JSON after redaction: %v\npayload: %s", event.EventType, err, *event.PayloadJSON)
			}
		}
	})
}

// --- Test that no-secret events have Redacted=false ---

func TestNoSecretEventsAreNotMarkedRedacted(t *testing.T) {
	t.Run("bootstrap_success_events_not_redacted", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{
			IDFunc: func() string { return "evt-001" },
		})

		err := svc.Bootstrap(context.Background(), &BootstrapRequest{
			Repo:      "https://github.com/org/repo.git",
			Branch:    "main",
			SandboxID: "sb-001",
			AttemptID: "att-001",
			RunID:     "run-001",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, event := range store.insertedEvents {
			if event.Redacted {
				t.Errorf("event %s should not be marked Redacted when no secrets are present", event.EventType)
			}
		}
	})
}
