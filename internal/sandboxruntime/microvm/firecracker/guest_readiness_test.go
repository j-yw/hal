package firecracker

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestGuestReadinessRequestShapeIncludesOnlyHandleAndRuntimeIdentity(t *testing.T) {
	reqType := reflect.TypeOf(GuestReadinessRequest{})
	if reqType.NumField() != 2 {
		t.Fatalf("GuestReadinessRequest field count = %d, want handle and runtime ID only", reqType.NumField())
	}
	assertGuestReadinessField(t, reqType, "Handle", reflect.TypeOf(ProcessHandleMetadata{}), `json:"handle,omitempty"`)
	assertGuestReadinessField(t, reqType, "RuntimeID", reflect.TypeOf(""), `json:"runtimeId,omitempty"`)

	req := NewGuestReadinessRequest(
		ProcessHandleMetadata{ID: "fc-handle-1234", Source: "adapter"},
		"fc-runtime-1234",
	)
	if req.Handle.ID != "fc-handle-1234" || req.Handle.Source != "adapter" || req.RuntimeID != "fc-runtime-1234" {
		t.Fatalf("NewGuestReadinessRequest() = %#v, want sanitized handle and runtime ID", req)
	}
}

func TestGuestReadinessRequestSanitizesUnsafeInputs(t *testing.T) {
	req := SanitizeGuestReadinessRequest(GuestReadinessRequest{
		Handle: ProcessHandleMetadata{
			ID:     "pid:/Users/alice/private/firecracker.sock",
			Source: "env:OPENAI_API_KEY token=ghp_secret",
		},
		RuntimeID: "fc-runtime/Users/alice/private/token",
	})
	if req.Handle.ID != "" || req.Handle.Source != "" || req.RuntimeID != "" {
		t.Fatalf("SanitizeGuestReadinessRequest() = %#v, want unsafe metadata omitted", req)
	}

	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal(GuestReadinessRequest) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"firecracker.sock",
		"OPENAI_API_KEY",
		"ghp_secret",
		"pid:",
		"token",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("guest readiness request leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestGuestReadinessResultShapeAndRuntimeMetadataAreSanitized(t *testing.T) {
	resultType := reflect.TypeOf(GuestReadinessResult{})
	if resultType.NumField() != 5 {
		t.Fatalf("GuestReadinessResult field count = %d, want three durable fields and two live-only proof binding fields", resultType.NumField())
	}
	assertGuestReadinessField(t, resultType, "State", reflect.TypeOf(sandboxruntime.RuntimeGuestReadinessState("")), `json:"state,omitempty"`)
	assertGuestReadinessField(t, resultType, "Transport", reflect.TypeOf(""), `json:"transport,omitempty"`)
	assertGuestReadinessField(t, resultType, "Labels", reflect.TypeOf([]string{}), `json:"labels,omitempty"`)
	assertGuestReadinessField(t, resultType, "IsolationProofGeneration", reflect.TypeOf(""), `json:"-"`)
	assertGuestReadinessField(t, resultType, "IsolationRuntimeGeneration", reflect.TypeOf(""), `json:"-"`)

	result := NewGuestReadinessResult(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"VSock",
		[]string{
			"probe_ok",
			"ready",
			"/Users/alice/private",
			"https://ready.example.test/status",
			"exec_support",
			"copy_support",
			"credential_proxy",
			"pid_1234",
		},
	)
	if result.State != sandboxruntime.RuntimeGuestReadinessStateReady {
		t.Fatalf("State = %q, want ready", result.State)
	}
	if result.Transport != "vsock" {
		t.Fatalf("Transport = %q, want sanitized transport label", result.Transport)
	}
	if !reflect.DeepEqual(result.Labels, []string{"ready", "probe_ok"}) {
		t.Fatalf("Labels = %#v, want canonical ready plus safe labels", result.Labels)
	}

	metadata := result.RuntimeMetadata()
	if metadata == nil {
		t.Fatal("RuntimeMetadata() = nil, want shared guest readiness metadata")
	}
	if metadata.State != result.State || metadata.Transport != result.Transport || !reflect.DeepEqual(metadata.Labels, result.Labels) {
		t.Fatalf("RuntimeMetadata() = %#v, want sanitized result values %#v", metadata, result)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(GuestReadinessResult) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"ready.example.test",
		"exec_support",
		"copy_support",
		"credential_proxy",
		"pid_1234",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("guest readiness result leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestGuestReadinessResultRejectsUnknownState(t *testing.T) {
	result := NewGuestReadinessResult(
		sandboxruntime.RuntimeGuestReadinessState("guest_ready"),
		"vsock",
		[]string{"probe_ok"},
	)
	if !reflect.DeepEqual(result, GuestReadinessResult{}) {
		t.Fatalf("NewGuestReadinessResult(unknown state) = %#v, want empty result", result)
	}
	if metadata := result.RuntimeMetadata(); metadata != nil {
		t.Fatalf("RuntimeMetadata() = %#v, want nil for empty result", metadata)
	}
}

type fakeGuestReadinessWaiter struct {
	calls  int
	wait   func(context.Context, GuestReadinessRequest) (GuestReadinessResult, error)
	last   GuestReadinessRequest
	result GuestReadinessResult
	err    error
}

var _ GuestReadinessWaiter = (*fakeGuestReadinessWaiter)(nil)

func (waiter *fakeGuestReadinessWaiter) WaitForGuestReadiness(ctx context.Context, req GuestReadinessRequest) (GuestReadinessResult, error) {
	waiter.calls++
	waiter.last = req
	if waiter.wait != nil {
		return waiter.wait(ctx, req)
	}
	return waiter.result, waiter.err
}

func assertGuestReadinessField(t *testing.T, typ reflect.Type, name string, wantType reflect.Type, wantJSON string) {
	t.Helper()
	field, ok := typ.FieldByName(name)
	if !ok {
		t.Fatalf("%s missing field %s", typ.Name(), name)
	}
	if field.Type != wantType {
		t.Fatalf("%s.%s type = %v, want %v", typ.Name(), name, field.Type, wantType)
	}
	if got := string(field.Tag); got != wantJSON {
		t.Fatalf("%s.%s tag = %q, want %q", typ.Name(), name, got, wantJSON)
	}
}
