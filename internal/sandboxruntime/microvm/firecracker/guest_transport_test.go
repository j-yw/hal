package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestGuestTransportInterfaceIncludesExecCopyInAndCopyOut(t *testing.T) {
	var _ GuestTransport = &fakeGuestTransport{}

	stdin := strings.NewReader("stdin")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	target := sandboxruntime.Target{ID: "runtime-alpha", Name: "firecracker-dev", Provider: BackendID}
	transport := &fakeGuestTransport{}
	ctx := context.Background()

	result, err := transport.Exec(ctx, GuestExecRequest{
		Target:  target,
		Args:    []string{"sh", "-lc", "true"},
		Env:     map[string]string{"HAL_TEST": "1"},
		WorkDir: "/workspace/project",
		Stdin:   stdin,
		Stdout:  stdout,
		Stderr:  stderr,
	})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("Exec() exit code = %d, want 7", result.ExitCode)
	}
	if transport.execCalls != 1 {
		t.Fatalf("Exec() calls = %d, want 1", transport.execCalls)
	}
	if err := transport.CopyIn(ctx, GuestCopyRequest{
		Target:          target,
		SourcePath:      "/safe/input.txt",
		DestinationPath: "/workspace/input.txt",
	}); err != nil {
		t.Fatalf("CopyIn() unexpected error: %v", err)
	}
	if err := transport.CopyOut(ctx, GuestCopyRequest{
		Target:          target,
		SourcePath:      "/workspace/output.txt",
		DestinationPath: "/safe/output.txt",
	}); err != nil {
		t.Fatalf("CopyOut() unexpected error: %v", err)
	}
	if transport.copyInCalls != 1 || transport.copyOutCalls != 1 {
		t.Fatalf("copy calls = in:%d out:%d, want 1 each", transport.copyInCalls, transport.copyOutCalls)
	}
}

func TestGuestExecRequestContainsOnlyInjectedBoundaryFields(t *testing.T) {
	assertExactGuestRequestFields(t, reflect.TypeOf(GuestExecRequest{}), []guestRequestField{
		{name: "Target", typ: reflect.TypeOf(sandboxruntime.Target{})},
		{name: "Args", typ: reflect.TypeOf([]string{})},
		{name: "Env", typ: reflect.TypeOf(map[string]string{})},
		{name: "WorkDir", typ: reflect.TypeOf("")},
		{name: "Stdin", typ: reflect.TypeOf((*io.Reader)(nil)).Elem()},
		{name: "Stdout", typ: reflect.TypeOf((*io.Writer)(nil)).Elem()},
		{name: "Stderr", typ: reflect.TypeOf((*io.Writer)(nil)).Elem()},
	})
}

func TestGuestCopyRequestContainsOnlyInjectedBoundaryFields(t *testing.T) {
	assertExactGuestRequestFields(t, reflect.TypeOf(GuestCopyRequest{}), []guestRequestField{
		{name: "Target", typ: reflect.TypeOf(sandboxruntime.Target{})},
		{name: "SourcePath", typ: reflect.TypeOf("")},
		{name: "DestinationPath", typ: reflect.TypeOf("")},
	})
}

func TestGuestTransportRequestsOmitRawBoundaryDataFromJSON(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	execReq := GuestExecRequest{
		Target:  sandboxruntime.Target{ID: "runtime-secret", Name: "private-target", Provider: BackendID},
		Args:    []string{"sh", "-lc", "cat /Users/alice/private/socket token=ghp_secret"},
		Env:     map[string]string{"SECRET_TOKEN": "ghp_secret"},
		WorkDir: "/Users/alice/private/workspace",
		Stdin:   strings.NewReader("secret stdin"),
		Stdout:  stdout,
		Stderr:  stderr,
	}
	copyReq := GuestCopyRequest{
		Target:          sandboxruntime.Target{ID: "runtime-secret", Name: "private-target", Provider: BackendID},
		SourcePath:      "/Users/alice/private/input-token-ghp_secret.txt",
		DestinationPath: "/workspace/input-token-ghp_secret.txt",
	}

	encodedExec, err := json.Marshal(execReq)
	if err != nil {
		t.Fatalf("Marshal(GuestExecRequest) error = %v", err)
	}
	encodedCopy, err := json.Marshal(copyReq)
	if err != nil {
		t.Fatalf("Marshal(GuestCopyRequest) error = %v", err)
	}
	if string(encodedExec) != "{}" {
		t.Fatalf("GuestExecRequest JSON = %s, want {}", encodedExec)
	}
	if string(encodedCopy) != "{}" {
		t.Fatalf("GuestCopyRequest JSON = %s, want {}", encodedCopy)
	}
}

type guestRequestField struct {
	name string
	typ  reflect.Type
}

func assertExactGuestRequestFields(t *testing.T, typ reflect.Type, want []guestRequestField) {
	t.Helper()

	if typ.NumField() != len(want) {
		t.Fatalf("%s field count = %d, want %d", typ.Name(), typ.NumField(), len(want))
	}
	for index, field := range want {
		got := typ.Field(index)
		if got.Name != field.name {
			t.Fatalf("%s field %d name = %q, want %q", typ.Name(), index, got.Name, field.name)
		}
		if got.Type != field.typ {
			t.Fatalf("%s.%s type = %v, want %v", typ.Name(), field.name, got.Type, field.typ)
		}
		if tag := got.Tag.Get("json"); tag != "-" {
			t.Fatalf("%s.%s json tag = %q, want -", typ.Name(), field.name, tag)
		}
	}
}

type fakeGuestTransport struct {
	execCalls    int
	copyInCalls  int
	copyOutCalls int
}

func (f *fakeGuestTransport) Exec(_ context.Context, req GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	f.execCalls++
	if req.Stdin == nil || req.Stdout == nil || req.Stderr == nil {
		return nil, errFakeGuestTransportMissingStream
	}
	return &sandboxruntime.ExecResult{ExitCode: 7}, nil
}

func (f *fakeGuestTransport) CopyIn(context.Context, GuestCopyRequest) error {
	f.copyInCalls++
	return nil
}

func (f *fakeGuestTransport) CopyOut(context.Context, GuestCopyRequest) error {
	f.copyOutCalls++
	return nil
}

var errFakeGuestTransportMissingStream = &fakeGuestTransportError{}

type fakeGuestTransportError struct{}

func (*fakeGuestTransportError) Error() string {
	return "missing stream"
}
