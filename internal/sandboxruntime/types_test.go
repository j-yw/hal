package sandboxruntime

import (
	"context"
	"io"
	"reflect"
	"testing"
)

func TestLifecycleDriverInterfaceIncludesCoreOperations(t *testing.T) {
	var _ LifecycleDriver = fakeLifecycleDriver{}

	driver := fakeLifecycleDriver{}
	ctx := context.Background()
	target := Target{Name: "dev", Provider: "daytona", Status: "running"}

	if got, err := driver.Create(ctx, CreateRequest{Name: "dev"}); err != nil || got.Name != "dev" {
		t.Fatalf("Create() = %#v, %v; want target named dev", got, err)
	}
	if got, err := driver.Start(ctx, LifecycleRequest{Target: target}); err != nil || got.Status != "running" {
		t.Fatalf("Start() = %#v, %v; want running target", got, err)
	}
	if got, err := driver.Stop(ctx, LifecycleRequest{Target: target}); err != nil || got.Status != "stopped" {
		t.Fatalf("Stop() = %#v, %v; want stopped target", got, err)
	}
	if err := driver.Delete(ctx, LifecycleRequest{Target: target}); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}
	if got, err := driver.Inspect(ctx, InspectRequest{Target: target}); err != nil || got.Name != "dev" {
		t.Fatalf("Inspect() = %#v, %v; want target named dev", got, err)
	}
}

func TestExecRequestContainsStreamingCommandFields(t *testing.T) {
	var _ ExecDriver = fakeExecDriver{}

	requestType := reflect.TypeOf(ExecRequest{})
	assertFieldType(t, requestType, "Target", reflect.TypeOf(Target{}))
	assertFieldType(t, requestType, "Args", reflect.TypeOf([]string{}))
	assertFieldType(t, requestType, "Stdout", reflect.TypeOf((*io.Writer)(nil)).Elem())
	assertFieldType(t, requestType, "Stderr", reflect.TypeOf((*io.Writer)(nil)).Elem())
	assertFieldType(t, requestType, "Stdin", reflect.TypeOf((*io.Reader)(nil)).Elem())
	assertFieldType(t, requestType, "Env", reflect.TypeOf(map[string]string{}))
	assertFieldType(t, requestType, "WorkDir", reflect.TypeOf(""))
}

func TestFileTransportInterfaceIncludesCopyInAndCopyOut(t *testing.T) {
	var _ FileTransport = fakeFileTransport{}

	requestType := reflect.TypeOf(CopyRequest{})
	assertFieldType(t, requestType, "Target", reflect.TypeOf(Target{}))
	assertFieldType(t, requestType, "SourcePath", reflect.TypeOf(""))
	assertFieldType(t, requestType, "DestinationPath", reflect.TypeOf(""))

	transport := fakeFileTransport{}
	ctx := context.Background()
	if err := transport.CopyIn(ctx, CopyRequest{SourcePath: "/host/in", DestinationPath: "/remote/in"}); err != nil {
		t.Fatalf("CopyIn() unexpected error: %v", err)
	}
	if err := transport.CopyOut(ctx, CopyRequest{SourcePath: "/remote/out", DestinationPath: "/host/out"}); err != nil {
		t.Fatalf("CopyOut() unexpected error: %v", err)
	}
}

func assertFieldType(t *testing.T, typ reflect.Type, fieldName string, want reflect.Type) {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("%s field missing from %s", fieldName, typ.Name())
	}
	if field.Type != want {
		t.Fatalf("%s.%s type = %v, want %v", typ.Name(), fieldName, field.Type, want)
	}
}

type fakeLifecycleDriver struct{}

func (fakeLifecycleDriver) Create(context.Context, CreateRequest) (*Target, error) {
	return &Target{Name: "dev"}, nil
}

func (fakeLifecycleDriver) Start(_ context.Context, req LifecycleRequest) (*Target, error) {
	target := req.Target
	target.Status = "running"
	return &target, nil
}

func (fakeLifecycleDriver) Stop(_ context.Context, req LifecycleRequest) (*Target, error) {
	target := req.Target
	target.Status = "stopped"
	return &target, nil
}

func (fakeLifecycleDriver) Delete(context.Context, LifecycleRequest) error {
	return nil
}

func (fakeLifecycleDriver) Inspect(_ context.Context, req InspectRequest) (*Target, error) {
	return &req.Target, nil
}

type fakeExecDriver struct{}

func (fakeExecDriver) Exec(context.Context, ExecRequest) (*ExecResult, error) {
	return &ExecResult{}, nil
}

type fakeFileTransport struct{}

func (fakeFileTransport) CopyIn(context.Context, CopyRequest) error {
	return nil
}

func (fakeFileTransport) CopyOut(context.Context, CopyRequest) error {
	return nil
}
