package rootlesspodman_test

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

func TestDefaultMetadataIdentifiesRootlessPodmanLocalContainer(t *testing.T) {
	metadata := rootlesspodman.DefaultMetadata()

	if metadata.DriverID != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("DriverID = %q, want %q", metadata.DriverID, sandboxruntime.DriverRootlessPodman)
	}
	if metadata.HostKind != sandbox.SandboxHostKindLocal {
		t.Fatalf("HostKind = %q, want %q", metadata.HostKind, sandbox.SandboxHostKindLocal)
	}
	if metadata.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("IsolationLevel = %q, want %q", metadata.IsolationLevel, sandbox.SandboxIsolationLevelContainer)
	}
	if metadata.IsolationLevel == sandbox.SandboxIsolationLevelVM {
		t.Fatalf("IsolationLevel = %q, rootless Podman metadata must not claim VM isolation", metadata.IsolationLevel)
	}
}

func TestDriverExposesRootlessPodmanMetadata(t *testing.T) {
	driver := rootlesspodman.New(rootlesspodman.Options{})

	if got := driver.ID(); got != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("ID() = %q, want %q", got, sandboxruntime.DriverRootlessPodman)
	}
	if got := driver.Metadata(); got != rootlesspodman.DefaultMetadata() {
		t.Fatalf("Metadata() = %#v, want %#v", got, rootlesspodman.DefaultMetadata())
	}
}

func TestRunnerInterfacesCompileWithFakes(t *testing.T) {
	var _ rootlesspodman.LifecycleCommandRunner = (*fakeCommandRunner)(nil)
	var _ rootlesspodman.ExecCommandRunner = (*fakeCommandRunner)(nil)
	var _ rootlesspodman.CopyCommandRunner = (*fakeCommandRunner)(nil)

	runner := &fakeCommandRunner{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	request := rootlesspodman.CommandRequest{
		Operation: rootlesspodman.OperationExec,
		Args:      []string{"podman", "exec", "hal-dev", "echo", "ok"},
		Env:       map[string]string{"HAL_TEST": "1"},
		WorkDir:   "/workspace",
		Stdin:     bytes.NewBufferString("input"),
		Stdout:    stdout,
		Stderr:    stderr,
	}

	if result, err := runner.RunLifecycleCommand(context.Background(), request); err != nil || result.ExitCode != 0 {
		t.Fatalf("RunLifecycleCommand() = %#v, %v; want exit 0", result, err)
	}
	if result, err := runner.RunExecCommand(context.Background(), request); err != nil || result.ExitCode != 0 {
		t.Fatalf("RunExecCommand() = %#v, %v; want exit 0", result, err)
	}
	if result, err := runner.RunCopyCommand(context.Background(), request); err != nil || result.ExitCode != 0 {
		t.Fatalf("RunCopyCommand() = %#v, %v; want exit 0", result, err)
	}

	if len(runner.execRequests) != 1 || !reflect.DeepEqual(runner.execRequests[0].Args, request.Args) {
		t.Fatalf("exec requests = %#v, want request args preserved", runner.execRequests)
	}
}

func TestCommandRequestContainsStreamingCommandFields(t *testing.T) {
	requestType := reflect.TypeOf(rootlesspodman.CommandRequest{})

	assertFieldType(t, requestType, "Operation", reflect.TypeOf(""))
	assertFieldType(t, requestType, "Args", reflect.TypeOf([]string{}))
	assertFieldType(t, requestType, "Env", reflect.TypeOf(map[string]string{}))
	assertFieldType(t, requestType, "WorkDir", reflect.TypeOf(""))
	assertFieldType(t, requestType, "Stdin", reflect.TypeOf((*io.Reader)(nil)).Elem())
	assertFieldType(t, requestType, "Stdout", reflect.TypeOf((*io.Writer)(nil)).Elem())
	assertFieldType(t, requestType, "Stderr", reflect.TypeOf((*io.Writer)(nil)).Elem())
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

type fakeCommandRunner struct {
	lifecycleRequests []rootlesspodman.CommandRequest
	execRequests      []rootlesspodman.CommandRequest
	copyRequests      []rootlesspodman.CommandRequest
	resultByOperation map[string]rootlesspodman.CommandResult
	errByOperation    map[string]error
	copyResults       []rootlesspodman.CommandResult
	copyErrors        []error
}

func (f *fakeCommandRunner) RunLifecycleCommand(_ context.Context, req rootlesspodman.CommandRequest) (rootlesspodman.CommandResult, error) {
	f.lifecycleRequests = append(f.lifecycleRequests, req)
	return f.commandResult(req.Operation)
}

func (f *fakeCommandRunner) RunExecCommand(_ context.Context, req rootlesspodman.CommandRequest) (rootlesspodman.CommandResult, error) {
	f.execRequests = append(f.execRequests, req)
	return f.commandResult(req.Operation)
}

func (f *fakeCommandRunner) RunCopyCommand(_ context.Context, req rootlesspodman.CommandRequest) (rootlesspodman.CommandResult, error) {
	f.copyRequests = append(f.copyRequests, req)
	index := len(f.copyRequests) - 1
	if index < len(f.copyResults) || index < len(f.copyErrors) {
		result := rootlesspodman.CommandResult{ExitCode: 0}
		if index < len(f.copyResults) {
			result = f.copyResults[index]
		}
		var err error
		if index < len(f.copyErrors) {
			err = f.copyErrors[index]
		}
		return result, err
	}
	return f.commandResult(req.Operation)
}

func (f *fakeCommandRunner) commandResult(operation string) (rootlesspodman.CommandResult, error) {
	result := rootlesspodman.CommandResult{ExitCode: 0}
	if f.resultByOperation != nil {
		if configured, ok := f.resultByOperation[operation]; ok {
			result = configured
		}
	}
	var err error
	if f.errByOperation != nil {
		err = f.errByOperation[operation]
	}
	return result, err
}

func (f *fakeCommandRunner) lifecycleOperations() []string {
	operations := make([]string, 0, len(f.lifecycleRequests))
	for _, req := range f.lifecycleRequests {
		operations = append(operations, req.Operation)
	}
	return operations
}

func (f *fakeCommandRunner) copyOperations() []string {
	operations := make([]string, 0, len(f.copyRequests))
	for _, req := range f.copyRequests {
		operations = append(operations, req.Operation)
	}
	return operations
}
