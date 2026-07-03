package sandboxruntime

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeDriverIDConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "ssh machine", got: DriverSSHMachine, want: "ssh_machine"},
		{name: "rootless podman", got: DriverRootlessPodman, want: "rootless_podman"},
		{name: "microVM", got: DriverMicroVM, want: "microvm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("driver ID = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

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

func TestRuntimeMetadataIncludesOptionalProcessLaunchMetadata(t *testing.T) {
	metadataType := reflect.TypeOf(RuntimeMetadata{})
	assertFieldType(t, metadataType, "ProcessLaunch", reflect.TypeOf((*RuntimeProcessLaunchMetadata)(nil)))

	launchType := reflect.TypeOf(RuntimeProcessLaunchMetadata{})
	assertFieldType(t, launchType, "State", reflect.TypeOf(""))
	assertFieldType(t, launchType, "Labels", reflect.TypeOf([]string{}))
	assertFieldType(t, launchType, "ProcessID", reflect.TypeOf(""))
	assertFieldType(t, launchType, "ProcessIDSource", reflect.TypeOf(""))

	metadata := RuntimeMetadata{
		Backend: "firecracker",
		ProcessLaunch: &RuntimeProcessLaunchMetadata{
			State:           "process_launch_accepted",
			Labels:          []string{"process_launch_accepted"},
			ProcessID:       "pid-1234",
			ProcessIDSource: "adapter",
		},
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"processLaunch":`,
		`"state":"process_launch_accepted"`,
		`"labels":["process_launch_accepted"]`,
		`"processId":"pid-1234"`,
		`"processIdSource":"adapter"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
}

func TestRuntimeMetadataIncludesOptionalGuestReadinessMetadata(t *testing.T) {
	metadataType := reflect.TypeOf(RuntimeMetadata{})
	assertFieldType(t, metadataType, "GuestReadiness", reflect.TypeOf((*RuntimeGuestReadinessMetadata)(nil)))

	readinessType := reflect.TypeOf(RuntimeGuestReadinessMetadata{})
	assertFieldType(t, readinessType, "State", reflect.TypeOf(RuntimeGuestReadinessState("")))
	assertFieldType(t, readinessType, "Transport", reflect.TypeOf(""))
	assertFieldType(t, readinessType, "Labels", reflect.TypeOf([]string{}))

	metadata := RuntimeMetadata{
		Backend: "firecracker",
		GuestReadiness: NewRuntimeGuestReadinessMetadata(
			RuntimeGuestReadinessStateWaiting,
			"VSock",
			[]string{"probe_pending", "waiting"},
		),
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"guestReadiness":`,
		`"state":"waiting"`,
		`"transport":"vsock"`,
		`"labels":["waiting","probe_pending"]`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
}

func TestRuntimeGuestReadinessMetadataStatesAreStable(t *testing.T) {
	tests := []struct {
		name  string
		state RuntimeGuestReadinessState
		want  string
	}{
		{name: "not configured", state: RuntimeGuestReadinessStateNotConfigured, want: "not_configured"},
		{name: "waiting", state: RuntimeGuestReadinessStateWaiting, want: "waiting"},
		{name: "ready", state: RuntimeGuestReadinessStateReady, want: "ready"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.state) != tt.want {
				t.Fatalf("guest readiness state = %q, want %q", tt.state, tt.want)
			}
			metadata := NewRuntimeGuestReadinessMetadata(tt.state, "vsock", nil)
			if metadata == nil {
				t.Fatal("NewRuntimeGuestReadinessMetadata() = nil, want metadata")
			}
			if metadata.State != tt.state {
				t.Fatalf("metadata State = %q, want %q", metadata.State, tt.state)
			}
		})
	}
}

func TestRuntimeGuestReadinessMetadataSanitizesUnsafeValues(t *testing.T) {
	metadata := SanitizeRuntimeGuestReadinessMetadata(&RuntimeGuestReadinessMetadata{
		State:     RuntimeGuestReadinessStateReady,
		Transport: "tcp://127.0.0.1:9000/private/firecracker.sock?token=ghp_secret",
		Labels: []string{
			"ready",
			"probe_ok",
			"/Users/alice/private",
			"https://guest-ready.example.test:8443/status",
			"127.0.0.1",
			"OPENAI_API_KEY",
			"guest_command_payload",
			"exec_support",
			"copy_support",
			"credential_proxy",
			"template_ready",
			"hosted_vendor",
			"secure_runtime",
			"image_ready",
			"provisioned",
			"guest_agent",
			"ssh_ready",
		},
	})
	if metadata == nil {
		t.Fatal("SanitizeRuntimeGuestReadinessMetadata() = nil, want sanitized metadata")
	}
	if metadata.Transport != "" {
		t.Fatalf("unsafe Transport = %q, want omitted", metadata.Transport)
	}
	if !reflect.DeepEqual(metadata.Labels, []string{"ready", "probe_ok"}) {
		t.Fatalf("Labels = %#v, want canonical ready plus safe label only", metadata.Labels)
	}

	encoded, err := json.Marshal(RuntimeMetadata{GuestReadiness: metadata})
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"127.0.0.1",
		"9000",
		"firecracker.sock",
		"guest-ready.example.test",
		"ghp_secret",
		"OPENAI_API_KEY",
		"guest_command_payload",
		"exec_support",
		"copy_support",
		"credential_proxy",
		"template_ready",
		"hosted_vendor",
		"secure_runtime",
		"image_ready",
		"provisioned",
		"guest_agent",
		"ssh_ready",
		"token=",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("guest readiness metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
	for _, want := range []string{
		`"guestReadiness":`,
		`"state":"ready"`,
		`"labels":["ready","probe_ok"]`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("guest readiness metadata JSON %s missing %s", publicText, want)
		}
	}
}

func TestRuntimeGuestReadinessMetadataDoesNotClaimExecOrCopySupport(t *testing.T) {
	metadata := RuntimeMetadata{
		Backend:        "firecracker",
		GuestReadiness: NewRuntimeGuestReadinessMetadata(RuntimeGuestReadinessStateReady, "vsock", []string{"probe_ok"}),
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, unsupported := range []string{
		"exec",
		"copy",
		"copyin",
		"copyout",
		"guest_agent",
		"guest_command",
		"file_transfer",
		"template",
		"image",
		"provision",
		"ssh",
	} {
		if strings.Contains(publicText, unsupported) {
			t.Fatalf("guest readiness metadata claims unsupported capability %q in %s", unsupported, publicText)
		}
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
