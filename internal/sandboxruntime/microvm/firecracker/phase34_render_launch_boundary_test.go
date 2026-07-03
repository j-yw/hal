package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase34LiveBootRendersBootFilesIntoStateDirBeforeLaunch(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "firecracker-state")
	config := phase34LiveBootFakeConfig(t)
	starter := &phase34RenderLaunchStarter{}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         stateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: starter},
		BootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		LiveProcessManager:   fakeLiveBootSafetyHooks{},
		LiveStart:            true,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      "phase34-render-before-launch",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	backendConfig := phase34ExpectedLiveBootConfig(t, config, stateRoot, created.Runtime.RuntimeID)
	starter.beforeLaunch = func(req ProcessRunnerStartRequest) {
		phase34AssertRenderedLiveBootFiles(t, backendConfig)
		phase34AssertProcessRunnerStartRequest(t, req, backendConfig)
	}

	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil after rendering boot files before injected launch", err)
	}

	if starter.startCalls != 1 {
		t.Fatalf("starter calls = %d, want one injected ProcessRunnerStartRequest launch", starter.startCalls)
	}
	if started == nil || started.Runtime.Metadata == nil || started.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("started target metadata = %#v, want safe launch metadata after fake live boot", started)
	}
	if started.Runtime.Metadata.ProcessLaunch.State != string(ProcessLaunchStateAccepted) {
		t.Fatalf("ProcessLaunch.State = %q, want %q", started.Runtime.Metadata.ProcessLaunch.State, ProcessLaunchStateAccepted)
	}
}

func TestPhase34LiveBootRenderFailurePreventsLaunchAndSanitizesError(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "private-render-state")
	if err := os.WriteFile(stateRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile(state root blocker) error = %v", err)
	}
	config := phase34LiveBootFakeConfig(t)
	starter := &phase34RenderLaunchStarter{}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         stateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: starter},
		BootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		LiveProcessManager:   fakeLiveBootSafetyHooks{},
		LiveStart:            true,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      "phase34-render-failure",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil because render failures occur during Start", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})

	if started != nil {
		t.Fatalf("Start() target = %#v, want nil when boot-file rendering fails", started)
	}
	if starter.startCalls != 0 {
		t.Fatalf("starter calls = %d, want render failure to prevent process launch", starter.startCalls)
	}
	phase34AssertSanitizedLiveBootRenderError(t, err,
		stateRoot,
		filepath.Base(stateRoot),
		"private-render-state",
		"firecracker-config.json",
		"firecracker.log",
		"firecracker.metrics",
		"vmlinux",
		"rootfs.ext4",
		"initrd.img",
	)
}

type phase34RenderLaunchStarter struct {
	startCalls   int
	request      ProcessRunnerStartRequest
	beforeLaunch func(ProcessRunnerStartRequest)
}

func (starter *phase34RenderLaunchStarter) StartProcess(_ context.Context, req ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	starter.startCalls++
	starter.request = req
	if starter.beforeLaunch != nil {
		starter.beforeLaunch(req)
	}
	return ProcessHandleMetadata{
		ID:     "phase34-live-boot",
		Source: "fake-starter",
	}, nil
}

func phase34LiveBootFakeConfig(t *testing.T) microvm.Config {
	t.Helper()

	root := t.TempDir()
	config := validMicroVMConfig()
	config.HypervisorPath = filepath.Join(root, "bin", "firecracker")
	config.KernelImagePath = filepath.Join(root, "images", "vmlinux")
	config.RootfsPath = filepath.Join(root, "images", "rootfs.ext4")
	config.InitrdPath = filepath.Join(root, "images", "initrd.img")
	config.CPUCount = 3
	config.MemoryMiB = 1536
	return config
}

func phase34ExpectedLiveBootConfig(t *testing.T, input microvm.Config, stateRoot, runtimeID string) BackendConfig {
	t.Helper()

	config, err := BackendConfigFromMicroVMConfig(input)
	if err != nil {
		t.Fatalf("BackendConfigFromMicroVMConfig() error = %v, want nil", err)
	}
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    runtimeID,
		BaseStateDir: stateRoot,
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	config.RuntimeID = runtimeID
	config.Paths = paths
	return config
}

func phase34AssertRenderedLiveBootFiles(t *testing.T, config BackendConfig) {
	t.Helper()

	if info, err := os.Stat(config.Paths.StateDir); err != nil {
		t.Fatalf("state dir %q missing before launch: %v", config.Paths.StateDir, err)
	} else if !info.IsDir() {
		t.Fatalf("state dir %q is not a directory", config.Paths.StateDir)
	}
	phase34AssertPathUnderStateDir(t, config.Paths.ConfigPath, config.Paths.StateDir)
	phase34AssertPathUnderStateDir(t, config.Paths.LogPath, config.Paths.StateDir)
	phase34AssertPathUnderStateDir(t, config.Paths.MetricsPath, config.Paths.StateDir)
	phase34AssertRegularFile(t, config.Paths.ConfigPath)
	phase34AssertRegularFile(t, config.Paths.LogPath)
	phase34AssertRegularFile(t, config.Paths.MetricsPath)

	rawConfig, err := os.ReadFile(config.Paths.ConfigPath)
	if err != nil {
		t.Fatalf("ReadFile(rendered config) error = %v", err)
	}
	var rendered map[string]json.RawMessage
	if err := json.Unmarshal(rawConfig, &rendered); err != nil {
		t.Fatalf("rendered config JSON is invalid: %v\n%s", err, string(rawConfig))
	}

	machineConfig, err := RenderMachineConfigPayload(config)
	if err != nil {
		t.Fatalf("RenderMachineConfigPayload() error = %v, want nil", err)
	}
	phase34AssertRawPayload(t, rendered, "machine-config", machineConfig)

	bootSource, err := RenderBootSourcePayload(config)
	if err != nil {
		t.Fatalf("RenderBootSourcePayload() error = %v, want nil", err)
	}
	phase34AssertRawPayload(t, rendered, "boot-source", bootSource)

	rootDrive, err := RenderRootDrivePayload(config)
	if err != nil {
		t.Fatalf("RenderRootDrivePayload() error = %v, want nil", err)
	}
	phase34AssertRootDrivePayload(t, rendered, rootDrive)
	phase34AssertRawJSONContainsString(t, rawConfig, config.Paths.LogPath)
	phase34AssertRawJSONContainsString(t, rawConfig, config.Paths.MetricsPath)
}

func phase34AssertProcessRunnerStartRequest(t *testing.T, req ProcessRunnerStartRequest, config BackendConfig) {
	t.Helper()

	if req.Executable != config.ExecutablePath {
		t.Fatalf("runner Executable = %q, want %q", req.Executable, config.ExecutablePath)
	}
	wantArgs := []string{
		"--api-sock", config.Paths.APISocketPath,
		"--config-file", config.Paths.ConfigPath,
		"--log-path", config.Paths.LogPath,
		"--metrics-path", config.Paths.MetricsPath,
	}
	if !reflect.DeepEqual(req.Args, wantArgs) {
		t.Fatalf("runner Args = %#v, want %#v", req.Args, wantArgs)
	}
	if req.Environment == nil {
		t.Fatal("runner Environment = nil, want explicit empty list")
	}
	if len(req.Environment) != 0 {
		t.Fatalf("runner Environment = %#v, want no host environment delivery", req.Environment)
	}
}

func phase34AssertPathUnderStateDir(t *testing.T, path, stateDir string) {
	t.Helper()

	if !strings.HasPrefix(path, stateDir+string(filepath.Separator)) {
		t.Fatalf("path %q is outside state dir %q", path, stateDir)
	}
}

func phase34AssertRegularFile(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file %q missing before launch: %v", path, err)
	}
	if info.IsDir() {
		t.Fatalf("file %q is a directory, want regular support file", path)
	}
}

func phase34AssertRawPayload(t *testing.T, rendered map[string]json.RawMessage, key string, want any) {
	t.Helper()

	raw, ok := rendered[key]
	if !ok {
		t.Fatalf("rendered config missing %q payload; keys=%v", key, phase34RenderedConfigKeys(rendered))
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal(%s payload) error = %v", key, err)
	}
	if !phase34EqualCompactJSON(raw, wantJSON) {
		t.Fatalf("%s payload = %s, want %s", key, string(raw), string(wantJSON))
	}
}

func phase34AssertRootDrivePayload(t *testing.T, rendered map[string]json.RawMessage, want RootDrivePayload) {
	t.Helper()

	raw, ok := rendered["drives"]
	if !ok {
		t.Fatalf("rendered config missing drives payload; keys=%v", phase34RenderedConfigKeys(rendered))
	}
	var drives []RootDrivePayload
	if err := json.Unmarshal(raw, &drives); err != nil {
		t.Fatalf("rendered drives payload is invalid: %v\n%s", err, string(raw))
	}
	if !reflect.DeepEqual(drives, []RootDrivePayload{want}) {
		t.Fatalf("drives payload = %#v, want single root drive %#v", drives, want)
	}
}

func phase34AssertRawJSONContainsString(t *testing.T, raw []byte, want string) {
	t.Helper()

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal(%q) error = %v", want, err)
	}
	if !strings.Contains(string(raw), string(encoded)) {
		t.Fatalf("rendered config %s does not contain support path %s", string(raw), string(encoded))
	}
}

func phase34RenderedConfigKeys(rendered map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(rendered))
	for key := range rendered {
		keys = append(keys, key)
	}
	return keys
}

func phase34EqualCompactJSON(a, b []byte) bool {
	var compactA bytes.Buffer
	if err := json.Compact(&compactA, a); err != nil {
		return false
	}
	var compactB bytes.Buffer
	if err := json.Compact(&compactB, b); err != nil {
		return false
	}
	return bytes.Equal(compactA.Bytes(), compactB.Bytes())
}

func phase34AssertSanitizedLiveBootRenderError(t *testing.T, err error, unsafeFragments ...string) {
	t.Helper()

	if err == nil {
		t.Fatal("render error = nil, want sanitized OperationError")
	}
	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("render error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code == "" {
		t.Fatalf("render OperationError.Code is empty: %#v", opErr)
	}
	if strings.TrimSpace(opErr.Operation) == "" {
		t.Fatalf("render OperationError.Operation is empty: %#v", opErr)
	}

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(render error) error = %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range unsafeFragments {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("render error leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}
