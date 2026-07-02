package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestBackendImplementsMicroVMBackend(t *testing.T) {
	var _ microvm.Backend = NewBackend(BackendOptions{BaseStateDir: firecrackerPathTestBase("target-state")})
}

func TestBackendCreateReturnsDeterministicTargetMetadata(t *testing.T) {
	backend := NewBackend(BackendOptions{BaseStateDir: firecrackerPathTestBase("target-state")})
	request := microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-dev",
	}

	first, err := backend.Create(context.Background(), request)
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	second, err := backend.Create(context.Background(), request)
	if err != nil {
		t.Fatalf("Create() second error = %v, want nil", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Create() target metadata is not deterministic:\nfirst:  %#v\nsecond: %#v", first, second)
	}

	assertFirecrackerCreatedTarget(t, first, "firecracker-dev")

	other, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-other",
	})
	if err != nil {
		t.Fatalf("Create(other) error = %v, want nil", err)
	}
	if other.Runtime.RuntimeID == first.Runtime.RuntimeID {
		t.Fatalf("different target names produced same runtime ID %q", first.Runtime.RuntimeID)
	}
}

func TestBackendCreateMetadataIsRedactionSafe(t *testing.T) {
	backend := NewBackend(BackendOptions{BaseStateDir: firecrackerPathTestBase("alice", "private", "target-state")})
	config := validMicroVMConfig()
	config.HypervisorPath = "/Users/alice/private/bin/firecracker"
	config.KernelImagePath = "/Users/alice/private/images/vmlinux-secret"
	config.RootfsPath = "/Users/alice/private/images/rootfs-secret.ext4"
	config.InitrdPath = "/Users/alice/private/images/initrd-secret.img"
	config.ImageLabel = "raw-secret-template"
	target, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      "dev /Users/alice/private token=ghp_secret",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}

	encoded, marshalErr := json.Marshal(target)
	if marshalErr != nil {
		t.Fatalf("Marshal(target) error = %v", marshalErr)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"ghp_secret",
		"vmlinux-secret",
		"rootfs-secret.ext4",
		"initrd-secret.img",
		"raw-secret-template",
		DefaultAPISocketPath,
		DefaultConfigPath,
		DefaultLogPath,
		DefaultMetricsPath,
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("created target metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
	if strings.TrimSpace(target.Name) == "" || strings.Contains(target.Name, "ghp_secret") || strings.Contains(target.Name, "/Users") {
		t.Fatalf("target name = %q, want redaction-safe display metadata", target.Name)
	}
}

func TestBackendCreateMetadataDoesNotClaimUnsupportedFirecrackerCapabilities(t *testing.T) {
	backend := NewBackend(BackendOptions{BaseStateDir: firecrackerPathTestBase("target-state")})
	target, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-dev",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}

	if target.Runtime.IsolationLevel != "" {
		t.Fatalf("backend target isolationLevel = %q, want empty until driver metadata is applied after live VM creation exists", target.Runtime.IsolationLevel)
	}
	if target.Runtime.Metadata == nil {
		t.Fatal("runtime metadata = nil, want Firecracker capability metadata")
	}
	metadataText := strings.Join(append(append([]string{}, target.Runtime.Metadata.CapabilityLabels...), target.Runtime.Metadata.PathRoles...), " ")
	for _, unsupported := range []string{
		"live_vm_isolation",
		"deny_by_default",
		"credential_proxy",
		"network_proxy",
		"guest_agent",
		"vsock_exec",
		"file_copy",
		sandbox.SandboxNetworkPolicyDenyByDefault,
	} {
		if strings.Contains(metadataText, unsupported) {
			t.Fatalf("created target metadata claims unsupported capability %q in %q", unsupported, metadataText)
		}
	}
	if target.Connection.Address != "" || target.Connection.PublicIP != "" || target.Connection.TailscaleIP != "" || target.Connection.WorkspaceID != "" {
		t.Fatalf("target connection metadata = %#v, want no live connection claims", target.Connection)
	}
}

func TestBackendStartReturnsSanitizedOperationPlanWithoutStartingProcess(t *testing.T) {
	adapter := &fakeProcessAdapter{}
	backend := NewBackend(BackendOptions{
		BaseStateDir:   firecrackerPathTestBase("start-state"),
		ProcessAdapter: adapter,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-dev",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}

	if adapter.prepareCalls != 1 {
		t.Fatalf("prepare calls = %d, want 1", adapter.prepareCalls)
	}
	if adapter.startCalls != 0 {
		t.Fatalf("start calls = %d, want 0 for start planning", adapter.startCalls)
	}
	if started == nil {
		t.Fatal("Start() target = nil, want planning target")
	}
	if started.Status != sandbox.StatusStopped {
		t.Fatalf("started Status = %q, want %q because this phase plans without live launch", started.Status, sandbox.StatusStopped)
	}
	if started.Runtime.Metadata == nil || started.Runtime.Metadata.OperationPlan == nil {
		t.Fatalf("runtime metadata = %#v, want sanitized operation plan", started.Runtime.Metadata)
	}

	plan := started.Runtime.Metadata.OperationPlan
	if plan.Action != string(OperationActionStart) {
		t.Fatalf("operation plan Action = %q, want %q", plan.Action, OperationActionStart)
	}
	if plan.ProcessDescriptor == nil {
		t.Fatal("operation plan ProcessDescriptor = nil, want sanitized descriptor metadata")
	}
	descriptor := plan.ProcessDescriptor
	if descriptor.Action != string(OperationActionStart) {
		t.Fatalf("descriptor Action = %q, want %q", descriptor.Action, OperationActionStart)
	}
	if descriptor.ExecutableRole != string(OperationPathRoleExecutable) {
		t.Fatalf("descriptor ExecutableRole = %q, want %q", descriptor.ExecutableRole, OperationPathRoleExecutable)
	}
	wantArgv := []sandboxruntime.RuntimeOperationArgument{
		{PathRole: string(OperationPathRoleExecutable)},
		{Value: "--api-sock"},
		{PathRole: string(OperationPathRoleAPISocket)},
		{Value: "--config-file"},
		{PathRole: string(OperationPathRoleConfig)},
		{Value: "--log-path"},
		{PathRole: string(OperationPathRoleLog)},
		{Value: "--metrics-path"},
		{PathRole: string(OperationPathRoleMetrics)},
	}
	if !reflect.DeepEqual(descriptor.Argv, wantArgv) {
		t.Fatalf("descriptor Argv = %#v, want %#v", descriptor.Argv, wantArgv)
	}
	if descriptor.Environment == nil || len(descriptor.Environment) != 0 {
		t.Fatalf("descriptor Environment = %#v, want explicit empty metadata list", descriptor.Environment)
	}
	wantPathRoles := []string{
		string(OperationPathRoleAPISocket),
		string(OperationPathRoleConfig),
		string(OperationPathRoleLog),
		string(OperationPathRoleMetrics),
	}
	if !reflect.DeepEqual(descriptor.PathRoles, wantPathRoles) {
		t.Fatalf("descriptor PathRoles = %#v, want %#v", descriptor.PathRoles, wantPathRoles)
	}
	wantPayloads := []sandboxruntime.RuntimeOperationPayload{
		{Role: string(OperationPayloadRoleMachineConfig), APIPath: firecrackerMachineConfigAPIPath},
		{Role: string(OperationPayloadRoleBootSource), APIPath: firecrackerBootSourceAPIPath},
		{Role: string(OperationPayloadRoleRootDrive), APIPath: firecrackerRootDriveAPIPath},
	}
	if !reflect.DeepEqual(descriptor.Payloads, wantPayloads) {
		t.Fatalf("descriptor Payloads = %#v, want %#v", descriptor.Payloads, wantPayloads)
	}

	encoded, marshalErr := json.Marshal(started)
	if marshalErr != nil {
		t.Fatalf("Marshal(started) error = %v", marshalErr)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/usr/bin/firecracker",
		"/opt/hal/images",
		"rootfs.ext4",
		"vmlinux",
		"firecracker.sock",
		"firecracker-config.json",
		"firecracker.log",
		"firecracker.metrics",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("start operation metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestBackendStartRejectsInvalidPathPlanWithOperationError(t *testing.T) {
	backend := NewBackend(BackendOptions{BaseStateDir: "alice/private/firecracker-state"})
	target := sandboxruntime.Target{
		ID:       "runtime-alpha",
		Name:     "firecracker-dev",
		Provider: BackendID,
		Status:   sandbox.StatusStopped,
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverMicroVM,
			RuntimeID: "runtime-alpha",
		},
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	_, err = controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})

	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeInvalidConfig, PathPlanningOperation, "baseStateDir")
	assertFirecrackerErrorDoesNotLeak(t, err, "alice/private", "firecracker-state")
}

func TestBackendStartReturnsSanitizedProcessAdapterFailure(t *testing.T) {
	adapter := &fakeProcessAdapter{
		prepare: func(context.Context, ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
			return ProcessCommandDescriptor{}, errors.New("prepare failed at /Users/alice/private/firecracker.sock token=ghp_secret")
		},
	}
	backend := NewBackend(BackendOptions{
		BaseStateDir:   firecrackerPathTestBase("start-failure-state"),
		ProcessAdapter: adapter,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-dev",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	_, err = controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})

	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeBackendOperationFailed, ProcessBoundaryOperation, "processAdapter")
	assertFirecrackerErrorDoesNotLeak(t, err, "/Users/alice", "private", "firecracker.sock", "ghp_secret")
}

func TestMicroVMDriverCreateCanUseInjectedFirecrackerBackend(t *testing.T) {
	backend := NewBackend(BackendOptions{BaseStateDir: firecrackerPathTestBase("driver-target-state")})
	kvmReadable := true
	driver := microvm.NewDriver(microvm.DriverOptions{
		Config: validMicroVMConfig(),
		CapabilityDetector: microvm.CapabilityDetectorFunc(func(microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
			return microvm.CapabilityReport{
				OS:               "linux",
				Architecture:     "amd64",
				KVMDevicePresent: true,
				KVMReadable:      &kvmReadable,
				Availability:     microvm.CapabilityAvailabilityAvailable,
				ReasonCode:       microvm.CapabilityReasonAvailable,
			}
		}),
		Backend: backend,
	})

	target, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-dev"})
	if err != nil {
		t.Fatalf("driver Create() error = %v, want nil", err)
	}
	assertFirecrackerCreatedTarget(t, target, "firecracker-dev")
	if target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("driver-created target isolationLevel = %q, want microVM driver metadata %q", target.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelVM)
	}
}

func assertFirecrackerCreatedTarget(t *testing.T, target *sandboxruntime.Target, wantName string) {
	t.Helper()
	if target == nil {
		t.Fatal("target = nil, want Firecracker target")
	}
	if target.ID == "" || !strings.HasPrefix(target.ID, "fc-") || len(target.ID) > maxPathPlanRuntimeIDBytes {
		t.Fatalf("target ID = %q, want stable safe Firecracker runtime ID", target.ID)
	}
	if target.Name != wantName {
		t.Fatalf("target Name = %q, want %q", target.Name, wantName)
	}
	if target.Provider != BackendID {
		t.Fatalf("target Provider = %q, want %q", target.Provider, BackendID)
	}
	if target.Status != sandbox.StatusStopped {
		t.Fatalf("target Status = %q, want %q", target.Status, sandbox.StatusStopped)
	}
	if target.Runtime.Driver != sandboxruntime.DriverMicroVM {
		t.Fatalf("runtime Driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverMicroVM)
	}
	if target.Runtime.Metadata == nil {
		t.Fatal("runtime Metadata = nil, want Firecracker metadata")
	}
	if target.Runtime.Metadata.Backend != BackendID {
		t.Fatalf("runtime metadata Backend = %q, want %q", target.Runtime.Metadata.Backend, BackendID)
	}
	if target.Runtime.RuntimeID != target.ID {
		t.Fatalf("runtime RuntimeID = %q, want target ID %q", target.Runtime.RuntimeID, target.ID)
	}
	wantCapabilities := []string{
		"target_creation",
		"deterministic_identity",
		"path_role_metadata",
		"process_boundary",
	}
	if !reflect.DeepEqual(target.Runtime.Metadata.CapabilityLabels, wantCapabilities) {
		t.Fatalf("runtime metadata CapabilityLabels = %#v, want %#v", target.Runtime.Metadata.CapabilityLabels, wantCapabilities)
	}
	wantPathRoles := []string{
		string(OperationPathRoleStateDir),
		string(OperationPathRoleAPISocket),
		string(OperationPathRoleConfig),
		string(OperationPathRoleLog),
		string(OperationPathRoleMetrics),
	}
	if !reflect.DeepEqual(target.Runtime.Metadata.PathRoles, wantPathRoles) {
		t.Fatalf("runtime metadata PathRoles = %#v, want %#v", target.Runtime.Metadata.PathRoles, wantPathRoles)
	}
}

func assertFirecrackerStartOperationError(t *testing.T, err error, code microvm.ErrorCode, operation, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("start operation error = nil, want OperationError")
	}
	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code != code {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, code)
	}
	if opErr.Operation != operation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, operation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}
