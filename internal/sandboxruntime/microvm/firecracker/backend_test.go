package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
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
		t.Fatalf("backend target isolationLevel = %q, want empty direct backend metadata; microVM driver applies %q", target.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelVM)
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
	poisonFirecrackerRuntimeMetadata(created)
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
	assertFirecrackerOwnedRuntimeMetadata(t, started)

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
		"guest_agent",
		"network_proxy",
		"SECRET_TOKEN",
		"OPENAI_API_KEY",
		"/Users/alice",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("start operation metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestBackendNetworkEnforcementMetadataIsClonedSanitizedAndPlanningOnly(t *testing.T) {
	processAdapter := &fakeProcessAdapter{}
	networkMetadata := firecrackerBackendNetworkEnforcementMetadata()
	backend := NewBackend(BackendOptions{
		BaseStateDir:       firecrackerPathTestBase("network-metadata"),
		ProcessAdapter:     processAdapter,
		NetworkEnforcement: networkMetadata,
	})

	networkMetadata.Plan.ID = "mutated-plan"
	networkMetadata.Orchestration.PlanID = "mutated-orchestration"
	networkMetadata.Orchestration.Proxy.ID = "mutated-proxy"
	networkMetadata.Orchestration.Rules[0].ID = "mutated-rules"

	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-network-metadata",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	assertFirecrackerNetworkEnforcementPlanningMetadata(t, created)

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
		t.Fatalf("Start() error = %v, want planning-only nil error", err)
	}
	assertFirecrackerNetworkEnforcementPlanningMetadata(t, started)
	if processAdapter.prepareCalls != 1 {
		t.Fatalf("process prepare calls = %d, want 1 planning call", processAdapter.prepareCalls)
	}
	if processAdapter.startCalls != 0 {
		t.Fatalf("process start calls = %d, want none without LiveStart", processAdapter.startCalls)
	}
}

func TestBackendNetworkEnforcementMetadataDoesNotBreakMicroVMPlanningConstruction(t *testing.T) {
	var plannerCalls int
	request := firecrackerBackendNetworkEnforcementPlanRequest()
	planner := networkenforcement.PlannerFunc(func(got networkenforcement.PlanRequest) networkenforcement.Plan {
		plannerCalls++
		if !reflect.DeepEqual(got, request) {
			t.Fatalf("planner request = %#v, want %#v", got, request)
		}
		return networkenforcement.BuildPlan(got)
	})
	networkAdapter := &recordingFirecrackerNetworkEnforcementAdapter{
		result: networkenforcement.Result{
			AdapterID:       "fake-firecracker-network-adapter",
			Outcome:         networkenforcement.ResultOutcomeSuccess,
			EnforcementMode: networkenforcement.ResultModeFirewall,
			Mechanisms:      []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
			Operations:      []string{"firewall_apply"},
			Capability: &networkenforcement.ResultCapability{
				Supported:                  true,
				Modes:                      []networkenforcement.ResultMode{networkenforcement.ResultModeFirewall},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: networkenforcement.ResultReasonApplied,
		},
	}
	processAdapter := &fakeProcessAdapter{}
	driver := microvm.NewDriver(microvm.DriverOptions{
		Config: validMicroVMConfig(),
		CapabilityDetector: microvm.CapabilityDetectorFunc(func(microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
			return microvm.CapabilityReport{
				Availability: microvm.CapabilityAvailabilityAvailable,
				ReasonCode:   microvm.CapabilityReasonAvailable,
			}
		}),
		Backend: NewBackend(BackendOptions{
			BaseStateDir:       firecrackerPathTestBase("planning-compat"),
			ProcessAdapter:     processAdapter,
			NetworkEnforcement: firecrackerBackendNetworkEnforcementMetadata(),
		}),
		NetworkEnforcement: &microvm.NetworkEnforcementPlanning{
			Request: request,
			Planner: planner,
			Adapter: networkAdapter,
		},
	})
	if plannerCalls != 1 || networkAdapter.calls != 1 {
		t.Fatalf("network planner calls=%d adapter calls=%d, want one explicit planning pass", plannerCalls, networkAdapter.calls)
	}
	driverMetadata := driver.Metadata().NetworkEnforcement
	if driverMetadata == nil || driverMetadata.Plan == nil || driverMetadata.Result == nil {
		t.Fatalf("driver NetworkEnforcement = %#v, want existing planning metadata", driverMetadata)
	}
	if driverMetadata.Result.AdapterID != "fake-firecracker-network-adapter" ||
		driverMetadata.Result.EnforcementMode != string(networkenforcement.ResultModeFirewall) {
		t.Fatalf("driver NetworkEnforcement result = %#v, want explicit planning result", driverMetadata.Result)
	}

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-planning-compat"})
	if err != nil {
		t.Fatalf("driver.Create() error = %v, want nil", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("driver.Start() error = %v, want planning-only nil error", err)
	}
	assertFirecrackerNetworkEnforcementPlanningMetadata(t, started)
	if processAdapter.startCalls != 0 {
		t.Fatalf("process start calls = %d, want no live process start from network planning metadata", processAdapter.startCalls)
	}
	if networkAdapter.calls != 1 {
		t.Fatalf("network adapter calls = %d, want no additional live enforcement during Create/Start", networkAdapter.calls)
	}
}

func TestBackendStartPublicJSONRedactsPlanningAndLiveLaunchMetadata(t *testing.T) {
	tests := []struct {
		name      string
		liveStart bool
		adapter   ProcessAdapter
	}{
		{
			name:    "planning only",
			adapter: &fakeProcessAdapter{},
		},
		{
			name:      "explicit live start",
			liveStart: true,
			adapter: &fakeProcessAdapter{
				start: func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
					return ProcessHandleMetadata{
						ID:     "424242",
						Source: "pid=424242",
					}, nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validMicroVMConfig()
			config.HypervisorPath = "/Users/alice/private/bin/firecracker-secret"
			config.KernelImagePath = "/Users/alice/private/images/vmlinux-secret"
			config.RootfsPath = "/Users/alice/private/images/rootfs-secret.ext4"
			config.InitrdPath = "/Users/alice/private/images/initrd-secret.img"
			config.ImageLabel = "template-token-ghp_secret"
			baseStateDir := filepath.Join(t.TempDir(), "Users", "alice", "private", "live-start-json-state")
			options := BackendOptions{
				BaseStateDir:   baseStateDir,
				ProcessAdapter: tt.adapter,
				LiveStart:      tt.liveStart,
			}
			if tt.liveStart {
				safety := fakeLiveBootSafetyHooks{}
				options.BootAcceptanceWaiter = safety
				options.LiveProcessManager = safety
			}
			backend := NewBackend(options)
			created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
				Operation: microvm.OperationCreate,
				Config:    config,
				Name:      "firecracker-live-json token=ghp_secret",
			})
			if err != nil {
				t.Fatalf("Create() error = %v, want nil", err)
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
				t.Fatalf("Start() error = %v, want nil", err)
			}
			if started == nil {
				t.Fatal("Start() target = nil, want Firecracker target")
			}
			assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, started)

			encoded, marshalErr := json.Marshal(started)
			if marshalErr != nil {
				t.Fatalf("Marshal(started) error = %v", marshalErr)
			}
			publicText := string(encoded)
			for _, unsafe := range []string{
				"/Users/alice",
				"private",
				"firecracker-secret",
				"firecracker.sock",
				"firecracker-config.json",
				"firecracker.log",
				"firecracker.metrics",
				"vmlinux-secret",
				"rootfs-secret.ext4",
				"initrd-secret.img",
				"template-token-ghp_secret",
				"ghp_secret",
				"SECRET_TOKEN",
				"OPENAI_API_KEY",
				"424242",
				"pid=424242",
			} {
				if strings.Contains(publicText, unsafe) {
					t.Fatalf("public %s target JSON leaked unsafe fragment %q in %s", tt.name, unsafe, publicText)
				}
			}
		})
	}
}

func TestBackendDefaultOptionsStartRemainsPlanningOnly(t *testing.T) {
	backend := NewBackend(BackendOptions{})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-default",
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
		t.Fatalf("Start() error = %v, want planning-only nil error", err)
	}

	if started == nil {
		t.Fatal("Start() target = nil, want planning target")
	}
	if started.Status != sandbox.StatusStopped {
		t.Fatalf("started Status = %q, want %q for default planning-only start", started.Status, sandbox.StatusStopped)
	}
	assertFirecrackerOwnedRuntimeMetadata(t, started)
	if started.Runtime.Metadata.OperationPlan == nil || started.Runtime.Metadata.OperationPlan.ProcessDescriptor == nil {
		t.Fatalf("runtime operation metadata = %#v, want rendered start plan and descriptor", started.Runtime.Metadata.OperationPlan)
	}
	if started.Runtime.Metadata.ProcessLaunch.State != string(ProcessLaunchStateBoundaryAvailable) {
		t.Fatalf("ProcessLaunch.State = %q, want planning-only %q", started.Runtime.Metadata.ProcessLaunch.State, ProcessLaunchStateBoundaryAvailable)
	}
	if started.Runtime.Metadata.GuestReadiness != nil {
		t.Fatalf("GuestReadiness = %#v, want default backend to leave readiness unconfigured", started.Runtime.Metadata.GuestReadiness)
	}
}

func TestBackendGuestReadinessWaiterIsOptionalAndInertUntilLiveWiring(t *testing.T) {
	waiter := &fakeGuestReadinessWaiter{}
	adapter := &fakeProcessAdapter{
		prepare: func(_ context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
			return ProcessCommandDescriptorFromStartPlan(req.Plan)
		},
		start: func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
			t.Fatal("StartProcess should not run without LiveStart")
			return ProcessHandleMetadata{}, nil
		},
	}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         firecrackerPathTestBase("guest-readiness-planning"),
		ProcessAdapter:       adapter,
		GuestReadinessWaiter: waiter,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-readiness",
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
	firecrackerController, ok := controller.(firecrackerController)
	if !ok {
		t.Fatalf("controller type = %T, want firecrackerController", controller)
	}
	if firecrackerController.guestReadinessWaiter != waiter {
		t.Fatalf("guestReadinessWaiter = %#v, want injected waiter", firecrackerController.guestReadinessWaiter)
	}

	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Start() error = %v, want planning-only nil error", err)
	}
	if waiter.calls != 0 {
		t.Fatalf("guest readiness calls = %d, want none until live readiness wiring is added", waiter.calls)
	}
	if adapter.prepareCalls != 1 || adapter.startCalls != 0 {
		t.Fatalf("adapter calls = prepare:%d start:%d, want planning-only prepare", adapter.prepareCalls, adapter.startCalls)
	}
	if started == nil || started.Runtime.Metadata == nil {
		t.Fatalf("started target = %#v, want Firecracker metadata", started)
	}
	if started.Runtime.Metadata.GuestReadiness != nil {
		t.Fatalf("GuestReadiness = %#v, want absent before explicit readiness wait", started.Runtime.Metadata.GuestReadiness)
	}
	if started.Runtime.Metadata.ProcessLaunch == nil || started.Runtime.Metadata.ProcessLaunch.State != string(ProcessLaunchStateBoundaryAvailable) {
		t.Fatalf("ProcessLaunch = %#v, want planning-only boundary metadata", started.Runtime.Metadata.ProcessLaunch)
	}
}

func TestBackendInjectedAdapterWithoutLiveStartRemainsPlanningOnly(t *testing.T) {
	adapter := &fakeProcessAdapter{
		prepare: func(_ context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
			return ProcessCommandDescriptorFromStartPlan(req.Plan)
		},
		start: func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
			t.Fatal("StartProcess should not run unless LiveStart is explicitly enabled")
			return ProcessHandleMetadata{}, nil
		},
	}
	backend := NewBackend(BackendOptions{
		BaseStateDir:   firecrackerPathTestBase("planning-only-with-adapter"),
		ProcessAdapter: adapter,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-planning-only",
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
		t.Fatalf("Start() error = %v, want planning-only nil error", err)
	}

	if adapter.prepareCalls != 1 || adapter.startCalls != 0 {
		t.Fatalf("adapter calls = prepare:%d start:%d, want one prepare and no process start", adapter.prepareCalls, adapter.startCalls)
	}
	if started == nil || started.Runtime.Metadata == nil || started.Runtime.Metadata.OperationPlan == nil {
		t.Fatalf("started target metadata = %#v, want planning metadata", started)
	}
	if started.Runtime.Metadata.ProcessLaunch == nil || started.Runtime.Metadata.ProcessLaunch.State != string(ProcessLaunchStateBoundaryAvailable) {
		t.Fatalf("ProcessLaunch = %#v, want boundary-available planning metadata", started.Runtime.Metadata.ProcessLaunch)
	}
}

func TestBackendLiveStartOptionCallsInjectedAdapterAfterPlanRendered(t *testing.T) {
	var events []string
	adapter := &fakeProcessAdapter{
		prepare: func(_ context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
			events = append(events, "prepare")
			if req.Plan.Action != OperationActionStart {
				t.Fatalf("PrepareStartCommand plan Action = %q, want %q", req.Plan.Action, OperationActionStart)
			}
			if req.Plan.Executable.Role != OperationPathRoleExecutable {
				t.Fatalf("PrepareStartCommand executable role = %q, want %q", req.Plan.Executable.Role, OperationPathRoleExecutable)
			}
			if len(req.Plan.Argv) == 0 {
				t.Fatal("PrepareStartCommand plan Argv is empty, want rendered process argv")
			}
			return ProcessCommandDescriptorFromStartPlan(req.Plan)
		},
		start: func(_ context.Context, req ProcessStartRequest) (ProcessHandleMetadata, error) {
			events = append(events, "start")
			if req.Descriptor.Action != OperationActionStart {
				t.Fatalf("StartProcess descriptor Action = %q, want %q", req.Descriptor.Action, OperationActionStart)
			}
			if len(req.Descriptor.Argv) == 0 {
				t.Fatal("StartProcess descriptor Argv is empty, want prepared process argv")
			}
			return ProcessHandleMetadata{ID: "fc-handle-1234", Source: "adapter"}, nil
		},
	}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         filepath.Join(t.TempDir(), "live-start-state"),
		ProcessAdapter:       adapter,
		BootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		LiveProcessManager:   fakeLiveBootSafetyHooks{},
		LiveStart:            true,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-live",
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

	if !reflect.DeepEqual(events, []string{"prepare", "start"}) {
		t.Fatalf("adapter events = %#v, want prepare before live process start", events)
	}
	if adapter.prepareCalls != 1 || adapter.startCalls != 1 {
		t.Fatalf("adapter calls = prepare:%d start:%d, want one prepare and one explicit live start", adapter.prepareCalls, adapter.startCalls)
	}
	if started == nil {
		t.Fatal("Start() target = nil, want live-start target")
	}
	if started.Status != sandbox.StatusStopped {
		t.Fatalf("started Status = %q, want %q because live start does not claim guest readiness", started.Status, sandbox.StatusStopped)
	}
	if started.Runtime.Metadata == nil || started.Runtime.Metadata.OperationPlan == nil || started.Runtime.Metadata.OperationPlan.ProcessDescriptor == nil {
		t.Fatalf("runtime metadata = %#v, want rendered operation plan before live start", started.Runtime.Metadata)
	}
	if started.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatal("ProcessLaunch = nil, want safe accepted process metadata")
	}
	if started.Runtime.Metadata.ProcessLaunch.State != string(ProcessLaunchStateAccepted) {
		t.Fatalf("ProcessLaunch.State = %q, want %q", started.Runtime.Metadata.ProcessLaunch.State, ProcessLaunchStateAccepted)
	}
	if started.Runtime.Metadata.ProcessLaunch.ProcessID != "fc-handle-1234" || started.Runtime.Metadata.ProcessLaunch.ProcessIDSource != "adapter" {
		t.Fatalf("ProcessLaunch handle = %#v, want sanitized adapter handle", started.Runtime.Metadata.ProcessLaunch)
	}
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, started)
}

func TestBackendLiveStartReturnsSanitizedRunnerFailure(t *testing.T) {
	runnerErr := errors.New("firecracker runner failed executable=/Users/alice/private/bin/firecracker-secret argv=--api-sock /Users/alice/private/firecracker.sock --config-file /Users/alice/private/firecracker-config.json --log-path /Users/alice/private/firecracker.log --metrics-path /Users/alice/private/firecracker.metrics stderr=/Users/alice/private/firecracker.sock stdout=token=ghp_secret endpoint=https://raw-secret@example.test:8443/api pid=424242 OPENAI_API_KEY=sk-live-secret SECRET_TOKEN=ghp_secret")
	starter := &fakeProcessStarter{
		start: func(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
			return ProcessHandleMetadata{}, runnerErr
		},
	}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         filepath.Join(t.TempDir(), "live-start-failure-state"),
		ProcessAdapter:       ProcessLaunchAdapter{Starter: starter},
		BootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		LiveProcessManager:   fakeLiveBootSafetyHooks{},
		LiveStart:            true,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "firecracker-live-failure",
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

	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after live-start runner failure", started)
	}
	if starter.startCalls != 1 {
		t.Fatalf("starter calls = %d, want one explicit live-start attempt", starter.startCalls)
	}
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeBackendOperationFailed, ProcessBoundaryOperation, "processAdapter")
	if !errors.Is(err, runnerErr) {
		t.Fatalf("errors.Is(err, runnerErr) = false, want true without exposing raw runner output")
	}

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(live-start error) error = %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	wrappedText := ""
	for unwrapped := errors.Unwrap(err); unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
		wrappedText += " " + unwrapped.Error()
	}
	combinedText := publicText + wrappedText
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"firecracker.sock",
		"ghp_secret",
		"raw-secret",
		"example.test",
		"8443",
		"424242",
		"pid=424242",
		"OPENAI_API_KEY",
		"SECRET_TOKEN",
		"sk-live-secret",
	} {
		if strings.Contains(combinedText, unsafe) {
			t.Fatalf("live-start failure leaked unsafe fragment %q in public=%q wrapped=%q", unsafe, publicText, wrappedText)
		}
	}
	if !strings.Contains(wrappedText, "[redacted-path]") || !strings.Contains(wrappedText, "[redacted-endpoint]") {
		t.Fatalf("wrapped live-start error = %q, want sanitized runner output markers", wrappedText)
	}
	if !strings.Contains(wrappedText, "[redacted-pid]") || !strings.Contains(wrappedText, "[redacted-env]") {
		t.Fatalf("wrapped live-start error = %q, want sanitized PID and environment markers", wrappedText)
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

func TestBackendStopInspectDeleteBuildSanitizedLifecyclePlans(t *testing.T) {
	adapter := &fakeProcessAdapter{}
	baseStateDir := filepath.Join(t.TempDir(), "lifecycle-state")
	backend := NewBackend(BackendOptions{
		BaseStateDir:   baseStateDir,
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
	poisonFirecrackerRuntimeMetadata(created)
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStop,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStop,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Stop() error = %v, want nil", err)
	}
	assertFirecrackerOwnedRuntimeMetadata(t, stopped)
	assertFirecrackerLifecycleOperationPlan(t, stopped, OperationActionStop, []string{string(OperationPathRoleAPISocket)})
	if stopped.Status != sandbox.StatusStopped {
		t.Fatalf("Stop() status = %q, want %q", stopped.Status, sandbox.StatusStopped)
	}

	inspected, err := controller.Inspect(context.Background(), microvm.ControllerInspectRequest{
		Operation: microvm.OperationInspect,
		Config:    validMicroVMConfig(),
		Target:    *stopped,
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	assertFirecrackerOwnedRuntimeMetadata(t, inspected)
	assertFirecrackerLifecycleOperationPlan(t, inspected, OperationActionInspect, []string{string(OperationPathRoleAPISocket)})
	if inspected.Status != sandbox.StatusStopped {
		t.Fatalf("Inspect() status = %q, want preserved %q", inspected.Status, sandbox.StatusStopped)
	}

	deletePlan, err := planFirecrackerDeleteOperation(*inspected, baseStateDir)
	if err != nil {
		t.Fatalf("planFirecrackerDeleteOperation() error = %v, want nil", err)
	}
	deleteSummary := deletePlan.Summary()
	wantDeleteRoles := []OperationPathRole{
		OperationPathRoleStateDir,
		OperationPathRoleAPISocket,
		OperationPathRoleConfig,
		OperationPathRoleLog,
		OperationPathRoleMetrics,
	}
	if deleteSummary.Action != OperationActionDelete {
		t.Fatalf("delete summary Action = %q, want %q", deleteSummary.Action, OperationActionDelete)
	}
	if !reflect.DeepEqual(deleteSummary.PathRoles, wantDeleteRoles) {
		t.Fatalf("delete summary PathRoles = %#v, want %#v", deleteSummary.PathRoles, wantDeleteRoles)
	}

	stateFile := filepath.Join(baseStateDir, created.Runtime.RuntimeID, "owned-state")
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o755); err != nil {
		t.Fatalf("MkdirAll(state dir) error = %v", err)
	}
	if err := os.WriteFile(stateFile, []byte("planned cleanup only"), 0o600); err != nil {
		t.Fatalf("WriteFile(state file) error = %v", err)
	}
	if err := controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationDelete,
		Config:    validMicroVMConfig(),
		Target:    *inspected,
	}); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("Delete() touched host state file, Stat() error = %v", err)
	}
	if adapter.prepareCalls != 0 || adapter.startCalls != 0 {
		t.Fatalf("process adapter calls = prepare:%d start:%d, want no process calls for lifecycle planning", adapter.prepareCalls, adapter.startCalls)
	}

	encoded, marshalErr := json.Marshal([]*sandboxruntime.Target{stopped, inspected})
	if marshalErr != nil {
		t.Fatalf("Marshal(lifecycle targets) error = %v", marshalErr)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		baseStateDir,
		"firecracker.sock",
		"firecracker-config.json",
		"firecracker.log",
		"firecracker.metrics",
		"guest_agent",
		"network_proxy",
		"SECRET_TOKEN",
		"OPENAI_API_KEY",
		"/Users/alice",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("lifecycle operation metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestBackendStopInspectDeleteFailuresAreSanitizedOperationErrors(t *testing.T) {
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
		Operation: microvm.OperationStop,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	_, err = controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStop,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeInvalidConfig, PathPlanningOperation, "baseStateDir")
	assertFirecrackerErrorDoesNotLeak(t, err, "alice/private", "firecracker-state")

	_, err = controller.Inspect(context.Background(), microvm.ControllerInspectRequest{
		Operation: microvm.OperationInspect,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeInvalidConfig, PathPlanningOperation, "baseStateDir")
	assertFirecrackerErrorDoesNotLeak(t, err, "alice/private", "firecracker-state")

	err = controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationDelete,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeInvalidConfig, PathPlanningOperation, "baseStateDir")
	assertFirecrackerErrorDoesNotLeak(t, err, "alice/private", "firecracker-state")
}

func TestBackendUnsupportedExecAndCopyOperationsReturnSanitizedErrors(t *testing.T) {
	controller := firecrackerController{}
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

	tests := []struct {
		name      string
		operation string
		run       func() error
	}{
		{
			name:      "exec",
			operation: microvm.OperationExec,
			run: func() error {
				_, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
					Operation: microvm.OperationExec,
					Target:    target,
					Args:      []string{"sh", "-lc", "cat /Users/alice/private/socket token=ghp_secret"},
					Env:       map[string]string{"SECRET_TOKEN": "ghp_secret"},
					WorkDir:   "/Users/alice/private/workspace",
				})
				return err
			},
		},
		{
			name:      "copy in",
			operation: microvm.OperationCopyIn,
			run: func() error {
				return controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
					Operation:       microvm.OperationCopyIn,
					Target:          target,
					SourcePath:      "/Users/alice/private/input-token-ghp_secret.txt",
					DestinationPath: "/workspace/input-token-ghp_secret.txt",
				})
			},
		},
		{
			name:      "copy out",
			operation: microvm.OperationCopyOut,
			run: func() error {
				return controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
					Operation:       microvm.OperationCopyOut,
					Target:          target,
					SourcePath:      "/workspace/output-token-ghp_secret.txt",
					DestinationPath: "/Users/alice/private/output-token-ghp_secret.txt",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			assertFirecrackerUnsupportedOperationError(t, err, tt.operation)
			assertFirecrackerErrorDoesNotLeak(t, err,
				"/Users/alice",
				"private",
				"workspace",
				"ghp_secret",
				"SECRET_TOKEN",
				"input-token-ghp_secret.txt",
				"output-token-ghp_secret.txt",
			)
		})
	}
}

func TestMicroVMDriverCreateCanUseInjectedFirecrackerBackend(t *testing.T) {
	adapter := &fakeProcessAdapter{}
	backend := NewBackend(BackendOptions{
		BaseStateDir:   firecrackerPathTestBase("driver-target-state"),
		ProcessAdapter: adapter,
	})
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

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("driver Start() error = %v, want nil", err)
	}
	if adapter.prepareCalls != 1 {
		t.Fatalf("prepare calls = %d, want 1 through explicitly injected Firecracker backend", adapter.prepareCalls)
	}
	if adapter.startCalls != 0 {
		t.Fatalf("start calls = %d, want 0 because Firecracker backend still plans without live launch", adapter.startCalls)
	}
	if started == nil || started.Runtime.Metadata == nil || started.Runtime.Metadata.OperationPlan == nil {
		t.Fatalf("driver Start() target = %#v, want Firecracker operation-plan metadata", started)
	}
	if started.Runtime.Metadata.Backend != BackendID {
		t.Fatalf("started runtime backend = %q, want %q", started.Runtime.Metadata.Backend, BackendID)
	}
	if started.Runtime.Metadata.OperationPlan.Action != string(OperationActionStart) {
		t.Fatalf("started operation action = %q, want %q", started.Runtime.Metadata.OperationPlan.Action, OperationActionStart)
	}
}

type fakeLiveBootSafetyHooks struct{}

func (fakeLiveBootSafetyHooks) WaitForBootAcceptance(context.Context, BootAcceptanceRequest) (BootAcceptanceResult, error) {
	return BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}, nil
}

func (fakeLiveBootSafetyHooks) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	return nil
}

func (fakeLiveBootSafetyHooks) StopLiveProcess(context.Context, LiveProcessRequest) error {
	return nil
}

func (fakeLiveBootSafetyHooks) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	return nil
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
	assertFirecrackerOwnedRuntimeMetadata(t, target)
	if target.Runtime.RuntimeID != target.ID {
		t.Fatalf("runtime RuntimeID = %q, want target ID %q", target.Runtime.RuntimeID, target.ID)
	}
}

func assertFirecrackerOwnedRuntimeMetadata(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target == nil || target.Runtime.Metadata == nil {
		t.Fatalf("target runtime metadata = %#v, want Firecracker metadata", target)
	}
	if target.Runtime.Driver != sandboxruntime.DriverMicroVM {
		t.Fatalf("runtime Driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverMicroVM)
	}
	if target.Runtime.Metadata.Backend != BackendID {
		t.Fatalf("runtime metadata Backend = %q, want %q", target.Runtime.Metadata.Backend, BackendID)
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
	if target.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatal("runtime metadata ProcessLaunch = nil, want safe launch metadata")
	}
	if target.Runtime.Metadata.ProcessLaunch.State != string(ProcessLaunchStateBoundaryAvailable) {
		t.Fatalf("runtime metadata ProcessLaunch.State = %q, want %q", target.Runtime.Metadata.ProcessLaunch.State, ProcessLaunchStateBoundaryAvailable)
	}
	if !reflect.DeepEqual(target.Runtime.Metadata.ProcessLaunch.Labels, []string{string(ProcessLaunchStateBoundaryAvailable)}) {
		t.Fatalf("runtime metadata ProcessLaunch.Labels = %#v, want boundary-available label", target.Runtime.Metadata.ProcessLaunch.Labels)
	}
	if target.Runtime.Metadata.ProcessLaunch.ProcessID != "" || target.Runtime.Metadata.ProcessLaunch.ProcessIDSource != "" {
		t.Fatalf("runtime metadata ProcessLaunch exposes process identity before launch acceptance: %#v", target.Runtime.Metadata.ProcessLaunch)
	}
	if target.Runtime.Metadata.GuestReadiness != nil {
		t.Fatalf("runtime metadata GuestReadiness = %#v, want absent until explicit guest readiness wiring is configured", target.Runtime.Metadata.GuestReadiness)
	}
}

func assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target == nil || target.Runtime.Metadata == nil {
		t.Fatalf("target runtime metadata = %#v, want Firecracker metadata", target)
	}
	encoded, err := json.Marshal(target.Runtime.Metadata)
	if err != nil {
		t.Fatalf("Marshal(runtime metadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsupported := range []string{
		"guest_ready",
		"vm_boot_ready",
		"guest_network",
		"deny_by_default",
		"brokered_secret",
		"secret_broker",
		"network_proxy",
		"credential_broker",
		"credential_proxy",
		"credential",
		"guest_transport",
		"guesttransport",
		"live_guest_transport",
		"guest_exec",
		"guest_copy",
		"vsock_exec",
		"copy",
		"template",
		"kit",
		"docker_in_guest",
		"host_docker_socket",
		"rootless_podman",
		"kvm",
		"jailer",
		"root_setup",
		"/dev/kvm",
		"firecracker binary",
	} {
		if strings.Contains(strings.ToLower(publicText), unsupported) {
			t.Fatalf("live-start metadata claims unsupported capability %q in %s", unsupported, publicText)
		}
	}
}

func poisonFirecrackerRuntimeMetadata(target *sandboxruntime.Target) {
	target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{
		Backend: "stale_guest_agent_backend",
		CapabilityLabels: []string{
			"guest_agent",
			"network_proxy",
			"/Users/alice/private/token",
		},
		PathRoles: []string{
			"host_docker_socket",
			"/Users/alice/private/firecracker.sock",
		},
		OperationPlan: &sandboxruntime.RuntimeOperationPlan{
			Action: "stale",
			Environment: []sandboxruntime.RuntimeOperationEnvironment{
				{Name: "SECRET_TOKEN", Source: "env:OPENAI_API_KEY"},
			},
		},
		ProcessLaunch: &sandboxruntime.RuntimeProcessLaunchMetadata{
			State:           "guest_ready",
			Labels:          []string{"network_enforced", "/Users/alice/private/firecracker.sock"},
			ProcessID:       "pid:/Users/alice/private/firecracker.sock",
			ProcessIDSource: "env:OPENAI_API_KEY token=ghp_secret",
		},
		GuestReadiness: &sandboxruntime.RuntimeGuestReadinessMetadata{
			State:     sandboxruntime.RuntimeGuestReadinessStateReady,
			Transport: "tcp://127.0.0.1:9000/private/firecracker.sock?token=ghp_secret",
			Labels: []string{
				"exec_support",
				"copy_support",
				"/Users/alice/private",
			},
		},
	}
}

func firecrackerBackendNetworkEnforcementMetadata() *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               "network-plan-firecracker",
			Source:           "microvm",
			Operation:        "prepare_network",
			PolicySnapshotID: "policy-snapshot-firecracker",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall", "https://proxy.example.test"},
			Operations:       []string{"default_deny", "allowlist", "/tmp/firewall.sock", "token=secret"},
		},
		Orchestration: &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
			PlanID:           "network-plan-firecracker",
			AdapterID:        "fake-firecracker-orchestrator",
			Status:           "planned",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"proxy_route", "firewall_apply", "api.internal.example.com:443", "/tmp/live-proxy.sock"},
			PolicySnapshotID: "policy-snapshot-firecracker",
			PolicyPreset:     "deny_by_default",
			Proxy: &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
				ID:               "proxy-firecracker",
				PlanID:           "network-plan-firecracker",
				AdapterID:        "fake-firecracker-orchestrator",
				Status:           "prepared",
				Mechanisms:       []string{"proxy"},
				Operations:       []string{"proxy_prepare", "/tmp/proxy.sock"},
				PolicySnapshotID: "policy-snapshot-firecracker",
				PolicyPreset:     "deny_by_default",
				CapabilityLabels: []string{"proxy_prepared", "https://proxy.example.test"},
				ReasonCode:       "prepared",
			},
			Rules: []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
				{
					ID:               "rules-firecracker",
					PlanID:           "network-plan-firecracker",
					AdapterID:        "fake-firecracker-orchestrator",
					Status:           "planned",
					Mechanisms:       []string{"firewall"},
					Operations:       []string{"rules_plan", "iptables -A OUTPUT"},
					PolicySnapshotID: "policy-snapshot-firecracker",
					PolicyPreset:     "deny_by_default",
					CapabilityLabels: []string{"rules_planned", "secret_rules"},
					ReasonCode:       "prepared",
				},
			},
			CapabilityLabels: []string{"metadata_only", "default_deny_requested", "/tmp/proxy.sock"},
			ReasonCode:       "prepared",
			WarningCodes:     []string{"metadata_only_fallback", "https://warning.example.test"},
		},
	}
}

func assertFirecrackerNetworkEnforcementPlanningMetadata(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target == nil || target.Runtime.Metadata == nil || target.Runtime.Metadata.NetworkEnforcement == nil {
		t.Fatalf("target NetworkEnforcement = %#v, want planning metadata", target)
	}
	metadata := target.Runtime.Metadata.NetworkEnforcement
	if metadata.Result != nil {
		t.Fatalf("NetworkEnforcement.Result = %#v, want no enforcement result from metadata-only Firecracker options", metadata.Result)
	}
	if metadata.Plan == nil || metadata.Plan.ID != "network-plan-firecracker" ||
		metadata.Plan.PolicySnapshotID != "policy-snapshot-firecracker" ||
		!reflect.DeepEqual(metadata.Plan.Mechanisms, []string{"proxy", "firewall"}) {
		t.Fatalf("NetworkEnforcement.Plan = %#v, want sanitized Firecracker plan metadata", metadata.Plan)
	}
	orchestration := metadata.Orchestration
	if orchestration == nil ||
		orchestration.PlanID != "network-plan-firecracker" ||
		orchestration.AdapterID != "fake-firecracker-orchestrator" ||
		orchestration.Status != "planned" ||
		orchestration.PolicySnapshotID != "policy-snapshot-firecracker" {
		t.Fatalf("NetworkEnforcement.Orchestration = %#v, want sanitized Firecracker orchestration metadata", orchestration)
	}
	if orchestration.Proxy == nil || orchestration.Proxy.ID != "proxy-firecracker" || orchestration.Proxy.Status != "prepared" {
		t.Fatalf("NetworkEnforcement.Orchestration.Proxy = %#v, want sanitized proxy metadata", orchestration.Proxy)
	}
	if len(orchestration.Rules) != 1 || orchestration.Rules[0].ID != "rules-firecracker" || orchestration.Rules[0].Status != "planned" {
		t.Fatalf("NetworkEnforcement.Orchestration.Rules = %#v, want sanitized rule metadata", orchestration.Rules)
	}

	encoded, err := json.Marshal(target.Runtime.Metadata.NetworkEnforcement)
	if err != nil {
		t.Fatalf("Marshal(NetworkEnforcement) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"api.internal.example.com",
		"127.0.0.1",
		"443",
		"/tmp",
		"live-proxy.sock",
		"iptables",
		"token",
		"secret",
		"://",
		`"result":`,
		`"outcome":`,
		`"enforcementMode":`,
		`"capability":`,
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("Firecracker network metadata leaked or overclaimed %q in %s", unsafe, publicText)
		}
	}
}

type recordingFirecrackerNetworkEnforcementAdapter struct {
	calls  int
	plan   networkenforcement.Plan
	result networkenforcement.Result
}

func (adapter *recordingFirecrackerNetworkEnforcementAdapter) EnforceNetwork(_ context.Context, plan networkenforcement.SanitizedPlan) networkenforcement.Result {
	adapter.calls++
	adapter.plan = plan.Plan()
	result := adapter.result
	if result.PlanID == "" {
		result.PlanID = adapter.plan.ID
	}
	if result.PolicySnapshot == nil {
		result.PolicySnapshot = adapter.plan.PolicySnapshot
	}
	return result
}

func firecrackerBackendNetworkEnforcementPlanRequest() networkenforcement.PlanRequest {
	return networkenforcement.PlanRequest{
		ID:        "network-plan-firecracker-planning",
		Source:    networkenforcement.PlanSourceMicroVM,
		Operation: "prepare_network",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{
			ID:        "policy-snapshot-firecracker-planning",
			Preset:    networkenforcement.PolicyPresetDenyByDefault,
			RuleSetID: "rules-firecracker-planning",
		},
		RequestedPolicy: networkenforcement.RequestedNetworkPosture{
			Preset:            networkenforcement.PolicyPresetDenyByDefault,
			RuleSetID:         "rules-firecracker-planning",
			RuleIDs:           []string{"rule-firecracker-domain"},
			RuleCategories:    []networkenforcement.AllowlistRuleCategory{networkenforcement.AllowlistRuleCategoryDomain},
			PrivateNetwork:    networkenforcement.PostureBlock,
			MetadataEndpoint:  networkenforcement.PostureBlock,
			FirewallMode:      networkenforcement.FirewallIntentModeApply,
			FirewallMechanism: networkenforcement.EnforcementMechanismFirewall,
		},
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

func assertFirecrackerUnsupportedOperationError(t *testing.T, err error, operation string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s error = nil, want unsupported operation error", operation)
	}
	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code != microvm.ErrorCodeUnavailableCapability {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, microvm.ErrorCodeUnavailableCapability)
	}
	if opErr.Operation != operation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, operation)
	}
	publicText := err.Error()
	if !strings.Contains(publicText, "not supported in this phase") {
		t.Fatalf("error = %q, want phase-scoped unsupported detail", publicText)
	}
	for _, unsafe := range []string{"guest agent", "vsock transport"} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("error = %q, want no transport-specific detail containing %q", publicText, unsafe)
		}
	}
	for _, want := range []string{"not supported"} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("error = %q, want high-level unsupported detail containing %q", publicText, want)
		}
	}
}

func assertFirecrackerLifecycleOperationPlan(t *testing.T, target *sandboxruntime.Target, action OperationAction, pathRoles []string) {
	t.Helper()
	if target == nil {
		t.Fatalf("%s target = nil, want lifecycle planning target", action)
	}
	if target.Runtime.Metadata == nil || target.Runtime.Metadata.OperationPlan == nil {
		t.Fatalf("%s runtime metadata = %#v, want sanitized operation plan", action, target.Runtime.Metadata)
	}
	plan := target.Runtime.Metadata.OperationPlan
	if plan.Action != string(action) {
		t.Fatalf("%s operation plan Action = %q, want %q", action, plan.Action, action)
	}
	if plan.ProcessDescriptor != nil {
		t.Fatalf("%s operation ProcessDescriptor = %#v, want nil for non-process lifecycle planning", action, plan.ProcessDescriptor)
	}
	if !reflect.DeepEqual(plan.PathRoles, pathRoles) {
		t.Fatalf("%s operation PathRoles = %#v, want %#v", action, plan.PathRoles, pathRoles)
	}
	if len(plan.Payloads) != 0 {
		t.Fatalf("%s operation Payloads = %#v, want empty metadata list", action, plan.Payloads)
	}
	if len(plan.Environment) != 0 {
		t.Fatalf("%s operation Environment = %#v, want empty metadata list", action, plan.Environment)
	}
}
