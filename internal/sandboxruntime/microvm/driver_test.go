package microvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestDriverSatisfiesSandboxruntimeDriver(t *testing.T) {
	var _ sandboxruntime.Driver = (*Driver)(nil)
}

func TestDriverIDReturnsMicroVMRuntimeID(t *testing.T) {
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
	})

	if got := driver.ID(); got != sandboxruntime.DriverMicroVM {
		t.Fatalf("ID() = %q, want %q", got, sandboxruntime.DriverMicroVM)
	}
}

func TestDriverMetadataIdentifiesMicroVMRuntimeBoundary(t *testing.T) {
	report := availableCapabilityReport()
	driver := NewDriver(DriverOptions{CapabilityDetector: fixedCapabilityDetector(report)})

	metadata := driver.Metadata()
	if metadata.DriverID != sandboxruntime.DriverMicroVM {
		t.Fatalf("DriverID = %q, want %q", metadata.DriverID, sandboxruntime.DriverMicroVM)
	}
	if metadata.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("IsolationLevel = %q, want %q", metadata.IsolationLevel, sandbox.SandboxIsolationLevelVM)
	}
	if metadata.UsesHostDockerSocket {
		t.Fatal("UsesHostDockerSocket = true, want false for microVM driver")
	}
	if metadata.RuntimeFamily != RuntimeFamilyMicroVM {
		t.Fatalf("RuntimeFamily = %q, want %q", metadata.RuntimeFamily, RuntimeFamilyMicroVM)
	}
}

func TestDriverMetadataReflectsCapabilityDetectionState(t *testing.T) {
	report := CapabilityReport{
		OS:                            "linux",
		Architecture:                  "arm64",
		KVMDevicePresent:              true,
		KVMReadable:                   capabilityBool(false),
		Availability:                  CapabilityAvailabilityUnavailable,
		ReasonCode:                    CapabilityReasonKVMDeviceUnreadable,
		Error:                         NewUnavailableCapabilityError("detect_capability", errors.New("kvm device is not readable")),
		HypervisorExecutableAvailable: capabilityBool(true),
	}
	driver := NewDriver(DriverOptions{CapabilityDetector: fixedCapabilityDetector(report)})

	metadata := driver.Metadata()
	if !reflect.DeepEqual(metadata.Capability, report) {
		t.Fatalf("Metadata().Capability = %#v, want %#v", metadata.Capability, report)
	}
	if metadata.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q", metadata.Availability, CapabilityAvailabilityUnavailable)
	}
	if metadata.Capability.ReasonCode != CapabilityReasonKVMDeviceUnreadable {
		t.Fatalf("Capability.ReasonCode = %q, want %q", metadata.Capability.ReasonCode, CapabilityReasonKVMDeviceUnreadable)
	}
	if metadata.ReasonCode != DriverReasonCapabilityUnavailable {
		t.Fatalf("ReasonCode = %q, want %q", metadata.ReasonCode, DriverReasonCapabilityUnavailable)
	}
}

func TestDefaultDriverConstructionIsUnavailableWithoutBackendPrerequisites(t *testing.T) {
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
	})

	metadata := driver.Metadata()
	if metadata.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q without backend prerequisites", metadata.Availability, CapabilityAvailabilityUnavailable)
	}
	if metadata.ReasonCode != DriverReasonBackendNotConfigured {
		t.Fatalf("ReasonCode = %q, want %q", metadata.ReasonCode, DriverReasonBackendNotConfigured)
	}
	if metadata.BackendConfigured {
		t.Fatal("BackendConfigured = true, want false by default")
	}

	_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "microvm-dev"})
	assertOperationError(t, err, ErrorCodeBackendNotConfigured, "create")
}

func TestDefaultConstructorsDoNotConfigureOrSelectFirecrackerHost(t *testing.T) {
	for _, tt := range []struct {
		name      string
		construct func() *Driver
	}{
		{name: "New", construct: New},
		{name: "NewDriver zero options", construct: func() *Driver {
			return NewDriver(DriverOptions{})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			driver := tt.construct()
			if driver == nil {
				t.Fatal("default constructor returned nil driver")
			}

			metadata := driver.Metadata()
			if metadata.BackendConfigured {
				t.Fatal("BackendConfigured = true, want false for default microVM construction")
			}
			if metadata.Availability == CapabilityAvailabilityAvailable {
				t.Fatalf("Availability = %q, want unavailable without an explicit backend", metadata.Availability)
			}
			if metadata.ReasonCode == DriverReasonAvailable {
				t.Fatalf("ReasonCode = %q, want a non-live default constructor reason", metadata.ReasonCode)
			}
			if metadata.NetworkEnforcement != nil {
				t.Fatalf("NetworkEnforcement = %#v, want nil without explicit enforcement plan/result", metadata.NetworkEnforcement)
			}

			encoded, err := json.Marshal(metadata)
			if err != nil {
				t.Fatalf("Marshal metadata error: %v", err)
			}
			if strings.Contains(strings.ToLower(string(encoded)), "firecrackerhost") {
				t.Fatalf("default constructor metadata selected firecrackerhost: %s", encoded)
			}

			_, err = driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "microvm-default"})
			if err == nil {
				t.Fatal("Create() succeeded with default constructor, want unavailable or backend-not-configured")
			}
			var operationErr *OperationError
			if !errors.As(err, &operationErr) {
				t.Fatalf("Create() error = %T %v, want *OperationError", err, err)
			}
			switch operationErr.Code {
			case ErrorCodeUnavailableCapability, ErrorCodeBackendNotConfigured:
			default:
				t.Fatalf("Create() error code = %q, want %q or %q", operationErr.Code, ErrorCodeUnavailableCapability, ErrorCodeBackendNotConfigured)
			}
		})
	}
}

func TestPhase37MicroVMNewRemainsInertForFirecrackerGuestReadiness(t *testing.T) {
	driver := New()
	if driver == nil {
		t.Fatal("New() = nil, want default microVM driver")
	}
	if driver.backend != nil {
		t.Fatalf("New() backend = %T, want nil default backend", driver.backend)
	}

	metadata := driver.Metadata()
	if metadata.BackendConfigured {
		t.Fatal("BackendConfigured = true, want false for inert default microVM construction")
	}
	if metadata.Availability == CapabilityAvailabilityAvailable {
		t.Fatalf("Availability = %q, want unavailable without an explicit backend", metadata.Availability)
	}
	if metadata.ReasonCode == DriverReasonAvailable {
		t.Fatalf("ReasonCode = %q, want non-live default construction reason", metadata.ReasonCode)
	}
	if metadata.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("IsolationLevel = %q, want driver-level %q metadata", metadata.IsolationLevel, sandbox.SandboxIsolationLevelVM)
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(metadata) error = %v", err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, marker := range []string{
		"guestreadiness",
		"guest_readiness",
		"guest readiness",
		"guestreadinesswaiter",
		"livestart",
		"firecrackerhost",
	} {
		if strings.Contains(publicText, marker) {
			t.Fatalf("default microVM metadata configured live guest readiness marker %q in %s", marker, publicText)
		}
	}
}

func TestDefaultProductionDriverDetectsCapabilityAndStartsUnavailable(t *testing.T) {
	driver := New()
	metadata := driver.Metadata()

	if metadata.DriverID != sandboxruntime.DriverMicroVM {
		t.Fatalf("DriverID = %q, want %q", metadata.DriverID, sandboxruntime.DriverMicroVM)
	}
	if metadata.Capability.Availability == "" {
		t.Fatalf("Capability.Availability is empty in default production metadata: %#v", metadata.Capability)
	}
	if metadata.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want unavailable without backend prerequisites", metadata.Availability)
	}
	if metadata.BackendConfigured {
		t.Fatal("BackendConfigured = true, want false for default production construction")
	}
}

func TestDriverLifecycleDelegatesThroughBackendControllerBoundary(t *testing.T) {
	config := minimalValidConfig()
	config.CPUCount = 4
	config.MemoryMiB = 4096
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	env := map[string]string{"HAL_TEST": "1"}
	controller := &fakeController{}
	backend := &fakeBackend{controller: controller}
	driver := NewDriver(DriverOptions{
		Config:             config,
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		Backend:            backend,
	})

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{
		Name:   "microvm-dev",
		Env:    env,
		Stdout: stdout,
		Stderr: stderr,
	})
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	assertMicroVMTargetMetadata(t, created)

	env["HAL_TEST"] = "changed"
	if len(backend.createRequests) != 1 {
		t.Fatalf("backend create calls = %d, want 1", len(backend.createRequests))
	}
	createReq := backend.createRequests[0]
	if createReq.Name != "microvm-dev" {
		t.Fatalf("backend create name = %q, want microvm-dev", createReq.Name)
	}
	if !reflect.DeepEqual(createReq.Config, config) {
		t.Fatalf("backend create config = %#v, want %#v", createReq.Config, config)
	}
	if !reflect.DeepEqual(createReq.Env, map[string]string{"HAL_TEST": "1"}) {
		t.Fatalf("backend create env = %#v, want cloned original env", createReq.Env)
	}
	if createReq.Stdout != stdout || createReq.Stderr != stderr {
		t.Fatal("backend create did not receive original stdout/stderr writers")
	}

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{
		Target: *created,
		Stdout: stdout,
		Stderr: stderr,
	})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	assertMicroVMTargetMetadata(t, started)

	inspected, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: *started})
	if err != nil {
		t.Fatalf("Inspect() unexpected error: %v", err)
	}
	assertMicroVMTargetMetadata(t, inspected)

	stopped, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{
		Target: *inspected,
		Stdout: stdout,
		Stderr: stderr,
	})
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}
	assertMicroVMTargetMetadata(t, stopped)

	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{
		Target: *stopped,
		Stdout: stdout,
		Stderr: stderr,
	}); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	wantControllerOps := []string{OperationStart, OperationInspect, OperationStop, OperationDelete}
	if got := backend.controllerOperations(); !reflect.DeepEqual(got, wantControllerOps) {
		t.Fatalf("backend controller operations = %#v, want %#v", got, wantControllerOps)
	}
	for _, req := range backend.controllerRequests {
		if !reflect.DeepEqual(req.Config, config) {
			t.Fatalf("%s controller config = %#v, want %#v", req.Operation, req.Config, config)
		}
		if req.Target.Name != "microvm-dev" || req.Target.Runtime.Driver != sandboxruntime.DriverMicroVM || req.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
			t.Fatalf("%s controller target = %#v, want sanitized microVM target", req.Operation, req.Target)
		}
	}

	wantLifecycleOps := []string{OperationStart, OperationStop, OperationDelete}
	if got := controller.lifecycleOperations(); !reflect.DeepEqual(got, wantLifecycleOps) {
		t.Fatalf("controller lifecycle operations = %#v, want %#v", got, wantLifecycleOps)
	}
	if len(controller.inspectRequests) != 1 {
		t.Fatalf("controller inspect calls = %d, want 1", len(controller.inspectRequests))
	}
	inspectReq := controller.inspectRequests[0]
	if !reflect.DeepEqual(inspectReq.Config, config) {
		t.Fatalf("inspect config = %#v, want %#v", inspectReq.Config, config)
	}
	if inspectReq.Target.Name != "microvm-dev" || inspectReq.Target.Runtime.Driver != sandboxruntime.DriverMicroVM || inspectReq.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("inspect target = %#v, want sanitized microVM target", inspectReq.Target)
	}
	for _, req := range controller.lifecycleRequests {
		if !reflect.DeepEqual(req.Config, config) {
			t.Fatalf("%s lifecycle config = %#v, want %#v", req.Operation, req.Config, config)
		}
		if req.Target.Name != "microvm-dev" || req.Target.Runtime.Driver != sandboxruntime.DriverMicroVM || req.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
			t.Fatalf("%s lifecycle target = %#v, want sanitized microVM target", req.Operation, req.Target)
		}
	}
}

func TestApplyRuntimeMetadataSanitizesGuestReadinessMetadata(t *testing.T) {
	target := &sandboxruntime.Target{
		Name: "microvm-readiness",
		Runtime: sandboxruntime.RuntimeState{
			Metadata: &sandboxruntime.RuntimeMetadata{
				Backend: "firecracker",
				GuestReadiness: &sandboxruntime.RuntimeGuestReadinessMetadata{
					State:     sandboxruntime.RuntimeGuestReadinessStateReady,
					Transport: "tcp://127.0.0.1:9000/private/firecracker.sock?token=ghp_secret",
					Labels: []string{
						"probe_ok",
						"exec_support",
						"copy_support",
						"/Users/alice/private",
					},
				},
			},
		},
	}

	applied := applyRuntimeMetadata(target)
	if applied == nil || applied.Runtime.Metadata == nil || applied.Runtime.Metadata.GuestReadiness == nil {
		t.Fatalf("applyRuntimeMetadata() = %#v, want guest readiness metadata", applied)
	}
	readiness := applied.Runtime.Metadata.GuestReadiness
	if readiness.State != sandboxruntime.RuntimeGuestReadinessStateReady {
		t.Fatalf("GuestReadiness.State = %q, want ready", readiness.State)
	}
	if readiness.Transport != "" {
		t.Fatalf("GuestReadiness.Transport = %q, want unsafe transport omitted", readiness.Transport)
	}
	if !reflect.DeepEqual(readiness.Labels, []string{"ready", "probe_ok"}) {
		t.Fatalf("GuestReadiness.Labels = %#v, want sanitized labels", readiness.Labels)
	}

	encoded, err := json.Marshal(applied)
	if err != nil {
		t.Fatalf("Marshal(target) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"127.0.0.1",
		"9000",
		"firecracker.sock",
		"ghp_secret",
		"exec_support",
		"copy_support",
		"/Users/alice",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("applied target leaked unsafe guest readiness fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestDriverMetadataProjectsExplicitNetworkEnforcementAdapterSuccessAndFailure(t *testing.T) {
	plan := microVMNetworkEnforcementTestPlan()
	successAdapter := microVMNetworkEnforcementFakeAdapter{
		result: networkenforcement.Result{
			AdapterID:       "fake-microvm-adapter",
			Outcome:         networkenforcement.ResultOutcomeSuccess,
			EnforcementMode: networkenforcement.ResultModeProxyFirewall,
			Mechanisms: []networkenforcement.EnforcementMechanism{
				networkenforcement.EnforcementMechanismProxy,
				networkenforcement.EnforcementMechanismFirewall,
			},
			Operations: []string{"proxy_route", "firewall_apply"},
			Capability: &networkenforcement.ResultCapability{
				Supported:                  true,
				Modes:                      []networkenforcement.ResultMode{networkenforcement.ResultModeProxyFirewall},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsPrivateRangeRules:  true,
				SupportsMetadataEndpoint:   true,
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: networkenforcement.ResultReasonApplied,
		},
	}
	success := networkenforcement.RunAdapter(context.Background(), successAdapter, plan)
	successDriver := NewDriver(DriverOptions{
		CapabilityDetector:       fixedCapabilityDetector(availableCapabilityReport()),
		NetworkEnforcementPlan:   &plan,
		NetworkEnforcementResult: &success,
	})

	successMetadata := successDriver.Metadata()
	if successMetadata.Availability == CapabilityAvailabilityAvailable {
		t.Fatalf("Availability = %q, want no production-ready runtime without backend", successMetadata.Availability)
	}
	if successMetadata.NetworkEnforcement == nil ||
		successMetadata.NetworkEnforcement.Plan == nil ||
		successMetadata.NetworkEnforcement.Result == nil {
		t.Fatalf("NetworkEnforcement = %#v, want projected plan and result", successMetadata.NetworkEnforcement)
	}
	result := successMetadata.NetworkEnforcement.Result
	if result.Outcome != string(networkenforcement.ResultOutcomeSuccess) ||
		result.EnforcementMode != string(networkenforcement.ResultModeProxyFirewall) ||
		result.Capability == nil ||
		!result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("NetworkEnforcement result = %#v, want proxy_firewall capability", result)
	}
	encoded, err := json.Marshal(successMetadata)
	if err != nil {
		t.Fatalf("Marshal(success metadata) error: %v", err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"production", "egress", "://", "/tmp/", "token", "secret"} {
		if strings.Contains(publicText, forbidden) {
			t.Fatalf("success metadata leaked or claimed %q in %s", forbidden, publicText)
		}
	}

	failureAdapter := microVMNetworkEnforcementFakeAdapter{
		result: networkenforcement.Result{
			AdapterID:       "fake-failing-adapter",
			Outcome:         networkenforcement.ResultOutcomeFailure,
			EnforcementMode: networkenforcement.ResultModeProxyFirewall,
			Operations: []string{
				"firewall_apply",
				"/tmp/firewall.sock",
			},
			Capability: &networkenforcement.ResultCapability{
				Supported:                  true,
				Modes:                      []networkenforcement.ResultMode{networkenforcement.ResultModeProxyFirewall},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode:   networkenforcement.ResultReasonAdapterFailed,
			WarningCodes: []networkenforcement.ResultWarningCode{networkenforcement.ResultWarningSanitizedAdapterError},
		},
	}
	failure := networkenforcement.RunAdapter(context.Background(), failureAdapter, plan)
	failureDriver := NewDriver(DriverOptions{
		CapabilityDetector:       fixedCapabilityDetector(availableCapabilityReport()),
		NetworkEnforcementPlan:   &plan,
		NetworkEnforcementResult: &failure,
	})
	failureMetadata := failureDriver.Metadata()
	if failureMetadata.NetworkEnforcement == nil || failureMetadata.NetworkEnforcement.Result == nil {
		t.Fatalf("failure NetworkEnforcement = %#v, want fail-closed result", failureMetadata.NetworkEnforcement)
	}
	failureResult := failureMetadata.NetworkEnforcement.Result
	if failureResult.Outcome != string(networkenforcement.ResultOutcomeFailure) ||
		failureResult.EnforcementMode != string(networkenforcement.ResultModeNone) ||
		failureResult.Capability != nil {
		t.Fatalf("failure result = %#v, want none mode and cleared capability", failureResult)
	}
}

func TestDriverNetworkEnforcementPlanningUsesInjectedBoundaryOnlyWhenConfigured(t *testing.T) {
	request := microVMNetworkEnforcementTestPlanRequest()
	var plannerCalls int
	planner := networkenforcement.PlannerFunc(func(got networkenforcement.PlanRequest) networkenforcement.Plan {
		plannerCalls++
		if !reflect.DeepEqual(got, request) {
			t.Fatalf("planner request = %#v, want %#v", got, request)
		}
		return networkenforcement.BuildPlan(got)
	})
	adapter := &recordingMicroVMNetworkEnforcementAdapter{
		result: networkenforcement.Result{
			AdapterID:       "fake-runtime-planning-adapter",
			Outcome:         networkenforcement.ResultOutcomeSuccess,
			EnforcementMode: networkenforcement.ResultModeProxyFirewall,
			Mechanisms: []networkenforcement.EnforcementMechanism{
				networkenforcement.EnforcementMechanismProxy,
				networkenforcement.EnforcementMechanismFirewall,
			},
			Operations: []string{"proxy_route", "firewall_apply"},
			Capability: &networkenforcement.ResultCapability{
				Supported:                  true,
				Modes:                      []networkenforcement.ResultMode{networkenforcement.ResultModeProxyFirewall},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: networkenforcement.ResultReasonApplied,
		},
	}

	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		NetworkEnforcement: &NetworkEnforcementPlanning{
			Request: request,
			Planner: planner,
			Adapter: adapter,
		},
	})

	if plannerCalls != 1 {
		t.Fatalf("planner calls = %d, want 1 for explicit network enforcement planning", plannerCalls)
	}
	if adapter.calls != 1 || adapter.plan.ID != request.ID {
		t.Fatalf("adapter calls=%d plan=%#v, want sanitized planned input", adapter.calls, adapter.plan)
	}
	metadata := driver.Metadata().NetworkEnforcement
	if metadata == nil || metadata.Plan == nil || metadata.Result == nil {
		t.Fatalf("NetworkEnforcement = %#v, want planned metadata and adapter result", metadata)
	}
	if metadata.Plan.ID != request.ID || metadata.Result.AdapterID != "fake-runtime-planning-adapter" {
		t.Fatalf("NetworkEnforcement metadata = %#v, want explicit planner/adapter output", metadata)
	}
	if metadata.Result.EnforcementMode != string(networkenforcement.ResultModeProxyFirewall) ||
		metadata.Result.Capability == nil ||
		!metadata.Result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("NetworkEnforcement result = %#v, want explicit proxy/firewall capability", metadata.Result)
	}

	defaultDriver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
	})
	if got := defaultDriver.Metadata().NetworkEnforcement; got != nil {
		t.Fatalf("default NetworkEnforcement = %#v, want nil without explicit planning", got)
	}
}

func TestDriverNetworkEnforcementPlanningWithoutAdapterFailsClosed(t *testing.T) {
	request := microVMNetworkEnforcementTestPlanRequest()
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		NetworkEnforcement: &NetworkEnforcementPlanning{
			Request: request,
		},
	})

	metadata := driver.Metadata().NetworkEnforcement
	if metadata == nil || metadata.Plan == nil || metadata.Result == nil {
		t.Fatalf("NetworkEnforcement = %#v, want plan and unsupported result", metadata)
	}
	if metadata.Result.Outcome != string(networkenforcement.ResultOutcomeUnsupported) ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeNone) ||
		metadata.Result.Capability != nil {
		t.Fatalf("NetworkEnforcement result = %#v, want fail-closed unsupported metadata", metadata.Result)
	}
}

func TestDriverExecDelegatesThroughControllerAndStreamsOutput(t *testing.T) {
	config := minimalValidConfig()
	controller := &fakeController{
		execExitCode: 7,
		execStdout:   "guest stdout\n",
		execStderr:   "guest stderr\n",
	}
	backend := &fakeBackend{controller: controller}
	driver := NewDriver(DriverOptions{
		Config:             config,
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		Backend:            backend,
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	args := []string{"sh", "-lc", "printf output"}
	env := map[string]string{"HAL_EXEC": "1"}

	result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target:  sandboxruntime.Target{Name: "microvm-dev"},
		Args:    args,
		Env:     env,
		WorkDir: "/workspace/project",
		Stdout:  stdout,
		Stderr:  stderr,
	})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("Exec() exit code = %d, want 7", result.ExitCode)
	}
	if stdout.String() != "guest stdout\n" || stderr.String() != "guest stderr\n" {
		t.Fatalf("exec streams stdout=%q stderr=%q, want fake backend output", stdout.String(), stderr.String())
	}
	if got := backend.controllerOperations(); !reflect.DeepEqual(got, []string{OperationExec}) {
		t.Fatalf("backend controller operations = %#v, want exec", got)
	}
	if len(controller.execRequests) != 1 {
		t.Fatalf("controller exec calls = %d, want 1", len(controller.execRequests))
	}
	execReq := controller.execRequests[0]
	if !reflect.DeepEqual(execReq.Config, config) {
		t.Fatalf("exec config = %#v, want %#v", execReq.Config, config)
	}
	if execReq.Target.Name != "microvm-dev" || execReq.Target.Runtime.Driver != sandboxruntime.DriverMicroVM || execReq.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("exec target = %#v, want sanitized microVM target", execReq.Target)
	}
	if !reflect.DeepEqual(execReq.Args, args) || !reflect.DeepEqual(execReq.Env, env) || execReq.WorkDir != "/workspace/project" {
		t.Fatalf("exec request = %#v, want args/env/workdir preserved", execReq)
	}
}

func TestDriverCopyDelegatesThroughControllerWithSanitizedPaths(t *testing.T) {
	config := minimalValidConfig()
	controller := &fakeController{}
	backend := &fakeBackend{controller: controller}
	driver := NewDriver(DriverOptions{
		Config:             config,
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		Backend:            backend,
	})
	target := sandboxruntime.Target{Name: "microvm-dev"}

	if err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      " /safe/patch.diff ",
		DestinationPath: " /workspace/patch.diff ",
	}); err != nil {
		t.Fatalf("CopyIn() unexpected error: %v", err)
	}
	if err := driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      " /workspace/result.txt ",
		DestinationPath: " /safe/result.txt ",
	}); err != nil {
		t.Fatalf("CopyOut() unexpected error: %v", err)
	}

	if got := backend.controllerOperations(); !reflect.DeepEqual(got, []string{OperationCopyIn, OperationCopyOut}) {
		t.Fatalf("backend controller operations = %#v, want copy in/out", got)
	}
	if len(controller.copyRequests) != 2 {
		t.Fatalf("controller copy calls = %d, want 2", len(controller.copyRequests))
	}
	wantCopies := []struct {
		operation   string
		source      string
		destination string
	}{
		{operation: OperationCopyIn, source: "/safe/patch.diff", destination: "/workspace/patch.diff"},
		{operation: OperationCopyOut, source: "/workspace/result.txt", destination: "/safe/result.txt"},
	}
	for i, want := range wantCopies {
		got := controller.copyRequests[i]
		if got.Operation != want.operation || got.SourcePath != want.source || got.DestinationPath != want.destination {
			t.Fatalf("copy request %d = %#v, want operation=%s source=%s destination=%s", i, got, want.operation, want.source, want.destination)
		}
		if !reflect.DeepEqual(got.Config, config) {
			t.Fatalf("%s copy config = %#v, want %#v", got.Operation, got.Config, config)
		}
		if got.Target.Name != "microvm-dev" || got.Target.Runtime.Driver != sandboxruntime.DriverMicroVM || got.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
			t.Fatalf("%s copy target = %#v, want sanitized microVM target", got.Operation, got.Target)
		}
	}
}

func TestDriverRejectsUnavailableOperationsBeforeBackendCalls(t *testing.T) {
	report := availableCapabilityReport()
	report.Availability = CapabilityAvailabilityUnavailable
	report.ReasonCode = CapabilityReasonKVMDeviceUnreadable
	report.Error = NewUnavailableCapabilityError("detect_capability", errors.New("kvm failed at /Users/alice/private/vmlinux endpoint=https://secret.example.test:8443/api token=ghp_secret firecracker-go-sdk"))

	for _, tt := range driverOperationErrorCases(validMicroVMTarget()) {
		t.Run(tt.name, func(t *testing.T) {
			backend := &fakeBackend{controller: &fakeController{}}
			driver := NewDriver(DriverOptions{
				Config:             minimalValidConfig(),
				CapabilityDetector: fixedCapabilityDetector(report),
				Backend:            backend,
			})

			err := tt.run(driver)
			assertOperationError(t, err, ErrorCodeUnavailableCapability, tt.operation)
			assertNoBackendCalls(t, backend)
			assertPublicErrorOmits(t, err, []string{
				"/Users/alice",
				"vmlinux",
				"secret.example.test",
				"8443",
				"ghp_secret",
				"firecracker-go-sdk",
			})
		})
	}
}

func TestDriverRejectsOperationsWithoutConfiguredBackend(t *testing.T) {
	for _, tt := range driverOperationErrorCases(validMicroVMTarget()) {
		t.Run(tt.name, func(t *testing.T) {
			driver := NewDriver(DriverOptions{
				Config:             minimalValidConfig(),
				CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
			})

			err := tt.run(driver)
			assertOperationError(t, err, ErrorCodeBackendNotConfigured, tt.operation)
		})
	}
}

func TestDriverRejectsMissingTargetBeforeBackendControllerLookup(t *testing.T) {
	for _, tt := range driverTargetOperationErrorCases(sandboxruntime.Target{}) {
		t.Run(tt.name, func(t *testing.T) {
			backend := &fakeBackend{controller: &fakeController{}}
			driver := NewDriver(DriverOptions{
				Config:             minimalValidConfig(),
				CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
				Backend:            backend,
			})

			err := tt.run(driver)
			assertOperationError(t, err, ErrorCodeTargetRequired, tt.operation)
			if len(backend.controllerRequests) != 0 {
				t.Fatalf("backend controller calls = %d, want 0 before target validation succeeds", len(backend.controllerRequests))
			}
			if len(backend.createRequests) != 0 {
				t.Fatalf("backend create calls = %d, want 0 for target operation rejection", len(backend.createRequests))
			}
		})
	}
}

func TestDriverRejectsMissingCreateTargetNameBeforeBackendCreate(t *testing.T) {
	backend := &fakeBackend{controller: &fakeController{}}
	driver := NewDriver(DriverOptions{
		Config:             minimalValidConfig(),
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		Backend:            backend,
	})

	_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: " \t "})
	assertOperationError(t, err, ErrorCodeTargetNameRequired, OperationCreate)
	assertNoBackendCalls(t, backend)
}

func TestDriverRejectsInvalidConfigBeforeBackendCalls(t *testing.T) {
	invalidConfig := minimalValidConfig()
	invalidConfig.RootfsPath = " \t "

	for _, tt := range driverOperationErrorCases(validMicroVMTarget()) {
		t.Run(tt.name, func(t *testing.T) {
			backend := &fakeBackend{controller: &fakeController{}}
			driver := NewDriver(DriverOptions{
				Config:             invalidConfig,
				CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
				Backend:            backend,
			})

			err := tt.run(driver)
			assertOperationError(t, err, ErrorCodeInvalidConfig, tt.operation)
			assertOperationErrorField(t, err, "rootfsPath")
			assertNoBackendCalls(t, backend)
		})
	}
}

func TestDriverRejectsExplicitNegativeSizingBeforeBackendCalls(t *testing.T) {
	invalidConfig := minimalValidConfig()
	invalidConfig.MemoryMiB = -1

	backend := &fakeBackend{controller: &fakeController{}}
	driver := NewDriver(DriverOptions{
		Config:             invalidConfig,
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		Backend:            backend,
	})

	_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "microvm-dev"})
	assertOperationError(t, err, ErrorCodeInvalidConfig, OperationCreate)
	assertOperationErrorField(t, err, "memoryMiB")
	assertNoBackendCalls(t, backend)
}

func TestDriverWrapsBackendAndControllerErrorsWithSanitizedOperationErrors(t *testing.T) {
	rawErr := errors.New("firecracker-go-sdk failed kernel=/srv/hal/images/vmlinux rootfs=/nix/store/abc123/rootfs.ext4 socket=/mnt/secrets/firecracker.sock endpoint=https://secret.example.test:8443/api token=ghp_secret password=hunter2")
	unsafeFragments := []string{
		"/srv/hal",
		"/nix/store",
		"/mnt/secrets",
		"vmlinux",
		"rootfs.ext4",
		"firecracker.sock",
		"secret.example.test",
		"8443",
		"ghp_secret",
		"hunter2",
		"firecracker-go-sdk",
	}

	tests := []struct {
		name      string
		operation string
		backend   *fakeBackend
		run       func(*Driver) error
	}{
		{
			name:      "create backend error",
			operation: OperationCreate,
			backend:   &fakeBackend{createErr: rawErr},
			run: func(driver *Driver) error {
				_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "microvm-dev"})
				return err
			},
		},
		{
			name:      "start controller lookup error",
			operation: OperationStart,
			backend:   &fakeBackend{controllerErr: rawErr},
			run: func(driver *Driver) error {
				_, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: validMicroVMTarget()})
				return err
			},
		},
		{
			name:      "start controller operation error",
			operation: OperationStart,
			backend:   &fakeBackend{controller: &fakeController{startErr: rawErr}},
			run: func(driver *Driver) error {
				_, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: validMicroVMTarget()})
				return err
			},
		},
		{
			name:      "inspect controller operation error",
			operation: OperationInspect,
			backend:   &fakeBackend{controller: &fakeController{inspectErr: rawErr}},
			run: func(driver *Driver) error {
				_, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: validMicroVMTarget()})
				return err
			},
		},
		{
			name:      "stop controller operation error",
			operation: OperationStop,
			backend:   &fakeBackend{controller: &fakeController{stopErr: rawErr}},
			run: func(driver *Driver) error {
				_, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: validMicroVMTarget()})
				return err
			},
		},
		{
			name:      "delete controller operation error",
			operation: OperationDelete,
			backend:   &fakeBackend{controller: &fakeController{deleteErr: rawErr}},
			run: func(driver *Driver) error {
				return driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: validMicroVMTarget()})
			},
		},
		{
			name:      "exec controller operation error",
			operation: OperationExec,
			backend:   &fakeBackend{controller: &fakeController{execErr: rawErr}},
			run: func(driver *Driver) error {
				_, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Target: validMicroVMTarget(), Args: []string{"true"}})
				return err
			},
		},
		{
			name:      "copy in controller operation error",
			operation: OperationCopyIn,
			backend:   &fakeBackend{controller: &fakeController{copyInErr: rawErr}},
			run: func(driver *Driver) error {
				return driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
					Target:          validMicroVMTarget(),
					SourcePath:      "/safe/input.txt",
					DestinationPath: "/workspace/input.txt",
				})
			},
		},
		{
			name:      "copy out controller operation error",
			operation: OperationCopyOut,
			backend:   &fakeBackend{controller: &fakeController{copyOutErr: rawErr}},
			run: func(driver *Driver) error {
				return driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
					Target:          validMicroVMTarget(),
					SourcePath:      "/workspace/output.txt",
					DestinationPath: "/safe/output.txt",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := NewDriver(DriverOptions{
				Config:             minimalValidConfig(),
				CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
				Backend:            tt.backend,
			})

			err := tt.run(driver)
			assertOperationError(t, err, ErrorCodeBackendOperationFailed, tt.operation)
			if !errors.Is(err, rawErr) {
				t.Fatalf("errors.Is(%v, rawErr) = false, want true", err)
			}
			assertPublicErrorOmits(t, err, unsafeFragments)
		})
	}
}

func availableCapabilityReport() CapabilityReport {
	return CapabilityReport{
		OS:                             "linux",
		Architecture:                   "amd64",
		KVMDevicePresent:               true,
		KVMReadable:                    capabilityBool(true),
		HypervisorExecutableConfigured: false,
		Availability:                   CapabilityAvailabilityAvailable,
		ReasonCode:                     CapabilityReasonAvailable,
	}
}

type driverOperationErrorCase struct {
	name      string
	operation string
	run       func(*Driver) error
}

func driverOperationErrorCases(target sandboxruntime.Target) []driverOperationErrorCase {
	return append(
		[]driverOperationErrorCase{
			{
				name:      OperationCreate,
				operation: OperationCreate,
				run: func(driver *Driver) error {
					_, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "microvm-dev"})
					return err
				},
			},
		},
		driverTargetOperationErrorCases(target)...,
	)
}

func driverTargetOperationErrorCases(target sandboxruntime.Target) []driverOperationErrorCase {
	return []driverOperationErrorCase{
		{
			name:      OperationStart,
			operation: OperationStart,
			run: func(driver *Driver) error {
				_, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: target})
				return err
			},
		},
		{
			name:      OperationInspect,
			operation: OperationInspect,
			run: func(driver *Driver) error {
				_, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: target})
				return err
			},
		},
		{
			name:      OperationStop,
			operation: OperationStop,
			run: func(driver *Driver) error {
				_, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: target})
				return err
			},
		},
		{
			name:      OperationDelete,
			operation: OperationDelete,
			run: func(driver *Driver) error {
				return driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: target})
			},
		},
		{
			name:      OperationExec,
			operation: OperationExec,
			run: func(driver *Driver) error {
				_, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
					Target:  target,
					Args:    []string{"true"},
					WorkDir: "/workspace/project",
				})
				return err
			},
		},
		{
			name:      OperationCopyIn,
			operation: OperationCopyIn,
			run: func(driver *Driver) error {
				return driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
					Target:          target,
					SourcePath:      "/safe/input.txt",
					DestinationPath: "/workspace/input.txt",
				})
			},
		},
		{
			name:      OperationCopyOut,
			operation: OperationCopyOut,
			run: func(driver *Driver) error {
				return driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
					Target:          target,
					SourcePath:      "/workspace/output.txt",
					DestinationPath: "/safe/output.txt",
				})
			},
		},
	}
}

func validMicroVMTarget() sandboxruntime.Target {
	return sandboxruntime.Target{
		ID:   "microvm-target-1",
		Name: "microvm-dev",
		Runtime: sandboxruntime.RuntimeState{
			RuntimeID: "microvm-target-1",
		},
	}
}

func assertNoBackendCalls(t *testing.T, backend *fakeBackend) {
	t.Helper()
	if len(backend.createRequests) != 0 {
		t.Fatalf("backend create calls = %d, want 0", len(backend.createRequests))
	}
	if len(backend.controllerRequests) != 0 {
		t.Fatalf("backend controller calls = %d, want 0", len(backend.controllerRequests))
	}
}

func fixedCapabilityDetector(report CapabilityReport) CapabilityDetector {
	return CapabilityDetectorFunc(func(CapabilityDetectionRequest) CapabilityReport {
		return report
	})
}

type microVMNetworkEnforcementFakeAdapter struct {
	result networkenforcement.Result
}

func (adapter microVMNetworkEnforcementFakeAdapter) EnforceNetwork(_ context.Context, plan networkenforcement.SanitizedPlan) networkenforcement.Result {
	result := adapter.result
	if result.PlanID == "" {
		result.PlanID = plan.Plan().ID
	}
	if result.PolicySnapshot == nil {
		result.PolicySnapshot = plan.Plan().PolicySnapshot
	}
	return result
}

type recordingMicroVMNetworkEnforcementAdapter struct {
	calls  int
	plan   networkenforcement.Plan
	result networkenforcement.Result
}

func (adapter *recordingMicroVMNetworkEnforcementAdapter) EnforceNetwork(_ context.Context, plan networkenforcement.SanitizedPlan) networkenforcement.Result {
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

func microVMNetworkEnforcementTestPlan() networkenforcement.Plan {
	return networkenforcement.BuildPlan(microVMNetworkEnforcementTestPlanRequest())
}

func microVMNetworkEnforcementTestPlanRequest() networkenforcement.PlanRequest {
	return networkenforcement.PlanRequest{
		ID:        "network-plan-microvm",
		Source:    networkenforcement.PlanSourceMicroVM,
		Operation: "prepare_network",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{
			ID:        "policy-snapshot-microvm",
			Preset:    networkenforcement.PolicyPresetDenyByDefault,
			RuleSetID: "rules-microvm",
		},
		RequestedPolicy: networkenforcement.RequestedNetworkPosture{
			Preset:            networkenforcement.PolicyPresetDenyByDefault,
			RuleSetID:         "rules-microvm",
			RuleIDs:           []string{"rule-domain"},
			RuleCategories:    []networkenforcement.AllowlistRuleCategory{networkenforcement.AllowlistRuleCategoryDomain},
			PrivateNetwork:    networkenforcement.PostureBlock,
			MetadataEndpoint:  networkenforcement.PostureBlock,
			HTTP:              networkenforcement.ProxyRoutingModeRouteViaProxy,
			HTTPS:             networkenforcement.ProxyRoutingModeBlock,
			ProxyMechanism:    networkenforcement.EnforcementMechanismProxy,
			FirewallMode:      networkenforcement.FirewallIntentModeApply,
			FirewallMechanism: networkenforcement.EnforcementMechanismFirewall,
		},
	}
}

type fakeBackend struct {
	controller         Controller
	createErr          error
	controllerErr      error
	createRequests     []BackendCreateRequest
	controllerRequests []ControllerRequest
}

func (b *fakeBackend) Create(_ context.Context, req BackendCreateRequest) (*sandboxruntime.Target, error) {
	b.createRequests = append(b.createRequests, req)
	if b.createErr != nil {
		return nil, b.createErr
	}
	return &sandboxruntime.Target{
		ID:       "microvm-created",
		Name:     req.Name,
		Provider: sandboxruntime.DriverMicroVM,
		Status:   sandbox.StatusStopped,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverSSHMachine,
			RuntimeID:      "microvm-created",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}, nil
}

func (b *fakeBackend) Controller(_ context.Context, req ControllerRequest) (Controller, error) {
	b.controllerRequests = append(b.controllerRequests, req)
	if b.controllerErr != nil {
		return nil, b.controllerErr
	}
	return b.controller, nil
}

func (b *fakeBackend) controllerOperations() []string {
	operations := make([]string, 0, len(b.controllerRequests))
	for _, req := range b.controllerRequests {
		operations = append(operations, req.Operation)
	}
	return operations
}

type fakeController struct {
	lifecycleRequests []ControllerLifecycleRequest
	inspectRequests   []ControllerInspectRequest
	execRequests      []ControllerExecRequest
	copyRequests      []ControllerCopyRequest
	startErr          error
	stopErr           error
	deleteErr         error
	inspectErr        error
	execErr           error
	copyInErr         error
	copyOutErr        error
	execExitCode      int
	execStdout        string
	execStderr        string
}

func (c *fakeController) Start(_ context.Context, req ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	req.Operation = OperationStart
	c.lifecycleRequests = append(c.lifecycleRequests, req)
	if c.startErr != nil {
		return nil, c.startErr
	}
	target := req.Target
	target.Status = sandbox.StatusRunning
	return &target, nil
}

func (c *fakeController) Stop(_ context.Context, req ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	req.Operation = OperationStop
	c.lifecycleRequests = append(c.lifecycleRequests, req)
	if c.stopErr != nil {
		return nil, c.stopErr
	}
	target := req.Target
	target.Status = sandbox.StatusStopped
	return &target, nil
}

func (c *fakeController) Delete(_ context.Context, req ControllerLifecycleRequest) error {
	req.Operation = OperationDelete
	c.lifecycleRequests = append(c.lifecycleRequests, req)
	if c.deleteErr != nil {
		return c.deleteErr
	}
	return nil
}

func (c *fakeController) Inspect(_ context.Context, req ControllerInspectRequest) (*sandboxruntime.Target, error) {
	c.inspectRequests = append(c.inspectRequests, req)
	if c.inspectErr != nil {
		return nil, c.inspectErr
	}
	target := req.Target
	target.Status = sandbox.StatusRunning
	return &target, nil
}

func (c *fakeController) Exec(_ context.Context, req ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	c.execRequests = append(c.execRequests, req)
	if c.execErr != nil {
		return nil, c.execErr
	}
	writeString(req.Stdout, c.execStdout)
	writeString(req.Stderr, c.execStderr)
	return &sandboxruntime.ExecResult{ExitCode: c.execExitCode}, nil
}

func (c *fakeController) CopyIn(_ context.Context, req ControllerCopyRequest) error {
	req.Operation = OperationCopyIn
	c.copyRequests = append(c.copyRequests, req)
	if c.copyInErr != nil {
		return c.copyInErr
	}
	return nil
}

func (c *fakeController) CopyOut(_ context.Context, req ControllerCopyRequest) error {
	req.Operation = OperationCopyOut
	c.copyRequests = append(c.copyRequests, req)
	if c.copyOutErr != nil {
		return c.copyOutErr
	}
	return nil
}

func (c *fakeController) lifecycleOperations() []string {
	operations := make([]string, 0, len(c.lifecycleRequests))
	for _, req := range c.lifecycleRequests {
		operations = append(operations, req.Operation)
	}
	return operations
}

func writeString(w io.Writer, value string) {
	if w != nil {
		_, _ = io.WriteString(w, value)
	}
}

func assertMicroVMTargetMetadata(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target == nil {
		t.Fatal("target = nil, want microVM target")
	}
	if target.Runtime.Driver != sandboxruntime.DriverMicroVM {
		t.Fatalf("runtime driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverMicroVM)
	}
	if target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("runtime isolation = %q, want %q", target.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelVM)
	}
}

func assertOperationError(t *testing.T, err error, code ErrorCode, operation string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s error = nil, want %s", operation, code)
	}
	var opErr *OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("%s error type = %T, want *OperationError", operation, err)
	}
	if opErr.Code != code {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, code)
	}
	if opErr.Operation != operation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, operation)
	}
}

func assertOperationErrorField(t *testing.T, err error, field string) {
	t.Helper()
	var opErr *OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *OperationError", err)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}

func assertPublicErrorOmits(t *testing.T, err error, unsafeFragments []string) {
	t.Helper()
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(error) error: %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range unsafeFragments {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public error text leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
}
