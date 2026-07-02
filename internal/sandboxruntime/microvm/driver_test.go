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

type fakeBackend struct {
	controller         Controller
	createRequests     []BackendCreateRequest
	controllerRequests []ControllerRequest
}

func (b *fakeBackend) Create(_ context.Context, req BackendCreateRequest) (*sandboxruntime.Target, error) {
	b.createRequests = append(b.createRequests, req)
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
	execExitCode      int
	execStdout        string
	execStderr        string
}

func (c *fakeController) Start(_ context.Context, req ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	req.Operation = OperationStart
	c.lifecycleRequests = append(c.lifecycleRequests, req)
	target := req.Target
	target.Status = sandbox.StatusRunning
	return &target, nil
}

func (c *fakeController) Stop(_ context.Context, req ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	req.Operation = OperationStop
	c.lifecycleRequests = append(c.lifecycleRequests, req)
	target := req.Target
	target.Status = sandbox.StatusStopped
	return &target, nil
}

func (c *fakeController) Delete(_ context.Context, req ControllerLifecycleRequest) error {
	req.Operation = OperationDelete
	c.lifecycleRequests = append(c.lifecycleRequests, req)
	return nil
}

func (c *fakeController) Inspect(_ context.Context, req ControllerInspectRequest) (*sandboxruntime.Target, error) {
	c.inspectRequests = append(c.inspectRequests, req)
	target := req.Target
	target.Status = sandbox.StatusRunning
	return &target, nil
}

func (c *fakeController) Exec(_ context.Context, req ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	c.execRequests = append(c.execRequests, req)
	writeString(req.Stdout, c.execStdout)
	writeString(req.Stderr, c.execStderr)
	return &sandboxruntime.ExecResult{ExitCode: c.execExitCode}, nil
}

func (c *fakeController) CopyIn(_ context.Context, req ControllerCopyRequest) error {
	req.Operation = OperationCopyIn
	c.copyRequests = append(c.copyRequests, req)
	return nil
}

func (c *fakeController) CopyOut(_ context.Context, req ControllerCopyRequest) error {
	req.Operation = OperationCopyOut
	c.copyRequests = append(c.copyRequests, req)
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
