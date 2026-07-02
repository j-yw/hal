package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPrepareStartCommandUsesInjectedProcessAdapterOnly(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	adapter := &fakeProcessAdapter{
		prepare: func(_ context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
			if !reflect.DeepEqual(req.Plan, plan) {
				t.Fatalf("PrepareStartCommand request plan = %#v, want %#v", req.Plan, plan)
			}
			return ProcessCommandDescriptorFromStartPlan(req.Plan)
		},
	}

	descriptor, err := PrepareStartCommand(context.Background(), adapter, plan)
	if err != nil {
		t.Fatalf("PrepareStartCommand() error = %v, want nil", err)
	}

	if adapter.prepareCalls != 1 {
		t.Fatalf("prepare calls = %d, want 1", adapter.prepareCalls)
	}
	if adapter.startCalls != 0 {
		t.Fatalf("start calls = %d, want 0 during command preparation", adapter.startCalls)
	}
	if !reflect.DeepEqual(descriptor.Argv, plan.Argv) {
		t.Fatalf("descriptor Argv = %#v, want %#v", descriptor.Argv, plan.Argv)
	}
	if descriptor.Environment == nil {
		t.Fatal("descriptor Environment = nil, want explicit empty list")
	}
}

func TestStartProcessCallsOnlyInjectedProcessAdapter(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}
	adapter := &fakeProcessAdapter{
		start: func(_ context.Context, req ProcessStartRequest) (ProcessHandleMetadata, error) {
			if !reflect.DeepEqual(req.Descriptor, descriptor) {
				t.Fatalf("StartProcess request descriptor = %#v, want %#v", req.Descriptor, descriptor)
			}
			return ProcessHandleMetadata{ID: "fake-pid-1234", Source: "fake"}, nil
		},
	}

	handle, err := StartProcess(context.Background(), adapter, descriptor)
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	if adapter.prepareCalls != 0 {
		t.Fatalf("prepare calls = %d, want 0 during process start", adapter.prepareCalls)
	}
	if adapter.startCalls != 1 {
		t.Fatalf("start calls = %d, want 1", adapter.startCalls)
	}
	if handle.ID != "fake-pid-1234" || handle.Source != "fake" {
		t.Fatalf("handle = %#v, want fake metadata", handle)
	}
}

func TestProcessCommandDescriptorPublicJSONOmitRawHostPaths(t *testing.T) {
	config := validFirecrackerOperationConfig(t)
	config.ExecutablePath = "/Users/alice/private/bin/firecracker"
	config.KernelImagePath = "/Users/alice/private/images/vmlinux-secret"
	config.RootfsPath = "/Users/alice/private/images/rootfs-secret.ext4"
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    "runtime-alpha",
		BaseStateDir: "/Users/alice/private/firecracker-state",
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	config.Paths = paths
	plan, err := RenderStartOperationPlan(config)
	if err != nil {
		t.Fatalf("RenderStartOperationPlan() error = %v, want nil", err)
	}

	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}
	encodedDescriptor, marshalErr := json.Marshal(descriptor)
	if marshalErr != nil {
		t.Fatalf("Marshal(ProcessCommandDescriptor) error = %v", marshalErr)
	}
	encodedSummary, marshalErr := json.Marshal(descriptor.Summary())
	if marshalErr != nil {
		t.Fatalf("Marshal(OperationPlanSummary) error = %v", marshalErr)
	}

	publicText := string(encodedDescriptor) + " " + string(encodedSummary)
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"firecracker.sock",
		"firecracker-config.json",
		"firecracker.log",
		"firecracker.metrics",
		"vmlinux-secret",
		"rootfs-secret.ext4",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public process descriptor leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestProcessBoundaryRejectsInvalidPlansWithoutLeakingHostPaths(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	plan.Argv = append([]string(nil), plan.Argv...)
	plan.Argv[2] = "/Users/alice/private/firecracker.sock"

	_, err := ProcessCommandDescriptorFromStartPlan(plan)
	assertFirecrackerProcessBoundaryError(t, err, "argv")
	assertFirecrackerErrorDoesNotLeak(t, err,
		"/Users/alice",
		"private",
		"firecracker.sock",
	)
}

func TestProcessBoundaryRequiresInjectedAdapter(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)

	_, prepareErr := PrepareStartCommand(context.Background(), nil, plan)
	assertFirecrackerProcessBoundaryError(t, prepareErr, "processAdapter")

	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}
	_, startErr := StartProcess(context.Background(), nil, descriptor)
	assertFirecrackerProcessBoundaryError(t, startErr, "processAdapter")
}

func validFirecrackerStartOperationPlan(t *testing.T) StartOperationPlan {
	t.Helper()

	plan, err := RenderStartOperationPlan(validFirecrackerOperationConfig(t))
	if err != nil {
		t.Fatalf("RenderStartOperationPlan() error = %v, want nil", err)
	}
	return plan
}

func assertFirecrackerProcessBoundaryError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("process boundary error = nil, want invalid config error")
	}
	if !errors.Is(err, microvm.ErrInvalidConfig) {
		t.Fatalf("errors.Is(err, microvm.ErrInvalidConfig) = false for %v", err)
	}
	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code != microvm.ErrorCodeInvalidConfig {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, microvm.ErrorCodeInvalidConfig)
	}
	if opErr.Operation != ProcessBoundaryOperation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, ProcessBoundaryOperation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}

type fakeProcessAdapter struct {
	prepareCalls int
	startCalls   int
	prepare      func(context.Context, ProcessStartCommandRequest) (ProcessCommandDescriptor, error)
	start        func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error)
}

func (adapter *fakeProcessAdapter) PrepareStartCommand(ctx context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
	adapter.prepareCalls++
	if adapter.prepare == nil {
		return ProcessCommandDescriptorFromStartPlan(req.Plan)
	}
	return adapter.prepare(ctx, req)
}

func (adapter *fakeProcessAdapter) StartProcess(ctx context.Context, req ProcessStartRequest) (ProcessHandleMetadata, error) {
	adapter.startCalls++
	if adapter.start == nil {
		return ProcessHandleMetadata{ID: "fake-pid", Source: "fake"}, nil
	}
	return adapter.start(ctx, req)
}
