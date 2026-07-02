package firecracker

import (
	"context"
	"reflect"
	"testing"
)

func TestProcessLaunchAdapterImplementsProcessAdapter(t *testing.T) {
	var _ ProcessAdapter = ProcessLaunchAdapter{}
}

func TestProcessLaunchAdapterPrepareStartCommandDoesNotRequireStarter(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	adapter := ProcessLaunchAdapter{}

	descriptor, err := adapter.PrepareStartCommand(context.Background(), ProcessStartCommandRequest{Plan: plan})
	if err != nil {
		t.Fatalf("PrepareStartCommand() error = %v, want nil", err)
	}

	if !reflect.DeepEqual(descriptor.Argv, plan.Argv) {
		t.Fatalf("descriptor Argv = %#v, want %#v", descriptor.Argv, plan.Argv)
	}
	if descriptor.Environment == nil {
		t.Fatal("descriptor Environment = nil, want explicit empty list")
	}
}

func TestProcessLaunchAdapterStartProcessUsesInjectedStarterAndContext(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}

	type contextKey string
	ctx := context.WithValue(context.Background(), contextKey("launch"), "sentinel")
	starter := &fakeProcessStarter{
		start: func(gotCtx context.Context, req ProcessStartRequest) (ProcessHandleMetadata, error) {
			if gotCtx.Value(contextKey("launch")) != "sentinel" {
				t.Fatalf("starter context missing sentinel value")
			}
			if !reflect.DeepEqual(req.Descriptor, descriptor) {
				t.Fatalf("starter descriptor = %#v, want %#v", req.Descriptor, descriptor)
			}
			return ProcessHandleMetadata{ID: "pid-1234", Source: "starter"}, nil
		},
	}
	adapter := ProcessLaunchAdapter{Starter: starter}

	handle, err := adapter.StartProcess(ctx, ProcessStartRequest{Descriptor: descriptor})
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	if starter.startCalls != 1 {
		t.Fatalf("starter calls = %d, want 1", starter.startCalls)
	}
	if handle.ID != "pid-1234" || handle.Source != "starter" {
		t.Fatalf("handle = %#v, want fake starter metadata", handle)
	}
}

func TestProcessLaunchAdapterRequiresInjectedStarter(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}

	_, err = ProcessLaunchAdapter{}.StartProcess(context.Background(), ProcessStartRequest{Descriptor: descriptor})
	assertFirecrackerProcessBoundaryError(t, err, "processStarter")
}

type fakeProcessStarter struct {
	startCalls int
	start      func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error)
}

func (starter *fakeProcessStarter) StartProcess(ctx context.Context, req ProcessStartRequest) (ProcessHandleMetadata, error) {
	starter.startCalls++
	if starter.start == nil {
		return ProcessHandleMetadata{ID: "pid-1234", Source: "starter"}, nil
	}
	return starter.start(ctx, req)
}
