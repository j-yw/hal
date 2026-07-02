package firecracker

import (
	"context"
	"errors"
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

func TestProcessLaunchAdapterStartProcessBuildsRunnerRequestAndUsesContext(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}

	type contextKey string
	ctx := context.WithValue(context.Background(), contextKey("launch"), "sentinel")
	starter := &fakeProcessStarter{
		start: func(gotCtx context.Context, req ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
			if gotCtx.Value(contextKey("launch")) != "sentinel" {
				t.Fatalf("starter context missing sentinel value")
			}
			if req.Executable != descriptor.Executable.Path {
				t.Fatalf("runner Executable = %q, want %q", req.Executable, descriptor.Executable.Path)
			}
			if !reflect.DeepEqual(req.Args, descriptor.Argv[1:]) {
				t.Fatalf("runner Args = %#v, want %#v", req.Args, descriptor.Argv[1:])
			}
			if req.Environment == nil {
				t.Fatal("runner Environment = nil, want explicit empty list so host env is not inherited")
			}
			if len(req.Environment) != 0 {
				t.Fatalf("runner Environment = %#v, want no environment variables delivered", req.Environment)
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

func TestProcessLaunchAdapterStartProcessRejectsDescriptorEnvironmentBeforeStarter(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}
	descriptor.Environment = []OperationEnvironmentMetadata{
		{Name: "SECRET_TOKEN", Source: "env:OPENAI_API_KEY"},
	}
	starter := &fakeProcessStarter{}

	_, err = (ProcessLaunchAdapter{Starter: starter}).StartProcess(context.Background(), ProcessStartRequest{Descriptor: descriptor})

	assertFirecrackerProcessBoundaryError(t, err, "environment")
	assertFirecrackerErrorDoesNotLeak(t, err, "SECRET_TOKEN", "OPENAI_API_KEY")
	if starter.startCalls != 0 {
		t.Fatalf("starter calls = %d, want 0 for descriptor environment rejection", starter.startCalls)
	}
}

func TestProcessLaunchAdapterStartProcessHonorsCanceledContextBeforeStarter(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	starter := &fakeProcessStarter{}

	_, err = (ProcessLaunchAdapter{Starter: starter}).StartProcess(ctx, ProcessStartRequest{Descriptor: descriptor})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("StartProcess() error = %v, want context.Canceled", err)
	}
	if starter.startCalls != 0 {
		t.Fatalf("starter calls = %d, want 0 after canceled context", starter.startCalls)
	}
}

func TestProcessLaunchAdapterStartProcessSanitizesStarterHandleMetadata(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatalf("ProcessCommandDescriptorFromStartPlan() error = %v, want nil", err)
	}
	starter := &fakeProcessStarter{
		start: func(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
			return ProcessHandleMetadata{
				ID:     "pid-1234 /Users/alice/private token=ghp_secret",
				Source: "starter/secret",
			}, nil
		},
	}

	handle, err := (ProcessLaunchAdapter{Starter: starter}).StartProcess(context.Background(), ProcessStartRequest{Descriptor: descriptor})
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	if handle.ID != "" || handle.Source != "" {
		t.Fatalf("handle = %#v, want unsafe starter metadata cleared", handle)
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
	start      func(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error)
}

func (starter *fakeProcessStarter) StartProcess(ctx context.Context, req ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	starter.startCalls++
	if starter.start == nil {
		return ProcessHandleMetadata{ID: "pid-1234", Source: "starter"}, nil
	}
	return starter.start(ctx, req)
}
