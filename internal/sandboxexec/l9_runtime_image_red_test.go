package sandboxexec

import (
	"context"
	"io"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL9ExecutorPassesSelectedRuntimeImageIntoCreate(t *testing.T) {
	const selectedImage = "registry.test/hal/runtime:stable@sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	target := &sandbox.SandboxState{
		ID:       "logical-l9",
		Name:     "runtime-l9",
		Provider: "local",
		Status:   sandbox.StatusStopped,
		Host: &sandbox.SandboxHost{
			ID:   "worker-l9",
			Name: "worker-l9",
			Kind: sandbox.SandboxHostKindWorker,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			Image:          selectedImage,
			WorkerID:       "worker-l9",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	driver := &recordingRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		create: func(_ context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
			field := reflect.ValueOf(req).FieldByName("Image")
			if !field.IsValid() || field.Kind() != reflect.String {
				t.Fatal("sandboxruntime.CreateRequest.Image string field is required")
			}
			if got := field.String(); got != selectedImage {
				t.Fatalf("create runtime image = %q, want selected digest-pinned image", got)
			}
			return &sandboxruntime.Target{
				ID:     "container-l9",
				Name:   req.Name,
				Status: sandbox.StatusStopped,
				Runtime: sandboxruntime.RuntimeState{
					Driver:         sandboxruntime.DriverRootlessPodman,
					RuntimeID:      "container-l9",
					Image:          selectedImage,
					IsolationLevel: sandbox.SandboxIsolationLevelContainer,
				},
			}, nil
		},
	}

	_, err := Run(context.Background(), CommandRequest{
		SandboxName: target.Name,
		Command:     []string{"true"},
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error { return nil },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}
