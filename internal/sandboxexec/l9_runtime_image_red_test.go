package sandboxexec

import (
	"context"
	"errors"
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

func TestL9RunningTargetRequiresObservedRuntimeImageBeforeReady(t *testing.T) {
	const selectedImage = "registry.test/hal/runtime:stable@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	target := l9SelectedRuntimeImageTarget("runtime-l9-running", selectedImage, sandbox.StatusRunning)
	inspectErr := errors.New("inspect unavailable")
	readyCalled := false
	driver := &recordingRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		inspect: func(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
			return nil, inspectErr
		},
	}

	_, err := Run(context.Background(), CommandRequest{
		SandboxName: target.Name,
		Command:     []string{"true"},
	}, Dependencies{
		SelectedRuntimeImage: selectedImage,
		ResolveTarget:        func(context.Context, TargetRequest) (*sandbox.SandboxState, error) { return target, nil },
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		OnTargetReady: func(context.Context, *sandbox.SandboxState) error {
			readyCalled = true
			return nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error { return nil },
	})
	if err == nil || !errors.Is(err, inspectErr) {
		t.Fatalf("Run() error = %v, want observed-image inspect failure", err)
	}
	if readyCalled {
		t.Fatal("target readiness persisted before runtime image observation")
	}
	if driver.deleteCalled {
		t.Fatal("executor cleaned a running runtime it did not create")
	}
}

func TestL9StartedTargetRejectsMissingOrMismatchedObservedRuntimeImage(t *testing.T) {
	const selectedImage = "registry.test/hal/runtime:stable@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tt := range []struct {
		name     string
		observed string
	}{
		{name: "missing"},
		{name: "mismatched", observed: "registry.test/hal/runtime:stable@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target := l9SelectedRuntimeImageTarget("runtime-l9-"+tt.name, selectedImage, sandbox.StatusStopped)
			readyCalled := false
			driver := &recordingRuntimeDriver{
				id: sandboxruntime.DriverRootlessPodman,
				start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
					started := req.Target
					started.Status = sandbox.StatusRunning
					return &started, nil
				},
				inspect: func(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
					observed := req.Target
					observed.Runtime.Image = tt.observed
					return &observed, nil
				},
			}

			_, err := Run(context.Background(), CommandRequest{
				SandboxName: target.Name,
				Command:     []string{"true"},
			}, Dependencies{
				SelectedRuntimeImage: selectedImage,
				ResolveTarget:        func(context.Context, TargetRequest) (*sandbox.SandboxState, error) { return target, nil },
				ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
					return driver, nil
				},
				OnTargetReady: func(context.Context, *sandbox.SandboxState) error {
					readyCalled = true
					return nil
				},
				RunCommand: func(context.Context, RunContext, CommandRequest) error { return nil },
			})
			if err == nil || err.Error() != "selection_rejected" {
				t.Fatalf("Run() error = %v, want selection_rejected", err)
			}
			if readyCalled {
				t.Fatal("target readiness persisted for unverified runtime image")
			}
			if driver.deleteCalled {
				t.Fatal("executor cleaned a stopped runtime it did not create")
			}
		})
	}
}

func TestL9CreatedRuntimeIsCleanedAfterObservedImageMismatch(t *testing.T) {
	const selectedImage = "registry.test/hal/runtime:stable@sha256:3434343434343434343434343434343434343434343434343434343434343434"
	target := l9SelectedRuntimeImageTarget("runtime-l9-created", selectedImage, sandbox.StatusStopped)
	target.Runtime.RuntimeID = ""
	target.Host = &sandbox.SandboxHost{ID: "worker-l9", Name: "worker-l9", Kind: sandbox.SandboxHostKindWorker}
	target.Runtime.WorkerID = "worker-l9"
	deleteCalls := 0
	driver := &recordingRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		create: func(_ context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
			return &sandboxruntime.Target{
				ID:     "container-l9-created",
				Name:   req.Name,
				Status: sandbox.StatusStopped,
				Runtime: sandboxruntime.RuntimeState{
					Driver:    sandboxruntime.DriverRootlessPodman,
					RuntimeID: "container-l9-created",
					Image:     selectedImage,
				},
			}, nil
		},
		start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
			started := req.Target
			started.Status = sandbox.StatusRunning
			return &started, nil
		},
		inspect: func(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
			observed := req.Target
			observed.Runtime.Image = ""
			return &observed, nil
		},
		delete: func(_ context.Context, req sandboxruntime.LifecycleRequest) error {
			deleteCalls++
			if req.Target.Runtime.RuntimeID != "container-l9-created" {
				t.Fatalf("cleanup runtime ID = %q, want created runtime", req.Target.Runtime.RuntimeID)
			}
			return nil
		},
	}

	_, err := Run(context.Background(), CommandRequest{SandboxName: target.Name, Command: []string{"true"}}, Dependencies{
		SelectedRuntimeImage: selectedImage,
		ResolveTarget:        func(context.Context, TargetRequest) (*sandbox.SandboxState, error) { return target, nil },
		ResolveDriver: func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
		},
		RunCommand: func(context.Context, RunContext, CommandRequest) error { return nil },
	})
	if err == nil || err.Error() != "selection_rejected" {
		t.Fatalf("Run() error = %v, want selection_rejected", err)
	}
	if deleteCalls != 1 {
		t.Fatalf("cleanup calls = %d, want exactly 1", deleteCalls)
	}
}

func l9SelectedRuntimeImageTarget(name, image, status string) *sandbox.SandboxState {
	const digest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	return &sandbox.SandboxState{
		ID:       "target-" + name,
		Name:     name,
		Provider: "local",
		Status:   status,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "runtime-" + name,
			Image:          image,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			TemplateLock: &sandbox.SandboxTemplateLockMetadata{
				RuntimeImage: &sandbox.SandboxTemplateLockEntryMetadata{
					SourceKind:      "runtime_image",
					ReferenceKind:   "oci_image",
					Status:          "locked",
					DigestAlgorithm: "sha256",
					DigestValue:     digest,
				},
			},
		},
	}
}
