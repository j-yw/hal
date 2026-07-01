package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestSandboxWorkerRuntimeResolverBuildsClientDriverForSelectedWorkerRootlessPodman(t *testing.T) {
	host := &sandbox.SandboxHost{
		ID:       "worker-1",
		Name:     "worker one",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/private/worker-1.sock",
		SupportedRuntimes: []string{
			sandboxruntime.DriverRootlessPodman,
			sandboxruntime.DriverSSHMachine,
		},
	}
	target := sandboxruntime.Target{
		ID:     "sandbox-1",
		Name:   "dev",
		Status: sandbox.StatusRunning,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-1",
			Image:          "localhost/hal:test",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}

	var clientSocket string
	driver, err := sandboxWorkerRuntimeDriverFromTarget(sandboxWorkerRuntimeRequest{
		Target: target,
		Host:   host,
	}, sandboxWorkerRuntimeDriverFactories{
		newWorkerClient: func(socketPath string) (sandboxworker.RuntimeDriverClient, error) {
			clientSocket = socketPath
			return fakeWorkerRuntimeDriverClient{}, nil
		},
	})
	if err != nil {
		t.Fatalf("sandboxWorkerRuntimeDriverFromTarget() error = %v", err)
	}
	if clientSocket != "/tmp/private/worker-1.sock" {
		t.Fatalf("worker client socket = %q, want durable local socket path", clientSocket)
	}
	workerDriver, ok := driver.(*sandboxworker.ClientDriver)
	if !ok {
		t.Fatalf("driver type = %T, want *sandboxworker.ClientDriver", driver)
	}
	if workerDriver.ID() != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("driver ID = %q, want %q", workerDriver.ID(), sandboxruntime.DriverRootlessPodman)
	}
}

func TestSandboxWorkerRuntimeResolverUsesInjectableRuntimeFactory(t *testing.T) {
	wantClient := fakeWorkerRuntimeDriverClient{}
	var gotOptions sandboxworker.ClientDriverOptions
	driver, err := sandboxWorkerRuntimeDriverFromTarget(sandboxWorkerRuntimeRequest{
		Target: sandboxruntime.Target{
			Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman},
		},
		Host: &sandbox.SandboxHost{
			ID:                "worker-1",
			Name:              "worker one",
			Kind:              sandbox.SandboxHostKindWorker,
			Endpoint:          "/tmp/private/worker-1.sock",
			SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
		},
	}, sandboxWorkerRuntimeDriverFactories{
		newWorkerClient: func(socketPath string) (sandboxworker.RuntimeDriverClient, error) {
			if socketPath != "/tmp/private/worker-1.sock" {
				t.Fatalf("socketPath = %q, want durable local socket path", socketPath)
			}
			return wantClient, nil
		},
		newRuntimeDriver: func(options sandboxworker.ClientDriverOptions) (sandboxruntime.Driver, error) {
			gotOptions = options
			return fakeRuntimeResolverDriver{id: "fake_worker_rootless"}, nil
		},
	})
	if err != nil {
		t.Fatalf("sandboxWorkerRuntimeDriverFromTarget() error = %v", err)
	}
	if driver == nil || driver.ID() != "fake_worker_rootless" {
		t.Fatalf("driver = %#v, want fake injected worker driver", driver)
	}
	if gotOptions.DriverID != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("factory driver ID = %q, want %q", gotOptions.DriverID, sandboxruntime.DriverRootlessPodman)
	}
	if gotOptions.Client != wantClient {
		t.Fatalf("factory client = %#v, want injected worker client", gotOptions.Client)
	}
}

func TestSandboxWorkerRuntimeResolverRejectsUnselectedOrUnsupportedTargets(t *testing.T) {
	baseHost := &sandbox.SandboxHost{
		ID:                "worker-1",
		Name:              "worker one",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/worker-1.sock",
		SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
	}
	tests := []struct {
		name    string
		req     sandboxWorkerRuntimeRequest
		wantErr string
	}{
		{
			name: "missing host",
			req: sandboxWorkerRuntimeRequest{
				Target: sandboxruntime.Target{Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman}},
			},
			wantErr: "selected worker host metadata is required",
		},
		{
			name: "non-worker host",
			req: sandboxWorkerRuntimeRequest{
				Target: sandboxruntime.Target{Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman}},
				Host: &sandbox.SandboxHost{
					ID:                "ssh-host",
					Name:              "ssh host",
					Kind:              sandbox.SandboxHostKindSSH,
					Endpoint:          "ssh://deploy:secret@example.test?token=abc",
					SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
				},
			},
			wantErr: "is not a worker host",
		},
		{
			name: "missing runtime",
			req: sandboxWorkerRuntimeRequest{
				Target: sandboxruntime.Target{},
				Host:   baseHost,
			},
			wantErr: "selected runtime driver is required",
		},
		{
			name: "unsupported runtime",
			req: sandboxWorkerRuntimeRequest{
				Target: sandboxruntime.Target{Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverMicroVM}},
				Host:   baseHost,
			},
			wantErr: `does not support requested runtime "microvm"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := sandboxWorkerRuntimeDriverFromTarget(tt.req, sandboxWorkerRuntimeDriverFactories{
				newWorkerClient: func(string) (sandboxworker.RuntimeDriverClient, error) {
					t.Fatal("worker client should not be constructed for invalid worker runtime selections")
					return nil, nil
				},
			})
			if err == nil {
				t.Fatal("sandboxWorkerRuntimeDriverFromTarget() error = nil, want validation error")
			}
			if driver != nil {
				t.Fatalf("driver = %#v, want nil on validation error", driver)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
			for _, leaked := range []string{"deploy:secret", "example.test", "token=abc", "/tmp/private/worker-1.sock"} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("error leaked unsafe detail %q: %q", leaked, err.Error())
				}
			}
		})
	}
}

func TestSandboxWorkerRuntimeResolverRejectsMissingOrUnsupportedEndpointsBeforeClient(t *testing.T) {
	tests := []struct {
		name                string
		endpoint            string
		wantEndpointSummary string
	}{
		{
			name:                "missing endpoint",
			wantEndpointSummary: "configured endpoint: none",
		},
		{
			name:                "non local endpoint",
			endpoint:            "ssh://deploy:secret@example.test/tmp/private/worker-1.sock?token=secret",
			wantEndpointSummary: "configured endpoint: ssh endpoint",
		},
		{
			name:                "unsupported configured endpoint",
			endpoint:            "worker-1.sock?token=secret",
			wantEndpointSummary: "configured endpoint: configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := sandboxWorkerRuntimeDriverFromTarget(sandboxWorkerRuntimeRequest{
				Target: sandboxruntime.Target{
					Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman},
				},
				Host: &sandbox.SandboxHost{
					ID:                "worker-1",
					Name:              "worker one",
					Kind:              sandbox.SandboxHostKindWorker,
					Endpoint:          tt.endpoint,
					SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
				},
			}, sandboxWorkerRuntimeDriverFactories{
				newWorkerClient: func(string) (sandboxworker.RuntimeDriverClient, error) {
					t.Fatal("worker client should not be constructed when worker endpoint metadata is unusable")
					return nil, nil
				},
			})
			if err == nil {
				t.Fatal("sandboxWorkerRuntimeDriverFromTarget() error = nil, want endpoint validation error")
			}
			if driver != nil {
				t.Fatalf("driver = %#v, want nil on endpoint validation error", driver)
			}
			for _, want := range []string{"worker_endpoint_invalid", "worker-1", sandboxruntime.DriverRootlessPodman, tt.wantEndpointSummary} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want %q", err.Error(), want)
				}
			}
			for _, leaked := range []string{"deploy:secret", "example.test", "token=secret", "/tmp/private/worker-1.sock"} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("error leaked unsafe endpoint detail %q: %q", leaked, err.Error())
				}
			}
		})
	}
}

func TestSandboxWorkerRuntimeResolverWrapsWorkerClientFactoryFailures(t *testing.T) {
	driver, err := sandboxWorkerRuntimeDriverFromTarget(sandboxWorkerRuntimeRequest{
		Target: sandboxruntime.Target{
			Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman},
		},
		Host: &sandbox.SandboxHost{
			ID:                "worker-1",
			Name:              "worker one",
			Kind:              sandbox.SandboxHostKindWorker,
			Endpoint:          "unix:///tmp/private/worker-1.sock",
			SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
		},
	}, sandboxWorkerRuntimeDriverFactories{
		newWorkerClient: func(string) (sandboxworker.RuntimeDriverClient, error) {
			return nil, errors.New("dial /tmp/private/worker-1.sock?token=secret failed")
		},
	})
	if err == nil {
		t.Fatal("sandboxWorkerRuntimeDriverFromTarget() error = nil, want worker client error")
	}
	if driver != nil {
		t.Fatalf("driver = %#v, want nil on worker client error", driver)
	}
	var clientErr *sandboxworker.ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("error type = %T, want *sandboxworker.ClientError", err)
	}
	for _, leaked := range []string{"/tmp/private/worker-1.sock", "token=secret"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error leaked unsafe detail %q: %q", leaked, err.Error())
		}
	}
}
