package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/spf13/cobra"
)

func TestSandboxdCommandRegisteredWithoutDisruptingSandboxCommands(t *testing.T) {
	cmd, err := commandAtPath(Root(), "sandboxd")
	if err != nil {
		t.Fatalf("sandboxd command missing: %v", err)
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("sandboxd missing metadata fields: %v", missing)
	}
	for _, flagName := range []string{"socket", "worker-id", "driver", "podman", "max-concurrent", "json"} {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Fatalf("sandboxd missing --%s flag", flagName)
		}
	}

	sandbox, err := commandAtPath(Root(), "sandbox")
	if err != nil {
		t.Fatalf("sandbox command missing: %v", err)
	}
	if child := findDirectSubcommandByName(sandbox, "sandboxd"); child != nil {
		t.Fatal("sandboxd should be a top-level command, not a hal sandbox subcommand")
	}
	for _, subcommand := range []string{"setup", "auth", "create", "start", "stop", "status", "delete", "ssh"} {
		if _, err := commandAtPath(Root(), "sandbox", subcommand); err != nil {
			t.Fatalf("sandbox subcommand %q disrupted: %v", subcommand, err)
		}
	}
}

func TestSandboxdCommandParsesFlagsAndUsesInjectedDependencies(t *testing.T) {
	handler := &recordingSandboxdHandler{}
	var gotService sandboxworker.ServiceOptions
	var gotServer sandboxworker.ServerOptions
	var gotAvailabilityPodmanPath string
	var gotPodmanPath string
	var gotServeContext context.Context

	cmd, stdout, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			gotService = options
			return handler, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			gotServer = options
			return sandboxdServerFunc(func(ctx context.Context) error {
				gotServeContext = ctx
				return nil
			}), nil
		},
		rootlessPodmanAvailable: func(_ context.Context, podmanPath string) error {
			gotAvailabilityPodmanPath = podmanPath
			return nil
		},
		newRootlessPodmanDriver: func(podmanPath string) sandboxruntime.Driver {
			gotPodmanPath = podmanPath
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func() string {
			return "unused-default-worker"
		},
	})

	cmd.SetArgs([]string{
		"--socket", "/tmp/custom-sandboxd.sock",
		"--worker-id", "worker-test",
		"--driver", "rootless_podman",
		"--podman", "podman-test",
		"--max-concurrent", "3",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}

	if gotService.WorkerID != "worker-test" {
		t.Fatalf("service workerID = %q, want worker-test", gotService.WorkerID)
	}
	if gotService.HostKind != sandboxworker.HostKindLocal {
		t.Fatalf("service hostKind = %q, want %q", gotService.HostKind, sandboxworker.HostKindLocal)
	}
	if gotService.SocketPath != "/tmp/custom-sandboxd.sock" {
		t.Fatalf("service socketPath = %q", gotService.SocketPath)
	}
	if gotService.Capacity.MaxConcurrentSandboxes != 3 {
		t.Fatalf("maxConcurrentSandboxes = %d, want 3", gotService.Capacity.MaxConcurrentSandboxes)
	}
	if gotService.Registry == nil {
		t.Fatal("service registry is nil")
	}
	if got := strings.Join(gotService.Registry.DriverIDs(), ","); got != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("service registry driver IDs = %q, want %q", got, sandboxruntime.DriverRootlessPodman)
	}
	if gotAvailabilityPodmanPath != "podman-test" {
		t.Fatalf("availability podman path = %q, want podman-test", gotAvailabilityPodmanPath)
	}
	if gotPodmanPath != "podman-test" {
		t.Fatalf("podman path = %q, want podman-test", gotPodmanPath)
	}
	if gotServer.SocketPath != "/tmp/custom-sandboxd.sock" {
		t.Fatalf("server socketPath = %q", gotServer.SocketPath)
	}
	if gotServer.Handler != handler {
		t.Fatalf("server handler = %#v, want injected service handler", gotServer.Handler)
	}
	if gotServeContext == nil {
		t.Fatal("serve context was not passed to injected server")
	}

	var started sandboxdStartedOutput
	if err := json.Unmarshal(stdout.Bytes(), &started); err != nil {
		t.Fatalf("startup JSON = %q, unmarshal error: %v", stdout.String(), err)
	}
	if started.Status != "listening" || started.WorkerID != "worker-test" || started.SocketPath != "/tmp/custom-sandboxd.sock" {
		t.Fatalf("startup JSON = %#v", started)
	}
	if got := strings.Join(started.Drivers, ","); got != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("startup drivers = %q, want %q", got, sandboxruntime.DriverRootlessPodman)
	}
}

func TestSandboxdCommandUsesDefaultWorkerIDDependency(t *testing.T) {
	var gotService sandboxworker.ServiceOptions
	cmd, stdout, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			gotService = options
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
		rootlessPodmanAvailable: func(context.Context, string) error {
			return nil
		},
		newRootlessPodmanDriver: func(string) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func() string {
			return "worker-from-deps"
		},
	})
	cmd.SetArgs([]string{"--socket", "/tmp/default-worker.sock"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}
	if gotService.WorkerID != "worker-from-deps" {
		t.Fatalf("service workerID = %q, want dependency default", gotService.WorkerID)
	}
	if !strings.Contains(stdout.String(), "worker-from-deps") {
		t.Fatalf("human startup output = %q, want worker id", stdout.String())
	}
}

func TestSandboxdCommandRejectsMicroVMDriverWithoutConfiguredFactory(t *testing.T) {
	serviceCalled := false
	serverCalled := false
	cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			serviceCalled = true
			return nil, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			serverCalled = true
			return nil, nil
		},
		workerID: func() string {
			return "worker-test"
		},
	})
	cmd.SetArgs([]string{"--driver", sandboxruntime.DriverMicroVM})

	err := cmd.Execute()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Execute() error = %T, want ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if exitErr.Err == nil || !strings.Contains(exitErr.Err.Error(), `driver "microvm" is unsupported`) {
		t.Fatalf("exit error = %#v, want unsupported microVM driver detail", exitErr.Err)
	}
	if serviceCalled || serverCalled {
		t.Fatalf("serviceCalled=%v serverCalled=%v, want neither called", serviceCalled, serverCalled)
	}
}

func TestSandboxdCommandRegistersMicroVMOnlyWithInjectedFactory(t *testing.T) {
	handler := &recordingSandboxdHandler{}
	var gotService sandboxworker.ServiceOptions
	microVMConstructed := false
	rootlessAvailabilityCalled := false

	cmd, stdout, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			gotService = options
			return handler, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
		rootlessPodmanAvailable: func(context.Context, string) error {
			rootlessAvailabilityCalled = true
			return nil
		},
		newMicroVMDriver: func() sandboxruntime.Driver {
			microVMConstructed = true
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverMicroVM}
		},
		workerID: func() string {
			return "unused-default-worker"
		},
	})
	cmd.SetArgs([]string{
		"--socket", "/tmp/microvm-sandboxd.sock",
		"--worker-id", "worker-microvm",
		"--driver", sandboxruntime.DriverMicroVM,
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}

	if !microVMConstructed {
		t.Fatal("microVM driver factory was not called")
	}
	if rootlessAvailabilityCalled {
		t.Fatal("rootless Podman availability should not be checked for injected microVM-only registration")
	}
	if gotService.Registry == nil {
		t.Fatal("service registry is nil")
	}
	if got := strings.Join(gotService.Registry.DriverIDs(), ","); got != sandboxruntime.DriverMicroVM {
		t.Fatalf("service registry driver IDs = %q, want %q", got, sandboxruntime.DriverMicroVM)
	}

	var started sandboxdStartedOutput
	if err := json.Unmarshal(stdout.Bytes(), &started); err != nil {
		t.Fatalf("startup JSON = %q, unmarshal error: %v", stdout.String(), err)
	}
	if got := strings.Join(started.Drivers, ","); got != sandboxruntime.DriverMicroVM {
		t.Fatalf("startup drivers = %q, want %q", got, sandboxruntime.DriverMicroVM)
	}
}

func TestSandboxdRootlessPodmanUnavailableFailsBeforeService(t *testing.T) {
	req := sandboxdRequest{
		SocketPath:    "/tmp/hal-sandboxd-unavailable.sock",
		WorkerID:      "worker-test",
		Drivers:       []string{sandboxruntime.DriverRootlessPodman},
		PodmanPath:    "ssh://deploy:secret@example.test/tmp/private/podman?token=raw-secret",
		MaxConcurrent: 1,
		JSON:          true,
	}
	var stdout bytes.Buffer
	driverConstructed := false
	serviceCalled := false
	serverCalled := false

	err := runSandboxdWithDeps(context.Background(), req, &stdout, sandboxdDeps{
		rootlessPodmanAvailable: func(context.Context, string) error {
			return errors.New("stat /tmp/private/podman failed token=raw-secret at ssh://deploy:secret@example.test/tmp/private")
		},
		newRootlessPodmanDriver: func(string) sandboxruntime.Driver {
			driverConstructed = true
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			serviceCalled = true
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			serverCalled = true
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
	})
	if err == nil {
		t.Fatal("runSandboxdWithDeps() error = nil, want runtime_unavailable")
	}
	if !strings.Contains(err.Error(), "runtime_unavailable") || !strings.Contains(err.Error(), sandboxruntime.DriverRootlessPodman) {
		t.Fatalf("error = %q, want runtime_unavailable rootless_podman classification", err.Error())
	}
	if driverConstructed || serviceCalled || serverCalled {
		t.Fatalf("driverConstructed=%v serviceCalled=%v serverCalled=%v, want all false", driverConstructed, serviceCalled, serverCalled)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no startup JSON when runtime unavailable", stdout.String())
	}
	for _, leaked := range []string{
		"/tmp/private",
		req.SocketPath,
		"deploy:secret",
		"example.test",
		"token=raw-secret",
		"raw-secret",
	} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("runtime unavailable error leaked %q: %q", leaked, err.Error())
		}
	}
}

func TestSandboxdCommandRejectsUnsupportedDriverBeforeOpeningServer(t *testing.T) {
	serviceCalled := false
	serverCalled := false
	cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			serviceCalled = true
			return nil, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			serverCalled = true
			return nil, nil
		},
		workerID: func() string {
			return "worker-test"
		},
	})
	cmd.SetArgs([]string{"--driver", "ssh_machine"})

	err := cmd.Execute()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Execute() error = %T, want ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if exitErr.Err == nil || !strings.Contains(exitErr.Err.Error(), `driver "ssh_machine" is unsupported`) {
		t.Fatalf("exit error = %#v, want unsupported driver detail", exitErr.Err)
	}
	if serviceCalled || serverCalled {
		t.Fatalf("serviceCalled=%v serverCalled=%v, want neither called", serviceCalled, serverCalled)
	}
}

func TestSandboxdCommandRendersServeErrors(t *testing.T) {
	cmd, stdout, stderr := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error {
				return errors.New("listen failed")
			}), nil
		},
		rootlessPodmanAvailable: func(context.Context, string) error {
			return nil
		},
		newRootlessPodmanDriver: func(string) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func() string {
			return "worker-test"
		},
	})
	cmd.SetArgs([]string{"--socket", "/tmp/failing-sandboxd.sock"})

	err := cmd.Execute()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Execute() error = %T, want ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeExpectedNonZero {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeExpectedNonZero)
	}
	if !strings.Contains(stdout.String(), "sandboxd listening on /tmp/failing-sandboxd.sock") {
		t.Fatalf("stdout = %q, want startup line before serve error", stdout.String())
	}
	output := stderr.String()
	if !strings.Contains(output, "Sandboxd failed") || !strings.Contains(output, "listen failed") {
		t.Fatalf("stderr = %q, want rendered sandboxd error", output)
	}
	if strings.Contains(output, "Usage:") || strings.Contains(output, "Error:") {
		t.Fatalf("stderr should not include raw cobra usage/error output: %q", output)
	}
}

func newTestSandboxdCommand(deps sandboxdDeps) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	cmd := newSandboxdCommand(deps)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	return cmd, &stdout, &stderr
}

type recordingSandboxdHandler struct{}

func (handler *recordingSandboxdHandler) HandleRequest(ctx context.Context, req sandboxworker.Request) sandboxworker.Response {
	return sandboxworker.Response{
		ProtocolVersion: sandboxworker.ProtocolVersion,
		RequestID:       req.RequestID,
		Operation:       req.Operation,
		OK:              true,
	}
}

type sandboxdServerFunc func(context.Context) error

func (fn sandboxdServerFunc) ListenAndServe(ctx context.Context) error {
	return fn(ctx)
}

type fakeSandboxdRuntimeDriver struct {
	id string
}

func (driver fakeSandboxdRuntimeDriver) ID() string {
	if driver.id != "" {
		return driver.id
	}
	return sandboxruntime.DriverRootlessPodman
}

func (driver fakeSandboxdRuntimeDriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return &sandboxruntime.Target{Runtime: sandboxruntime.RuntimeState{Driver: driver.ID()}}, nil
}

func (driver fakeSandboxdRuntimeDriver) Start(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (driver fakeSandboxdRuntimeDriver) Stop(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (driver fakeSandboxdRuntimeDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (driver fakeSandboxdRuntimeDriver) Inspect(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (driver fakeSandboxdRuntimeDriver) Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}

func (driver fakeSandboxdRuntimeDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (driver fakeSandboxdRuntimeDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}
