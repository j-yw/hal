package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
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
	for _, flagName := range []string{
		"socket",
		"worker-id",
		"driver",
		"podman",
		"image",
		"max-concurrent",
		"json",
	} {
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

func TestDefaultSandboxdRootlessPodmanAvailableChecksServiceAndImage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake podman executable uses a POSIX shell")
	}
	dir := t.TempDir()
	podmanPath := filepath.Join(dir, "podman-test")
	logPath := filepath.Join(dir, "podman.log")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$PODMAN_TEST_LOG"
if [ "$1" = "info" ]; then
  [ "${PODMAN_TEST_FAIL_INFO:-}" = "1" ] && exit 1
  exit 0
fi
if [ "$1" = "image" ] && [ "$2" = "exists" ]; then
  [ "$3" = "localhost/hal-agent:test" ] || exit 1
  [ "${PODMAN_TEST_FAIL_IMAGE:-}" = "1" ] && exit 1
  exit 0
fi
exit 2
`
	if err := os.WriteFile(podmanPath, []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile(fake podman) error: %v", err)
	}
	t.Setenv("PODMAN_TEST_LOG", logPath)
	config := sandboxdRootlessPodmanConfig{
		PodmanPath: podmanPath,
		Image:      "localhost/hal-agent:test",
	}

	if err := defaultSandboxdRootlessPodmanAvailable(context.Background(), config); err != nil {
		t.Fatalf("defaultSandboxdRootlessPodmanAvailable() unexpected error: %v", err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(podman log) error: %v", err)
	}
	if got, want := string(logData), "info --format json\nimage exists localhost/hal-agent:test\n"; got != want {
		t.Fatalf("podman calls = %q, want %q", got, want)
	}

	t.Setenv("PODMAN_TEST_FAIL_INFO", "1")
	if err := defaultSandboxdRootlessPodmanAvailable(context.Background(), config); err == nil || !strings.Contains(err.Error(), "podman service is unavailable") {
		t.Fatalf("service preflight error = %v, want unavailable service", err)
	}
	t.Setenv("PODMAN_TEST_FAIL_INFO", "")
	t.Setenv("PODMAN_TEST_FAIL_IMAGE", "1")
	if err := defaultSandboxdRootlessPodmanAvailable(context.Background(), config); err == nil || !strings.Contains(err.Error(), "podman image is unavailable") {
		t.Fatalf("image preflight error = %v, want unavailable image", err)
	}
}

func TestSandboxdCommandParsesFlagsAndUsesInjectedDependencies(t *testing.T) {
	handler := &recordingSandboxdHandler{}
	var gotService sandboxworker.ServiceOptions
	var gotServer sandboxworker.ServerOptions
	var gotAvailabilityPodmanPath string
	var gotAvailabilityPodmanImage string
	var gotPodmanPath string
	var gotPodmanImage string
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
		rootlessPodmanAvailable: func(_ context.Context, config sandboxdRootlessPodmanConfig) error {
			gotAvailabilityPodmanPath = config.PodmanPath
			gotAvailabilityPodmanImage = config.Image
			return nil
		},
		newRootlessPodmanDriver: func(config sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
			gotPodmanPath = config.PodmanPath
			gotPodmanImage = config.Image
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func(string) string {
			return "unused-default-worker"
		},
	})

	cmd.SetArgs([]string{
		"--socket", "/tmp/custom-sandboxd.sock",
		"--worker-id", "worker-test",
		"--driver", "rootless_podman",
		"--podman", "podman-test",
		"--image", "localhost/hal-agent:test",
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
	if gotAvailabilityPodmanImage != "localhost/hal-agent:test" || gotPodmanImage != "localhost/hal-agent:test" {
		t.Fatalf("podman images availability/driver = %q/%q, want localhost/hal-agent:test", gotAvailabilityPodmanImage, gotPodmanImage)
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

func TestSandboxdDefaultCapabilitiesDoNotClaimNetworkPolicyEnforcement(t *testing.T) {
	var gotService sandboxworker.ServiceOptions
	cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			gotService = options
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
		rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error {
			return nil
		},
		newRootlessPodmanDriver: func(sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func(string) string {
			return "worker-default-security"
		},
	})
	cmd.SetArgs([]string{"--socket", "/tmp/default-security-sandboxd.sock", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}
	service, err := sandboxworker.NewService(gotService)
	if err != nil {
		t.Fatalf("NewService(gotService) error: %v", err)
	}
	capabilities := service.Capabilities()
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error: %v", err)
	}
	assertSandboxdDefaultCapabilitySecurity(t, "worker", capabilities.Security)
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want exactly one default rootless driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("default runtime driver ID = %q, want %q", driver.ID, sandboxruntime.DriverRootlessPodman)
	}
	assertSandboxdDefaultCapabilitySecurity(t, "runtime driver", driver.Security)
}

func TestSandboxdCommandUsesDefaultWorkerIDDependency(t *testing.T) {
	var gotService sandboxworker.ServiceOptions
	var gotJobStateDir string
	cmd, stdout, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			gotService = options
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
		rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error {
			return nil
		},
		newRootlessPodmanDriver: func(sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func(jobStateDir string) string {
			gotJobStateDir = jobStateDir
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
	if gotJobStateDir != "/tmp/default-worker.sock.jobs" {
		t.Fatalf("worker ID dependency state root = %q, want socket-scoped job state root", gotJobStateDir)
	}
	if !strings.Contains(stdout.String(), "worker-from-deps") {
		t.Fatalf("human startup output = %q, want worker id", stdout.String())
	}
}

func TestDefaultSandboxdWorkerIDIsStableAndStateRootScoped(t *testing.T) {
	firstRoot := filepath.Join(t.TempDir(), "first", "jobs")
	first := defaultSandboxdWorkerID(firstRoot)
	if again := defaultSandboxdWorkerID(firstRoot); again != first {
		t.Fatalf("default worker ID changed for the same state root: %q then %q", first, again)
	}
	secondRoot := filepath.Join(t.TempDir(), "second", "jobs")
	if second := defaultSandboxdWorkerID(secondRoot); second == first {
		t.Fatalf("default worker ID %q did not distinguish durable state roots", first)
	}
	for _, forbidden := range []string{firstRoot, secondRoot, string(filepath.Separator)} {
		if strings.Contains(first, forbidden) {
			t.Fatalf("default worker ID exposed path material %q: %q", forbidden, first)
		}
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
		rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error {
			return errors.New("stat /tmp/private/podman failed token=raw-secret at ssh://deploy:secret@example.test/tmp/private")
		},
		newRootlessPodmanDriver: func(sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
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
		workerID: func(string) string {
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
		rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error {
			return nil
		},
		newRootlessPodmanDriver: func(sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func(string) string {
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

func TestRunSandboxdClosesWorkerServiceAfterServing(t *testing.T) {
	handler := &closableSandboxdHandler{}
	req := sandboxdRequest{
		SocketPath:    "/tmp/hal-sandboxd-close.sock",
		JobStateDir:   filepath.Join(t.TempDir(), "jobs"),
		WorkerID:      "worker-close",
		Drivers:       []string{sandboxruntime.DriverRootlessPodman},
		PodmanPath:    "fake-podman",
		PodmanImage:   "localhost/hal-agent:test",
		MaxConcurrent: 1,
	}
	err := runSandboxdWithDeps(context.Background(), req, io.Discard, sandboxdDeps{
		rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error {
			return nil
		},
		newRootlessPodmanDriver: func(sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		newService: func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			return handler, nil
		},
		newServer: func(sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
	})
	if err != nil {
		t.Fatalf("runSandboxdWithDeps() error: %v", err)
	}
	if !handler.closed {
		t.Fatal("runSandboxdWithDeps() returned without closing its worker service")
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

type closableSandboxdHandler struct {
	recordingSandboxdHandler
	closed bool
}

func (handler *closableSandboxdHandler) Close() {
	handler.closed = true
}

type sandboxdServerFunc func(context.Context) error

func (fn sandboxdServerFunc) ListenAndServe(ctx context.Context) error {
	return fn(ctx)
}

func assertSandboxdDefaultCapabilitySecurity(t *testing.T, label string, policy sandboxworker.SecurityPolicy) {
	t.Helper()
	if err := policy.Validate(); err != nil {
		t.Fatalf("%s security policy Validate() error: %v", label, err)
	}
	if policy.Requested.NetworkPolicy != sandboxworker.NetworkPolicyDenyByDefault {
		t.Fatalf("%s requested networkPolicy = %q, want %q", label, policy.Requested.NetworkPolicy, sandboxworker.NetworkPolicyDenyByDefault)
	}
	if policy.Enforced.NetworkPolicy != sandboxworker.NetworkPolicyBestEffort {
		t.Fatalf("%s enforced networkPolicy = %q, want %q", label, policy.Enforced.NetworkPolicy, sandboxworker.NetworkPolicyBestEffort)
	}
	if policy.Enforced.NetworkPolicy == sandboxworker.NetworkPolicyDenyByDefault {
		t.Fatalf("%s enforced networkPolicy claims deny-by-default enforcement: %#v", label, policy)
	}
	if policy.Enforced.NetworkEnforcement != sandboxworker.NetworkEnforcementNone {
		t.Fatalf("%s enforced networkEnforcement = %q, want %q", label, policy.Enforced.NetworkEnforcement, sandboxworker.NetworkEnforcementNone)
	}
}

func containsSandboxdTestString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
