package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
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
		"firecracker-executable",
		"firecracker-kernel",
		"firecracker-rootfs",
		"firecracker-initrd",
		"firecracker-jailer",
		"firecracker-state-dir",
		"microvm-cpu-count",
		"microvm-memory-mib",
		"microvm-disk-mib",
		"microvm-guest-workdir",
		"firecracker-boot-timeout",
		"firecracker-boot-poll-interval",
		"max-concurrent",
		"json",
	} {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Fatalf("sandboxd missing --%s flag", flagName)
		}
	}
	for _, flagName := range []string{"firecracker-guest-readiness-timeout", "firecracker-guest-readiness-poll-interval"} {
		if cmd.Flags().Lookup(flagName) != nil {
			t.Fatalf("sandboxd registered --%s by default without a configured readiness probe", flagName)
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
	if exitErr.Err == nil {
		t.Fatal("exit error detail is nil, want missing Firecracker input detail")
	}
	detail := exitErr.Err.Error()
	for _, want := range []string{"--firecracker-executable", "--firecracker-kernel", "--firecracker-rootfs", "--firecracker-state-dir"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("exit error = %q, want missing %s detail", detail, want)
		}
	}
	if strings.Contains(detail, `driver "microvm" is unsupported`) {
		t.Fatalf("exit error = %q, want missing Firecracker inputs before unsupported driver detail", detail)
	}
	if serviceCalled || serverCalled {
		t.Fatalf("serviceCalled=%v serverCalled=%v, want neither called", serviceCalled, serverCalled)
	}
}

func TestSandboxdDefaultsDoNotRegisterMicroVMFactory(t *testing.T) {
	flags := defaultSandboxdFlags()
	if got := strings.Join(flags.drivers, ","); got != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("default sandboxd drivers = %q, want only %q", got, sandboxruntime.DriverRootlessPodman)
	}

	deps := defaultSandboxdDeps()
	if deps.newMicroVMDriver == nil {
		t.Fatal("default sandboxd newMicroVMDriver is nil, want explicit microVM constructor available for --driver microvm")
	}
	if !sandboxdDriverSupportedByDeps(sandboxruntime.DriverMicroVM, deps) {
		t.Fatal("sandboxd reports microVM unsupported by default deps, want support gated by explicit --driver microvm inputs")
	}
}

func TestSandboxdCommandRegistersLiveMicroVMDriverWithExplicitInputs(t *testing.T) {
	handler := &recordingSandboxdHandler{}
	var gotService sandboxworker.ServiceOptions
	var gotDriver sandboxruntime.Driver

	deps := defaultSandboxdDeps()
	deps.newService = func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
		gotService = options
		driver, err := options.Registry.Lookup(sandboxruntime.DriverMicroVM)
		if err != nil {
			return nil, err
		}
		gotDriver = driver
		return handler, nil
	}
	deps.newServer = func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
		return sandboxdServerFunc(func(context.Context) error { return nil }), nil
	}

	cmd, stdout, _ := newTestSandboxdCommand(deps)
	cmd.SetArgs([]string{
		"--socket", "/tmp/live-microvm-sandboxd.sock",
		"--worker-id", "worker-live-microvm",
		"--driver", sandboxruntime.DriverMicroVM,
		"--firecracker-executable", "/usr/bin/firecracker",
		"--firecracker-kernel", "/opt/hal/images/vmlinux",
		"--firecracker-rootfs", "/opt/hal/images/rootfs.ext4",
		"--firecracker-state-dir", t.TempDir(),
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}
	if gotService.Registry == nil {
		t.Fatal("service registry is nil")
	}
	if gotDriver == nil {
		t.Fatal("microVM driver was not registered")
	}
	if gotDriver.ID() != sandboxruntime.DriverMicroVM {
		t.Fatalf("registered driver ID = %q, want %q", gotDriver.ID(), sandboxruntime.DriverMicroVM)
	}
	microVMDriver, ok := gotDriver.(*microvm.Driver)
	if !ok {
		t.Fatalf("registered microVM driver = %T, want *microvm.Driver", gotDriver)
	}
	if !microVMDriver.Metadata().BackendConfigured {
		t.Fatal("registered microVM driver BackendConfigured = false, want live Firecracker backend configured")
	}
	service, err := sandboxworker.NewService(gotService)
	if err != nil {
		t.Fatalf("NewService(gotService) error: %v", err)
	}
	capabilities := service.Capabilities()
	for _, unsupported := range []string{sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut} {
		if containsSandboxdTestString(capabilities.SupportedOperations, unsupported) {
			t.Fatalf("sandboxd microVM supportedOperations claim unsupported %q operation: %#v", unsupported, capabilities.SupportedOperations)
		}
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("sandboxd capabilities runtime drivers = %#v, want one microVM driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != sandboxruntime.DriverMicroVM {
		t.Fatalf("sandboxd capability driver ID = %q, want %q", driver.ID, sandboxruntime.DriverMicroVM)
	}
	if driver.IsolationLevel != sandboxworker.IsolationLevelVM {
		t.Fatalf("sandboxd microVM isolationLevel = %q, want %q", driver.IsolationLevel, sandboxworker.IsolationLevelVM)
	}
	for _, unsupported := range []string{sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut, "template", "kit"} {
		if containsSandboxdTestString(driver.Operations, unsupported) {
			t.Fatalf("sandboxd microVM capabilities claim unsupported %q operation: %#v", unsupported, driver.Operations)
		}
	}
	assertSandboxdMicroVMCapabilitySecurity(t, driver.Security)

	var started sandboxdStartedOutput
	if err := json.Unmarshal(stdout.Bytes(), &started); err != nil {
		t.Fatalf("startup JSON = %q, unmarshal error: %v", stdout.String(), err)
	}
	if got := strings.Join(started.Drivers, ","); got != sandboxruntime.DriverMicroVM {
		t.Fatalf("startup drivers = %q, want %q", got, sandboxruntime.DriverMicroVM)
	}
}

func TestSandboxdCommandRegistersMicroVMOnlyWithInjectedFactory(t *testing.T) {
	handler := &recordingSandboxdHandler{}
	var gotService sandboxworker.ServiceOptions
	var gotMicroVM sandboxdMicroVMConfig
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
		newMicroVMDriver: func(config sandboxdMicroVMConfig) (sandboxruntime.Driver, error) {
			microVMConstructed = true
			gotMicroVM = config
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverMicroVM}, nil
		},
		workerID: func() string {
			return "unused-default-worker"
		},
	})
	cmd.SetArgs([]string{
		"--socket", "/tmp/microvm-sandboxd.sock",
		"--worker-id", "worker-microvm",
		"--driver", sandboxruntime.DriverMicroVM,
		"--firecracker-executable", " /usr/bin/firecracker ",
		"--firecracker-kernel", " /opt/hal/images/vmlinux ",
		"--firecracker-rootfs", " /opt/hal/images/rootfs.ext4 ",
		"--firecracker-initrd", " /opt/hal/images/initrd.img ",
		"--firecracker-jailer", " /usr/bin/firecracker-jailer ",
		"--firecracker-state-dir", " /tmp/hal-firecracker-state ",
		"--microvm-cpu-count", "4",
		"--microvm-memory-mib", "4096",
		"--microvm-disk-mib", "20480",
		"--microvm-guest-workdir", " /workspace/project ",
		"--firecracker-boot-timeout", "15s",
		"--firecracker-boot-poll-interval", "250ms",
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
	if gotMicroVM.Config.HypervisorPath != "/usr/bin/firecracker" {
		t.Fatalf("microVM firecracker executable = %q", gotMicroVM.Config.HypervisorPath)
	}
	if gotMicroVM.Config.KernelImagePath != "/opt/hal/images/vmlinux" {
		t.Fatalf("microVM kernel image = %q", gotMicroVM.Config.KernelImagePath)
	}
	if gotMicroVM.Config.RootfsPath != "/opt/hal/images/rootfs.ext4" {
		t.Fatalf("microVM rootfs image = %q", gotMicroVM.Config.RootfsPath)
	}
	if gotMicroVM.Config.InitrdPath != "/opt/hal/images/initrd.img" {
		t.Fatalf("microVM initrd image = %q", gotMicroVM.Config.InitrdPath)
	}
	if gotMicroVM.Config.JailerPath != "/usr/bin/firecracker-jailer" {
		t.Fatalf("microVM jailer path = %q", gotMicroVM.Config.JailerPath)
	}
	if gotMicroVM.StateDir != "/tmp/hal-firecracker-state" {
		t.Fatalf("microVM state dir = %q", gotMicroVM.StateDir)
	}
	if gotMicroVM.Config.CPUCount != 4 || gotMicroVM.Config.MemoryMiB != 4096 || gotMicroVM.Config.DiskSizeMiB != 20480 {
		t.Fatalf("microVM sizing = cpu:%d memory:%d disk:%d", gotMicroVM.Config.CPUCount, gotMicroVM.Config.MemoryMiB, gotMicroVM.Config.DiskSizeMiB)
	}
	if gotMicroVM.Config.GuestWorkDir != "/workspace/project" {
		t.Fatalf("microVM guest workdir = %q", gotMicroVM.Config.GuestWorkDir)
	}
	if gotMicroVM.BootAcceptanceTimeout != 15*time.Second {
		t.Fatalf("microVM boot timeout = %s", gotMicroVM.BootAcceptanceTimeout)
	}
	if gotMicroVM.BootAcceptancePollInterval != 250*time.Millisecond {
		t.Fatalf("microVM boot poll interval = %s", gotMicroVM.BootAcceptancePollInterval)
	}
	if gotMicroVM.GuestReadinessProbeConfigured {
		t.Fatal("guest readiness probe configured by default, want false")
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

func TestSandboxdMicroVMValidationDoesNotRunForRootlessPodmanOnly(t *testing.T) {
	var gotService sandboxworker.ServiceOptions
	cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
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
			return "worker-test"
		},
	})
	cmd.SetArgs([]string{
		"--driver", sandboxruntime.DriverRootlessPodman,
		"--microvm-cpu-count", "-1",
		"--firecracker-boot-timeout", "-1s",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error = %v, want nil because microVM validation is gated by --driver microvm", err)
	}
	if got := strings.Join(gotService.Registry.DriverIDs(), ","); got != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("service registry driver IDs = %q, want %q", got, sandboxruntime.DriverRootlessPodman)
	}
}

func TestSandboxdGuestReadinessFlagsRequireConfiguredProbe(t *testing.T) {
	defaultCmd, _, _ := newTestSandboxdCommand(sandboxdDeps{})
	for _, flagName := range []string{"firecracker-guest-readiness-timeout", "firecracker-guest-readiness-poll-interval"} {
		if defaultCmd.Flags().Lookup(flagName) != nil {
			t.Fatalf("default sandboxd command registered --%s without a configured readiness probe", flagName)
		}
	}

	configuredCmd, _, _ := newTestSandboxdCommand(sandboxdDeps{microVMGuestReadinessConfigured: true})
	for _, flagName := range []string{"firecracker-guest-readiness-timeout", "firecracker-guest-readiness-poll-interval"} {
		if configuredCmd.Flags().Lookup(flagName) == nil {
			t.Fatalf("sandboxd command with configured readiness probe missing --%s", flagName)
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

func assertSandboxdMicroVMCapabilitySecurity(t *testing.T, policy sandboxworker.SecurityPolicy) {
	t.Helper()
	if err := policy.Validate(); err != nil {
		t.Fatalf("microVM security policy Validate() error: %v", err)
	}
	if policy.Requested.NetworkPolicy != sandboxworker.NetworkPolicyBestEffort ||
		policy.Requested.NetworkEnforcement != sandboxworker.NetworkEnforcementNone ||
		policy.Enforced.NetworkPolicy != sandboxworker.NetworkPolicyBestEffort ||
		policy.Enforced.NetworkEnforcement != sandboxworker.NetworkEnforcementNone {
		t.Fatalf("microVM network policy overclaims secure defaults: %#v", policy)
	}
	if policy.Requested.CredentialProxyMode || policy.Enforced.CredentialProxyMode ||
		len(policy.Requested.CredentialModes) != 0 || len(policy.Enforced.CredentialModes) != 0 {
		t.Fatalf("microVM credential policy overclaims support: %#v", policy)
	}
	if policy.Requested.IsolationLevel != sandboxworker.IsolationLevelVM ||
		policy.Enforced.IsolationLevel != sandboxworker.IsolationLevelVM {
		t.Fatalf("microVM isolation policy = %#v, want VM isolation", policy)
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
