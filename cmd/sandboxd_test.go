package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
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
		"firecracker-guest-agent-endpoint",
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
		rootlessPodmanAvailable: func(context.Context, string) error {
			return nil
		},
		newRootlessPodmanDriver: func(string) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func() string {
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
	kernelPath := writeSandboxdAssetFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeSandboxdAssetFile(t, "rootfs.ext4", "rootfs-bytes")

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
		"--firecracker-kernel", kernelPath,
		"--firecracker-rootfs", rootfsPath,
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

func TestSandboxdMicroVMDescriptorCanAdvertiseExplicitNetworkEnforcementCapability(t *testing.T) {
	descriptor := sandboxdMicroVMRuntimeDriverDescriptor(sandboxdMicroVMOperationsDefault(), &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               "network-plan-sandboxd",
			Source:           "microvm",
			Operation:        "prepare_network",
			PolicySnapshotID: "policy-snapshot-sandboxd",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"default_deny", "allowlist", "/tmp/raw-rules.sock"},
		},
		Result: &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
			PlanID:          "network-plan-sandboxd",
			AdapterID:       "fake-sandboxd-adapter",
			Outcome:         "success",
			EnforcementMode: "proxy_firewall",
			Mechanisms:      []string{"proxy", "firewall"},
			Operations:      []string{"proxy_route", "firewall_apply"},
			Capability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{"proxy_firewall"},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: "applied",
		},
	})
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("descriptor Validate() error: %v", err)
	}
	if descriptor.NetworkEnforcement == nil || descriptor.NetworkEnforcement.Result == nil {
		t.Fatalf("NetworkEnforcement = %#v, want explicit metadata", descriptor.NetworkEnforcement)
	}
	if descriptor.Security.Requested.NetworkPolicy != sandboxworker.NetworkPolicyDenyByDefault ||
		descriptor.Security.Requested.NetworkEnforcement != sandboxworker.NetworkEnforcementProxyFirewall {
		t.Fatalf("requested security = %#v, want explicit deny/proxy_firewall request", descriptor.Security.Requested)
	}
	if descriptor.Security.Enforced.NetworkPolicy != sandboxworker.NetworkPolicyDenyByDefault ||
		descriptor.Security.Enforced.NetworkEnforcement != sandboxworker.NetworkEnforcementProxyFirewall ||
		descriptor.Security.Enforced.NetworkEnforcementCapability == nil {
		t.Fatalf("enforced security = %#v, want explicit confirmed capability", descriptor.Security.Enforced)
	}
	if containsSandboxdTestString(descriptor.Operations, sandboxworker.OperationExec) ||
		containsSandboxdTestString(descriptor.Operations, sandboxworker.OperationCopyIn) ||
		containsSandboxdTestString(descriptor.Operations, sandboxworker.OperationCopyOut) {
		t.Fatalf("descriptor operations = %#v, want no guest-agent operations from network metadata alone", descriptor.Operations)
	}

	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatalf("Marshal(descriptor) error: %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"/tmp/",
		"raw-rules.sock",
		"token",
		"secret",
		"://",
		"production",
		"egress",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("descriptor leaked or claimed %q in %s", unsafe, publicText)
		}
	}
}

func TestSandboxdMicroVMDescriptorDoesNotClaimDefaultDenyWithoutEnforcingMode(t *testing.T) {
	descriptor := sandboxdMicroVMRuntimeDriverDescriptor(sandboxdMicroVMOperationsDefault(), &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:             "network-plan-sandboxd",
			Source:         "microvm",
			Operation:      "prepare_network",
			PolicyPreset:   "deny_by_default",
			DefaultPosture: "deny_by_default",
			Mechanisms:     []string{"proxy", "firewall"},
		},
		Result: &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
			PlanID:          "network-plan-sandboxd",
			AdapterID:       "fake-sandboxd-adapter",
			Outcome:         "success",
			EnforcementMode: "none",
			Capability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{"proxy_firewall"},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: "applied",
		},
	})
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("descriptor Validate() error: %v", err)
	}
	if descriptor.Security.Requested.NetworkPolicy != sandboxworker.NetworkPolicyDenyByDefault {
		t.Fatalf("requested security = %#v, want deny-by-default request from plan", descriptor.Security.Requested)
	}
	if descriptor.Security.Enforced.NetworkPolicy != sandboxworker.NetworkPolicyBestEffort ||
		descriptor.Security.Enforced.NetworkEnforcement != sandboxworker.NetworkEnforcementNone {
		t.Fatalf("enforced security = %#v, want no deny-by-default claim without an enforcing mode", descriptor.Security.Enforced)
	}
}

func TestSandboxdRuntimeRegistrationRequestsNetworkPlanOnlyForExplicitMicroVMPath(t *testing.T) {
	request := sandboxdNetworkEnforcementPlanRequest()
	var plannerCalls int
	planner := networkenforcement.PlannerFunc(func(got networkenforcement.PlanRequest) networkenforcement.Plan {
		plannerCalls++
		if !reflect.DeepEqual(got, request) {
			t.Fatalf("planner request = %#v, want %#v", got, request)
		}
		return networkenforcement.BuildPlan(got)
	})
	adapter := &recordingSandboxdNetworkEnforcementAdapter{
		result: networkenforcement.Result{
			AdapterID:       "fake-sandboxd-network-adapter",
			Outcome:         networkenforcement.ResultOutcomeSuccess,
			EnforcementMode: networkenforcement.ResultModeProxyFirewall,
			Mechanisms: []networkenforcement.EnforcementMechanism{
				networkenforcement.EnforcementMechanismProxy,
				networkenforcement.EnforcementMechanismFirewall,
			},
			Operations: []string{"proxy_route", "firewall_apply"},
			Capability: &networkenforcement.ResultCapability{
				Supported:                  true,
				Modes:                      []networkenforcement.ResultMode{networkenforcement.ResultModeProxyFirewall},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: networkenforcement.ResultReasonApplied,
		},
	}
	planning := &microvm.NetworkEnforcementPlanning{
		Request: request,
		Planner: planner,
		Adapter: adapter,
	}

	err := runSandboxdWithDeps(context.Background(), sandboxdRequest{
		SocketPath:    "/tmp/rootless-only-network-planning.sock",
		WorkerID:      "worker-rootless-only-network-planning",
		Drivers:       []string{sandboxruntime.DriverRootlessPodman},
		PodmanPath:    "fake-podman",
		MicroVM:       sandboxdMicroVMConfig{NetworkEnforcementPlanning: planning},
		MaxConcurrent: 1,
	}, io.Discard, sandboxdDeps{
		rootlessPodmanAvailable: func(context.Context, string) error {
			return nil
		},
		newRootlessPodmanDriver: func(string) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			if _, exists := options.RuntimeDrivers[sandboxruntime.DriverMicroVM]; exists {
				t.Fatalf("rootless-only service carried microVM runtime descriptor: %#v", options.RuntimeDrivers)
			}
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
	})
	if err != nil {
		t.Fatalf("rootless runSandboxdWithDeps() error = %v", err)
	}
	if plannerCalls != 0 || adapter.calls != 0 {
		t.Fatalf("rootless planner calls=%d adapter calls=%d, want none", plannerCalls, adapter.calls)
	}

	var gotService sandboxworker.ServiceOptions
	err = runSandboxdWithDeps(context.Background(), sandboxdRequest{
		SocketPath:    "/tmp/microvm-network-planning.sock",
		WorkerID:      "worker-microvm-network-planning",
		Drivers:       []string{sandboxruntime.DriverMicroVM},
		MicroVM:       sandboxdNetworkEnforcementMicroVMConfig(t, planning),
		MaxConcurrent: 1,
	}, io.Discard, sandboxdDeps{
		newMicroVMDriver: defaultSandboxdDeps().newMicroVMDriver,
		validateMicroVMConfig: func(config sandboxdMicroVMConfig) error {
			return defaultSandboxdMicroVMConfigValidator(config)
		},
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			gotService = options
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
	})
	if err != nil {
		t.Fatalf("microVM runSandboxdWithDeps() error = %v", err)
	}
	if plannerCalls != 1 || adapter.calls != 1 {
		t.Fatalf("microVM planner calls=%d adapter calls=%d, want one explicit planning pass", plannerCalls, adapter.calls)
	}

	service, err := sandboxworker.NewService(gotService)
	if err != nil {
		t.Fatalf("NewService(gotService) error: %v", err)
	}
	capabilities := service.Capabilities()
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("runtime drivers = %#v, want one explicit microVM descriptor", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != sandboxruntime.DriverMicroVM {
		t.Fatalf("runtime driver ID = %q, want %q", driver.ID, sandboxruntime.DriverMicroVM)
	}
	if driver.NetworkEnforcement == nil || driver.NetworkEnforcement.Plan == nil || driver.NetworkEnforcement.Result == nil {
		t.Fatalf("NetworkEnforcement = %#v, want explicit planner/adapter metadata", driver.NetworkEnforcement)
	}
	if driver.NetworkEnforcement.Result.AdapterID != "fake-sandboxd-network-adapter" ||
		driver.Security.Enforced.NetworkEnforcement != sandboxworker.NetworkEnforcementProxyFirewall {
		t.Fatalf("driver capability = %#v, want explicit proxy/firewall enforcement capability", driver)
	}
}

func TestSandboxdCommandRegistersLiveMicroVMGuestAgentTransportCapabilities(t *testing.T) {
	handler := &recordingSandboxdHandler{}
	var gotService sandboxworker.ServiceOptions
	var gotDriver sandboxruntime.Driver
	kernelPath := writeSandboxdAssetFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeSandboxdAssetFile(t, "rootfs.ext4", "rootfs-bytes")

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

	cmd, _, _ := newTestSandboxdCommand(deps)
	cmd.SetArgs([]string{
		"--socket", "/tmp/live-microvm-guest-agent-sandboxd.sock",
		"--worker-id", "worker-live-microvm",
		"--driver", sandboxruntime.DriverMicroVM,
		"--firecracker-executable", "/usr/bin/firecracker",
		"--firecracker-kernel", kernelPath,
		"--firecracker-rootfs", rootfsPath,
		"--firecracker-state-dir", t.TempDir(),
		"--firecracker-guest-agent-endpoint", "unix:///tmp/hal-guest-agent.sock",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}
	if gotDriver == nil || gotDriver.ID() != sandboxruntime.DriverMicroVM {
		t.Fatalf("registered microVM driver = %#v", gotDriver)
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
	for _, want := range []string{sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut} {
		if !containsSandboxdTestString(capabilities.SupportedOperations, want) {
			t.Fatalf("sandboxd supportedOperations = %#v, want configured guest agent operation %q", capabilities.SupportedOperations, want)
		}
	}
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("sandboxd capabilities runtime drivers = %#v, want one microVM driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != sandboxruntime.DriverMicroVM {
		t.Fatalf("sandboxd capability driver ID = %q, want %q", driver.ID, sandboxruntime.DriverMicroVM)
	}
	for _, want := range []string{sandboxworker.OperationCreate, sandboxworker.OperationStart, sandboxworker.OperationStop, sandboxworker.OperationDelete, sandboxworker.OperationInspect, sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut} {
		if !containsSandboxdTestString(driver.Operations, want) {
			t.Fatalf("sandboxd microVM operations = %#v, want %q", driver.Operations, want)
		}
	}
	assertSandboxdMicroVMCapabilitySecurity(t, driver.Security)
}

func TestSandboxdCommandRejectsInvalidGuestAgentEndpointBeforeMicroVMDriverConstruction(t *testing.T) {
	driverConstructed := false
	serviceCalled := false
	serverCalled := false
	kernelPath := writeSandboxdAssetFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeSandboxdAssetFile(t, "rootfs.ext4", "rootfs-bytes")
	deps := defaultSandboxdDeps()
	deps.newMicroVMDriver = func(config sandboxdMicroVMConfig) (sandboxruntime.Driver, error) {
		driverConstructed = true
		return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverMicroVM}, nil
	}
	deps.newService = func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
		serviceCalled = true
		return &recordingSandboxdHandler{}, nil
	}
	deps.newServer = func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
		serverCalled = true
		return sandboxdServerFunc(func(context.Context) error { return nil }), nil
	}

	cmd, _, _ := newTestSandboxdCommand(deps)
	cmd.SetArgs([]string{
		"--socket", "/tmp/invalid-guest-agent-sandboxd.sock",
		"--worker-id", "worker-live-microvm",
		"--driver", sandboxruntime.DriverMicroVM,
		"--firecracker-executable", "/usr/bin/firecracker",
		"--firecracker-kernel", kernelPath,
		"--firecracker-rootfs", rootfsPath,
		"--firecracker-state-dir", t.TempDir(),
		"--firecracker-guest-agent-endpoint", "tcp://guest.internal:8080/path?token=ghp_secret",
	})

	err := cmd.Execute()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Execute() error = %T, want ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if exitErr.Err == nil || !strings.Contains(exitErr.Err.Error(), "--firecracker-guest-agent-endpoint") {
		t.Fatalf("exit error = %#v, want guest agent endpoint detail", exitErr.Err)
	}
	for _, leaked := range []string{"tcp://", "guest.internal", "8080", "token=ghp_secret", "ghp_secret"} {
		if strings.Contains(exitErr.Err.Error(), leaked) {
			t.Fatalf("exit error leaked %q: %q", leaked, exitErr.Err.Error())
		}
	}
	if driverConstructed || serviceCalled || serverCalled {
		t.Fatalf("driverConstructed=%v serviceCalled=%v serverCalled=%v, want all false", driverConstructed, serviceCalled, serverCalled)
	}
}

func TestSandboxdCommandRegistersMicroVMOnlyWithInjectedFactory(t *testing.T) {
	handler := &recordingSandboxdHandler{}
	var gotService sandboxworker.ServiceOptions
	var gotMicroVM sandboxdMicroVMConfig
	microVMConstructed := false
	rootlessAvailabilityCalled := false
	kernelPath := writeSandboxdAssetFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeSandboxdAssetFile(t, "rootfs.ext4", "rootfs-bytes")
	initrdPath := writeSandboxdAssetFile(t, "initrd.img", "initrd-bytes")

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
		"--firecracker-kernel", " " + kernelPath + " ",
		"--firecracker-rootfs", " " + rootfsPath + " ",
		"--firecracker-initrd", " " + initrdPath + " ",
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
	if gotMicroVM.Config.KernelImagePath != kernelPath {
		t.Fatalf("microVM kernel image = %q", gotMicroVM.Config.KernelImagePath)
	}
	if gotMicroVM.Config.RootfsPath != rootfsPath {
		t.Fatalf("microVM rootfs image = %q", gotMicroVM.Config.RootfsPath)
	}
	if gotMicroVM.Config.InitrdPath != initrdPath {
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

func TestSandboxdCommandResolvesExplicitFirecrackerLaunchAssetsBeforeDriverConstruction(t *testing.T) {
	kernelPath := writeSandboxdAssetFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeSandboxdAssetFile(t, "rootfs.ext4", "rootfs-bytes")
	initrdPath := writeSandboxdAssetFile(t, "initrd.img", "initrd-bytes")

	var gotMicroVM sandboxdMicroVMConfig
	microVMConstructed := false
	cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
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
		"--socket", "/tmp/microvm-resolved-assets.sock",
		"--worker-id", "worker-microvm-assets",
		"--driver", sandboxruntime.DriverMicroVM,
		"--firecracker-executable", " /usr/bin/firecracker ",
		"--firecracker-kernel", " " + kernelPath + " ",
		"--firecracker-rootfs", rootfsPath,
		"--firecracker-initrd", initrdPath,
		"--firecracker-jailer", " /usr/bin/firecracker-jailer ",
		"--firecracker-state-dir", t.TempDir(),
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}
	if !microVMConstructed {
		t.Fatal("microVM driver factory was not called")
	}
	if gotMicroVM.Config.LaunchDescriptor == nil {
		t.Fatal("microVM launch descriptor = nil, want resolver-backed descriptor before driver construction")
	}
	if gotMicroVM.Config.HypervisorPath != "/usr/bin/firecracker" {
		t.Fatalf("firecracker executable = %q", gotMicroVM.Config.HypervisorPath)
	}
	if gotMicroVM.Config.JailerPath != "/usr/bin/firecracker-jailer" {
		t.Fatalf("firecracker jailer = %q", gotMicroVM.Config.JailerPath)
	}
	if gotMicroVM.Config.KernelImagePath != kernelPath || gotMicroVM.Config.RootfsPath != rootfsPath || gotMicroVM.Config.InitrdPath != initrdPath {
		t.Fatalf("legacy path fields = kernel:%q rootfs:%q initrd:%q", gotMicroVM.Config.KernelImagePath, gotMicroVM.Config.RootfsPath, gotMicroVM.Config.InitrdPath)
	}

	descriptor := gotMicroVM.Config.LaunchDescriptor
	if err := assets.ValidateLaunchDescriptor(*descriptor); err != nil {
		t.Fatalf("launch descriptor validation error: %v", err)
	}
	if descriptor.ID != "sandboxd-firecracker-launch" {
		t.Fatalf("descriptor ID = %q, want sandboxd-firecracker-launch", descriptor.ID)
	}
	assertSandboxdResolvedAsset(t, *descriptor, assets.AssetRoleKernel, assets.AssetKindKernelImage, kernelPath, "kernel-bytes")
	assertSandboxdResolvedAsset(t, *descriptor, assets.AssetRoleRootfs, assets.AssetKindRootfsImage, rootfsPath, "rootfs-bytes")
	assertSandboxdResolvedAsset(t, *descriptor, assets.AssetRoleInitrd, assets.AssetKindInitrdImage, initrdPath, "initrd-bytes")
}

func TestSandboxdCommandRejectsUnavailableLaunchAssetBeforeMicroVMDriverConstruction(t *testing.T) {
	rootfsPath := writeSandboxdAssetFile(t, "rootfs.ext4", "rootfs-bytes")
	missingKernelPath := filepath.Join(t.TempDir(), "missing-vmlinux")

	driverConstructed := false
	serviceCalled := false
	serverCalled := false
	cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
		newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
			serviceCalled = true
			return &recordingSandboxdHandler{}, nil
		},
		newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
			serverCalled = true
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
		newMicroVMDriver: func(config sandboxdMicroVMConfig) (sandboxruntime.Driver, error) {
			driverConstructed = true
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverMicroVM}, nil
		},
		workerID: func() string {
			return "unused-default-worker"
		},
	})
	cmd.SetArgs([]string{
		"--socket", "/tmp/microvm-missing-asset.sock",
		"--worker-id", "worker-microvm-assets",
		"--driver", sandboxruntime.DriverMicroVM,
		"--firecracker-executable", "/usr/bin/firecracker",
		"--firecracker-kernel", missingKernelPath,
		"--firecracker-rootfs", rootfsPath,
		"--firecracker-state-dir", t.TempDir(),
	})

	err := cmd.Execute()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Execute() error = %T, want ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if exitErr.Err == nil {
		t.Fatal("exit error detail is nil, want launch asset resolver detail")
	}
	detail := exitErr.Err.Error()
	for _, want := range []string{"--firecracker-kernel", "local asset resolver failed", "file_unavailable"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("exit error = %q, want %q", detail, want)
		}
	}
	for _, leaked := range []string{missingKernelPath, filepath.Base(missingKernelPath), rootfsPath, filepath.Base(rootfsPath)} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("exit error leaked %q: %q", leaked, detail)
		}
	}
	if driverConstructed || serviceCalled || serverCalled {
		t.Fatalf("driverConstructed=%v serviceCalled=%v serverCalled=%v, want all false", driverConstructed, serviceCalled, serverCalled)
	}
}

func TestSandboxdMicroVMValidationRejectsUnsafeLivePaths(t *testing.T) {
	tests := []struct {
		name      string
		flag      string
		value     string
		want      string
		forbidden []string
	}{
		{
			name:      "relative kernel",
			flag:      "--firecracker-kernel",
			value:     "relative/vmlinux",
			want:      "--firecracker-kernel is invalid",
			forbidden: []string{"relative/vmlinux"},
		},
		{
			name:      "control char rootfs",
			flag:      "--firecracker-rootfs",
			value:     "/opt/hal/images/rootfs.ext4\nsecret=raw",
			want:      "--firecracker-rootfs is invalid",
			forbidden: []string{"rootfs.ext4", "secret=raw"},
		},
		{
			name:      "unsafe initrd URL",
			flag:      "--firecracker-initrd",
			value:     "https://example.test/initrd.img?token=ghp_secret",
			want:      "--firecracker-initrd is invalid",
			forbidden: []string{"example.test", "token=ghp_secret", "ghp_secret"},
		},
		{
			name:      "unsafe state dir query",
			flag:      "--firecracker-state-dir",
			value:     "/tmp/hal-firecracker?token=ghp_secret",
			want:      "--firecracker-state-dir is invalid",
			forbidden: []string{"token=ghp_secret", "ghp_secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceCalled := false
			serverCalled := false
			kernelPath := writeSandboxdAssetFile(t, "vmlinux", "kernel-bytes")
			rootfsPath := writeSandboxdAssetFile(t, "rootfs.ext4", "rootfs-bytes")
			args := []string{
				"--socket", "/tmp/microvm-invalid-path.sock",
				"--worker-id", "worker-microvm",
				"--driver", sandboxruntime.DriverMicroVM,
				"--firecracker-executable", "/usr/bin/firecracker",
				"--firecracker-kernel", kernelPath,
				"--firecracker-rootfs", rootfsPath,
				"--firecracker-state-dir", "/tmp/hal-firecracker-state",
			}
			for i := 0; i < len(args)-1; i++ {
				if args[i] == tt.flag {
					args[i+1] = tt.value
				}
			}
			if tt.flag == "--firecracker-initrd" {
				args = append(args, tt.flag, tt.value)
			}

			cmd, _, _ := newTestSandboxdCommand(sandboxdDeps{
				newService: func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
					serviceCalled = true
					return &recordingSandboxdHandler{}, nil
				},
				newServer: func(options sandboxworker.ServerOptions) (sandboxdServer, error) {
					serverCalled = true
					return sandboxdServerFunc(func(context.Context) error { return nil }), nil
				},
				newMicroVMDriver: func(config sandboxdMicroVMConfig) (sandboxruntime.Driver, error) {
					return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverMicroVM}, nil
				},
				workerID: func() string {
					return "worker-test"
				},
			})
			cmd.SetArgs(args)

			err := cmd.Execute()
			var exitErr *ExitCodeError
			if !errors.As(err, &exitErr) {
				t.Fatalf("Execute() error = %T, want ExitCodeError", err)
			}
			if exitErr.Code != ExitCodeValidation {
				t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
			}
			if exitErr.Err == nil || !strings.Contains(exitErr.Err.Error(), tt.want) {
				t.Fatalf("exit error = %#v, want %q", exitErr.Err, tt.want)
			}
			for _, leaked := range tt.forbidden {
				if strings.Contains(exitErr.Err.Error(), leaked) {
					t.Fatalf("exit error leaked %q: %q", leaked, exitErr.Err.Error())
				}
			}
			if serviceCalled || serverCalled {
				t.Fatalf("serviceCalled=%v serverCalled=%v, want neither called", serviceCalled, serverCalled)
			}
		})
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
		"--firecracker-guest-agent-endpoint", "tcp://guest.internal:8080/path?token=ghp_secret",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error = %v, want nil because microVM validation is gated by --driver microvm", err)
	}
	if got := strings.Join(gotService.Registry.DriverIDs(), ","); got != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("service registry driver IDs = %q, want %q", got, sandboxruntime.DriverRootlessPodman)
	}
	service, err := sandboxworker.NewService(gotService)
	if err != nil {
		t.Fatalf("NewService(gotService) error: %v", err)
	}
	capabilities := service.Capabilities()
	if len(capabilities.RuntimeDrivers) != 1 {
		t.Fatalf("rootless capabilities runtime drivers = %#v, want one rootless driver", capabilities.RuntimeDrivers)
	}
	driver := capabilities.RuntimeDrivers[0]
	if driver.ID != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("rootless capability driver ID = %q, want %q", driver.ID, sandboxruntime.DriverRootlessPodman)
	}
	for _, want := range []string{sandboxworker.OperationExec, sandboxworker.OperationCopyIn, sandboxworker.OperationCopyOut} {
		if !containsSandboxdTestString(driver.Operations, want) {
			t.Fatalf("rootless Podman operations = %#v, want unchanged %q operation", driver.Operations, want)
		}
	}
	if _, exists := gotService.RuntimeDrivers[sandboxruntime.DriverMicroVM]; exists {
		t.Fatalf("rootless-only service carried microVM runtime descriptor: %#v", gotService.RuntimeDrivers)
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

type recordingSandboxdNetworkEnforcementAdapter struct {
	calls  int
	plan   networkenforcement.Plan
	result networkenforcement.Result
}

func (adapter *recordingSandboxdNetworkEnforcementAdapter) EnforceNetwork(_ context.Context, plan networkenforcement.SanitizedPlan) networkenforcement.Result {
	adapter.calls++
	adapter.plan = plan.Plan()
	result := adapter.result
	if result.PlanID == "" {
		result.PlanID = adapter.plan.ID
	}
	if result.PolicySnapshot == nil {
		result.PolicySnapshot = adapter.plan.PolicySnapshot
	}
	return result
}

func sandboxdNetworkEnforcementPlanRequest() networkenforcement.PlanRequest {
	return networkenforcement.PlanRequest{
		ID:        "network-plan-sandboxd-runtime",
		Source:    networkenforcement.PlanSourceMicroVM,
		Operation: "prepare_network",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{
			ID:        "policy-snapshot-sandboxd-runtime",
			Preset:    networkenforcement.PolicyPresetDenyByDefault,
			RuleSetID: "rules-sandboxd-runtime",
		},
		RequestedPolicy: networkenforcement.RequestedNetworkPosture{
			Preset:            networkenforcement.PolicyPresetDenyByDefault,
			RuleSetID:         "rules-sandboxd-runtime",
			RuleIDs:           []string{"rule-sandboxd-runtime"},
			PrivateNetwork:    networkenforcement.PostureBlock,
			MetadataEndpoint:  networkenforcement.PostureBlock,
			HTTP:              networkenforcement.ProxyRoutingModeRouteViaProxy,
			HTTPS:             networkenforcement.ProxyRoutingModeBlock,
			ProxyMechanism:    networkenforcement.EnforcementMechanismProxy,
			FirewallMode:      networkenforcement.FirewallIntentModeApply,
			FirewallMechanism: networkenforcement.EnforcementMechanismFirewall,
		},
	}
}

func sandboxdNetworkEnforcementMicroVMConfig(t *testing.T, planning *microvm.NetworkEnforcementPlanning) sandboxdMicroVMConfig {
	t.Helper()

	defaults := microvm.DefaultConfig()
	return sandboxdMicroVMConfig{
		Config: microvm.Config{
			HypervisorPath:  "/usr/bin/firecracker",
			KernelImagePath: "/opt/hal/images/vmlinux",
			RootfsPath:      "/opt/hal/images/rootfs.ext4",
			CPUCount:        defaults.CPUCount,
			MemoryMiB:       defaults.MemoryMiB,
			DiskSizeMiB:     defaults.DiskSizeMiB,
			GuestWorkDir:    defaults.GuestWorkDir,
			NetworkMode:     defaults.NetworkMode,
		},
		StateDir:                   filepath.Join(t.TempDir(), "firecracker-state"),
		NetworkEnforcementPlanning: planning,
	}
}

func writeSandboxdAssetFile(t *testing.T, name string, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write sandboxd asset %q: %v", name, err)
	}
	return path
}

func assertSandboxdResolvedAsset(t *testing.T, descriptor assets.LaunchDescriptor, role assets.AssetRole, kind assets.AssetKind, path string, contents string) {
	t.Helper()

	for _, asset := range descriptor.Assets {
		if asset.Role != role {
			continue
		}
		if asset.Kind != kind {
			t.Fatalf("%s kind = %q, want %q", role, asset.Kind, kind)
		}
		if asset.Source.Type != assets.SourceTypeLocalFile {
			t.Fatalf("%s source type = %q, want local_file", role, asset.Source.Type)
		}
		if asset.Source.HostPath == nil {
			t.Fatalf("%s host path = nil, want resolved path", role)
		}
		if asset.Source.HostPath.Path != path {
			t.Fatalf("%s host path = %q, want %q", role, asset.Source.HostPath.Path, path)
		}
		if asset.Source.HostPath.Role != assets.HostPathRoleResolvedLocalAsset {
			t.Fatalf("%s host path role = %q, want %q", role, asset.Source.HostPath.Role, assets.HostPathRoleResolvedLocalAsset)
		}
		if asset.Lock.Digest.Algorithm != assets.DigestAlgorithmSHA256 {
			t.Fatalf("%s digest algorithm = %q, want sha256", role, asset.Lock.Digest.Algorithm)
		}
		if asset.Lock.Digest.Value != sandboxdSHA256Hex(contents) {
			t.Fatalf("%s digest = %q, want %q", role, asset.Lock.Digest.Value, sandboxdSHA256Hex(contents))
		}
		if asset.Lock.SizeBytes != int64(len(contents)) {
			t.Fatalf("%s size = %d, want %d", role, asset.Lock.SizeBytes, len(contents))
		}
		if asset.Lock.LockedAtUnixMillis <= 0 {
			t.Fatalf("%s lockedAt = %d, want positive resolver timestamp", role, asset.Lock.LockedAtUnixMillis)
		}
		return
	}
	t.Fatalf("descriptor missing %s asset: %#v", role, descriptor.Assets)
}

func sandboxdSHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
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
