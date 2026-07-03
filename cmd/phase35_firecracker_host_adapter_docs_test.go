package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase35FirecrackerHostAdapterVerificationDocs(t *testing.T) {
	doc := readPhase35FirecrackerHostAdapterDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 35 adds an injection-ready Firecracker host adapter package for the Phase 34 live boot boundaries.",
		"`internal/sandboxruntime/microvm/firecrackerhost`",
		"`internal/sandboxruntime/microvm/firecracker`",
		"Phase 34 owns the backend live boot contract and keeps live boot behind explicit `BackendOptions.LiveStart` plus injected `ProcessAdapter`, `BootAcceptanceWaiter`, and `LiveProcessManager` dependencies.",
		"Phase 35 provides host-side implementations that can satisfy those injected interfaces, but it does not register, select, or pass them to backend options from default Hal execution paths.",
		"`firecrackerhost.NewAdapter` builds an inert adapter unless dependencies are explicitly provided with options such as `WithProcessRunner`, `WithBootAcceptancePoller`, and `WithLiveProcessCleanup`.",
		"`firecrackerhost.NewProcessLifecycleManager` owns fake-safe host process handle lifecycle and state cleanup through injected boundaries.",
		"`firecrackerhost.NewOSExecProcessRunner` is the only production `os/exec` boundary for starting a Firecracker host process.",
		"The adapter is not wired into default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`, or worker execution paths.",
		"Phase 35 guard tests keep those default paths from importing `firecrackerhost`, constructing `NewAdapter`, constructing `NewProcessLifecycleManager`, constructing `NewOSExecProcessRunner`, selecting `firecrackerhost` by literal, or injecting host adapter dependencies into Phase 34 backend live boot options.",
		"go test -timeout=120s ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase34|TestPhase35'",
		"go test ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` should run only when `golangci-lint` is installed.",
		"If `golangci-lint` is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Phase 35 does not implement default Firecracker registration, default host adapter selection, default backend option injection, guest exec, guest copy, Docker/Podman guest engines, guest readiness checks, guest health checks, guest agent or vsock transport, SSH access, workspace synchronization, credential delivery, network proxy/firewall enforcement, Firecracker SDK integration, API socket machine configuration calls, jailer/root setup, cgroups, default live E2E tests, or command/factory/sandboxd enablement.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 35 Firecracker host adapter verification documentation missing %q", want)
		}
	}

	phase35AssertBroadVerificationCommands(t, doc)
	phase35AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"default Firecracker registration is implemented",
		"default host adapter selection is implemented",
		"default backend option injection is implemented",
		"guest exec is implemented",
		"guest copy is implemented",
		"Docker/Podman guest engines are implemented",
		"guest readiness checks are implemented",
		"guest health checks are implemented",
		"guest agent transport is implemented",
		"vsock transport is implemented",
		"SSH access is implemented",
		"workspace synchronization is implemented",
		"credential delivery is implemented",
		"network proxy/firewall enforcement is implemented",
		"Firecracker SDK integration is implemented",
		"API socket machine configuration calls are implemented",
		"jailer/root setup is implemented",
		"cgroups are implemented",
		"default live E2E tests are implemented",
		"default commands construct firecrackerhost",
		"default workers construct firecrackerhost",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 35 Firecracker host adapter verification documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase35FirecrackerHostAdapterFakeSafeVerification(t *testing.T) {
	doc := readPhase35FirecrackerHostAdapterDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 35 verification is fake-safe and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, provider/runtime integration, host-specific kernel or rootfs images, or a live guest.",
		"Default Phase 35 tests must use pure contracts, injected fake process runners, injected fake boot acceptance pollers, injected fake live process cleanup, fake filesystems, fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, temporary stores, and temporary state directories only.",
		"Default Phase 35 verification must not use integration build tags, the `firecracker_live` build tag, require live environment variables, start a real Firecracker process, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase34|TestPhase35'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 35 Firecracker host adapter fake-safe documentation missing %q", want)
		}
	}

	commands := phase35DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 35 Firecracker host adapter verification documentation must list default focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase34ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 35 default focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase35AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase35AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func TestPhase35FirecrackerHostAdapterOptionalLiveVerificationDocs(t *testing.T) {
	doc := readPhase35FirecrackerHostAdapterDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 35 includes optional live integration coverage behind the `firecracker_live` build tag.",
		"It is not part of default verification.",
		"When live prerequisites are unavailable, these tagged tests should skip with redacted messages instead of failing default verification.",
		"go test -tags firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"Linux host with `/dev/kvm` present and read/write accessible to the test process for backend live boot coverage.",
		"`HAL_FIRECRACKER_LIVE_FIRECRACKER`: executable regular file for the Firecracker binary.",
		"`HAL_FIRECRACKER_LIVE_KERNEL`: readable regular file for the kernel image.",
		"`HAL_FIRECRACKER_LIVE_ROOTFS`: read/write regular file for the rootfs image.",
		"`HAL_FIRECRACKER_LIVE_INITRD`: optional readable regular file for an initrd image.",
		"`HAL_FIRECRACKER_LIVE_TIMEOUT`: optional positive Go duration for host-side API socket acceptance, defaulting to `10s`.",
		"`HAL_FIRECRACKER_LIVE_CPU_COUNT`: optional integer greater than or equal to `1`, defaulting to `1`.",
		"`HAL_FIRECRACKER_LIVE_MEMORY_MIB`: optional integer greater than or equal to `1`, defaulting to `256`.",
		"`HAL_FIRECRACKER_LIVE=1`: explicit opt-in for the host adapter live-runner test.",
		"The optional live command starts real Firecracker processes only inside tagged tests.",
		"It does not wire the host adapter into default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`, worker, scheduler, or sandboxd paths.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 35 Firecracker host adapter optional live documentation missing %q", want)
		}
	}

	phase35AssertLiveVerificationCommand(t, doc)
	phase35AssertLiveIntegrationFilesMatchDocumentation(t)
}

func readPhase35FirecrackerHostAdapterDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase35-firecracker-host-adapter-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 35 Firecracker host adapter verification doc) error: %v", err)
	}
	return string(data)
}

func phase35DefaultFocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "firecracker_live") {
			continue
		}
		if strings.Contains(command, "./...") || strings.Contains(command, "-run '^$'") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase35AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 35 Firecracker host adapter verification documentation missing broad verification command line %q", want)
		}
	}
}

func phase35AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase35DefaultFocusedGoTestCommands(doc)
	for _, req := range phase35RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 35 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 35 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase35RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "adapter_test.go"), testName: "TestNewAdapterAppliesDependencyOptions"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "adapter_test.go"), testName: "TestAdapterWithoutDependenciesReturnsConfiguredSentinelError"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "boot_acceptance_test.go"), testName: "TestAdapterPollsBootAcceptanceUntilAPISocketReady"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "boot_acceptance_test.go"), testName: "TestAdapterBootAcceptancePollingErrorsAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "process_lifecycle_test.go"), testName: "TestProcessLifecycleManagerStartsFakeProcessWithOpaqueHandle"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "process_lifecycle_test.go"), testName: "TestProcessLifecycleManagerCleanupRemovesOnlyValidatedFirecrackerStateDir"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "process_lifecycle_test.go"), testName: "TestProcessLifecycleManagerCleanupFilesystemErrorsAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_boundary_test.go"), testName: "TestOSExecImportIsConfinedToRealProcessRunner"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_boundary_test.go"), testName: "TestFirecrackerOSExecLaunchIsConfinedToHostAdapterPackage"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_boundary_test.go"), testName: "TestFirecrackerHostLiveTestStaysOptIn"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_live_boot_contract_test.go"), testName: "TestPhase34DefaultBackendOptionsKeepLiveBootPlanningOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_live_boot_contract_test.go"), testName: "TestPhase34LiveBootRequiresCompleteOptionsBeforeProcessStart"},
		{pkg: "./cmd", file: "phase34_firecracker_default_guard_test.go", testName: "TestPhase34DefaultPathsDoNotWireFirecrackerLiveBoot"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_default_guard_test.go", testName: "TestPhase35DefaultCLIPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_default_guard_test.go", testName: "TestPhase35FactoryPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_default_guard_test.go", testName: "TestPhase35SandboxexecPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_default_guard_test.go", testName: "TestPhase35WorkerPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_default_guard_test.go", testName: "TestPhase35DefaultHostAdapterGuardCoversRequiredSurfaces"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_default_guard_test.go", testName: "TestPhase35DefaultHostAdapterGuardRejectsHostAdapterFixtures"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_docs_test.go", testName: "TestPhase35FirecrackerHostAdapterVerificationDocs"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_docs_test.go", testName: "TestPhase35FirecrackerHostAdapterFakeSafeVerification"},
		{pkg: "./cmd", file: "phase35_firecracker_host_adapter_docs_test.go", testName: "TestPhase35FirecrackerHostAdapterOptionalLiveVerificationDocs"},
	}
}

func phase35AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "adapter_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "boot_acceptance_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "process_lifecycle_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_test.go"),
		"phase35_firecracker_host_adapter_default_guard_test.go",
		"phase35_firecracker_host_adapter_docs_test.go",
	} {
		phase34AssertNoLiveIntegrationBuildTag(t, file)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}

func phase35AssertLiveVerificationCommand(t *testing.T, doc string) {
	t.Helper()
	var liveCommands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "firecracker_live") {
			liveCommands = append(liveCommands, command)
		}
	}
	if len(liveCommands) != 1 {
		t.Fatalf("phase 35 verification documentation live command count = %d, want 1: %#v", len(liveCommands), liveCommands)
	}
	command := liveCommands[0]
	want := "go test -tags firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost"
	if command != want {
		t.Fatalf("phase 35 live verification command = %q, want %q", command, want)
	}
	for _, req := range []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLiveBootWithRealProcess"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_live_test.go"), testName: "TestOSExecProcessRunnerLiveStartsFirecrackerAPISocket"},
	} {
		covered := phase34FocusedCommandCoveringTest(t, []string{command}, req.pkg, req.testName)
		if covered == "" {
			t.Fatalf("phase 35 live verification command does not cover %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 35 live test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase35AssertLiveIntegrationFilesMatchDocumentation(t *testing.T) {
	t.Helper()

	backendLivePath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go")
	backendLiveSource := phase35ReadFile(t, backendLivePath)
	for _, marker := range []string{
		"//go:build firecracker_live",
		"HAL_FIRECRACKER_LIVE_FIRECRACKER",
		"HAL_FIRECRACKER_LIVE_KERNEL",
		"HAL_FIRECRACKER_LIVE_ROOTFS",
		"HAL_FIRECRACKER_LIVE_INITRD",
		"HAL_FIRECRACKER_LIVE_TIMEOUT",
		"HAL_FIRECRACKER_LIVE_CPU_COUNT",
		"HAL_FIRECRACKER_LIVE_MEMORY_MIB",
		"/dev/kvm",
		"t.Skip",
	} {
		if !strings.Contains(backendLiveSource, marker) {
			t.Fatalf("%s missing documented live behavior marker %q", phase34FirecrackerDisplayPath(t, backendLivePath), marker)
		}
	}

	hostLivePath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_live_test.go")
	hostLiveSource := phase35ReadFile(t, hostLivePath)
	for _, marker := range []string{
		"//go:build firecracker_live",
		"HAL_FIRECRACKER_LIVE",
		"HAL_FIRECRACKER_LIVE_FIRECRACKER",
		"NewOSExecProcessRunner",
		"t.Skip",
	} {
		if !strings.Contains(hostLiveSource, marker) {
			t.Fatalf("%s missing documented live behavior marker %q", phase34FirecrackerDisplayPath(t, hostLivePath), marker)
		}
	}
}

func phase35ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
