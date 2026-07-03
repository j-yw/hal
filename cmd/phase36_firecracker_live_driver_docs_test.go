package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase36FirecrackerExplicitLiveDriverVerificationDocs(t *testing.T) {
	doc := readPhase36FirecrackerLiveDriverDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 36 exposes the live Firecracker driver only as an explicit construction API for future worker or runtime configuration.",
		"`internal/sandboxruntime/microvm/firecrackerhost`",
		"`firecrackerhost.LiveDriverOptions`, `firecrackerhost.NewLiveDriver`, and `firecrackerhost.NewLiveBackendOptions` are the only Phase 36 live-driver entry points.",
		"`BackendOptions.LiveStart: true`",
		"`firecracker.ProcessLaunchAdapter{Starter: adapter}`",
		"This API is for future worker or runtime configuration that explicitly chooses Firecracker live start.",
		"It is not a registration hook, command default, worker routing default, scheduler default, or sandbox daemon default.",
		"Default command, factory, sandboxexec, worker, scheduler, sandboxd, and backend-neutral microVM paths must not import `firecrackerhost`, construct `LiveDriverOptions`, call `NewLiveDriver`, call `NewLiveBackendOptions`, or select the explicit live driver by literal.",
		"This is a host API socket acceptance signal only.",
		"Default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`, worker routing, scheduler selection, and `hal sandboxd` do not enable live Firecracker.",
		"Default `firecracker.NewBackend(BackendOptions{})`, backends without `LiveStart: true`, and backends with injected adapters but without `LiveStart: true` must continue to render plans without launching a Firecracker process.",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase3[456].*Firecracker|MicroVM'",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` should run only when `golangci-lint` is installed.",
		"If `golangci-lint` is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Guest exec, guest copy in or out, guest readiness beyond host API socket acceptance, Firecracker SDK dependency, machine configuration API calls, image/rootfs/kernel provisioning, network proxy, credential broker, templates/kits, Docker/Podman guest engines, deny-by-default networking, and brokered secrets are non-goals.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 36 Firecracker explicit live driver verification documentation missing %q", want)
		}
	}

	phase36AssertBroadVerificationCommands(t, doc)
	phase36AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"default `hal run` enables live Firecracker",
		"default `hal auto` enables live Firecracker",
		"default `hal factory run` enables live Firecracker",
		"sandboxexec enables live Firecracker by default",
		"worker routing enables live Firecracker by default",
		"scheduler selection enables live Firecracker by default",
		"`hal sandboxd` enables live Firecracker by default",
		"guest exec is implemented",
		"guest copy in is implemented",
		"guest copy out is implemented",
		"guest readiness beyond host API socket acceptance is implemented",
		"Firecracker SDK dependency is required",
		"machine configuration API calls are implemented",
		"image/rootfs/kernel provisioning is implemented",
		"network proxy is implemented",
		"credential broker is implemented",
		"templates/kits are implemented",
		"Docker/Podman guest engines are implemented",
		"deny-by-default networking is implemented",
		"brokered secrets are implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 36 Firecracker explicit live driver documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase36FirecrackerExplicitLiveDriverFakeSafeVerification(t *testing.T) {
	doc := readPhase36FirecrackerLiveDriverDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 36 verification is fake-safe and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, provider/runtime integration, host-specific kernel or rootfs images, or a live guest.",
		"Default Phase 36 tests use pure contracts, injected fake host process runners, injected fake boot acceptance pollers, injected fake cleanup filesystems, fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, temporary stores, and temporary state directories only.",
		"Default Phase 36 verification must not use integration build tags, the `firecracker_live` build tag, require live environment variables, start a real Firecracker process, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase3[456].*Firecracker|MicroVM'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 36 Firecracker explicit live driver fake-safe documentation missing %q", want)
		}
	}

	commands := phase36DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 36 Firecracker explicit live driver verification documentation must list default focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase36ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 36 default focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase36AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase36AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func TestPhase36FirecrackerExplicitLiveDriverOptionalLiveVerificationDocs(t *testing.T) {
	doc := readPhase36FirecrackerLiveDriverDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 36 keeps optional live integration coverage behind the `firecracker_live` build tag.",
		"It is not part of default verification.",
		"The tagged command compiles optional live tests and should skip with redacted messages when required live prerequisites are absent, so the tests compile or skip under `firecracker_live` without requiring live Firecracker execution.",
		"go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"Linux host with `/dev/kvm` present and read/write accessible to the test process for backend live boot coverage.",
		"`HAL_FIRECRACKER_LIVE_FIRECRACKER`: executable regular file for the Firecracker binary.",
		"`HAL_FIRECRACKER_LIVE_KERNEL`: readable regular file for the kernel image.",
		"`HAL_FIRECRACKER_LIVE_ROOTFS`: read/write regular file for the rootfs image.",
		"`HAL_FIRECRACKER_LIVE_INITRD`: optional readable regular file for an initrd image.",
		"`HAL_FIRECRACKER_LIVE_TIMEOUT`: optional positive Go duration for host-side API socket acceptance, defaulting to `10s`.",
		"`HAL_FIRECRACKER_LIVE_CPU_COUNT`: optional integer greater than or equal to `1`, defaulting to `1`.",
		"`HAL_FIRECRACKER_LIVE_MEMORY_MIB`: optional integer greater than or equal to `1`, defaulting to `256`.",
		"`HAL_FIRECRACKER_LIVE=1`: explicit opt-in for the host adapter live-runner test.",
		"The optional live command starts real Firecracker processes only inside tagged tests when every prerequisite is present.",
		"It does not wire the explicit live driver into default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`, worker routing, scheduler selection, or `hal sandboxd` paths.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 36 Firecracker explicit live driver optional live documentation missing %q", want)
		}
	}

	phase36AssertLiveVerificationCommand(t, doc)
	phase36AssertLiveIntegrationFilesMatchDocumentation(t)
}

func readPhase36FirecrackerLiveDriverDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase36-firecracker-explicit-live-driver-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 36 Firecracker explicit live driver verification doc) error: %v", err)
	}
	return string(data)
}

func phase36DefaultFocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "firecracker_live") {
			continue
		}
		if strings.Contains(command, "./...") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase36AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase3[456].*Firecracker|MicroVM'",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 36 Firecracker explicit live driver verification documentation missing command line %q", want)
		}
	}
}

func phase36AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase36DefaultFocusedGoTestCommands(doc)
	for _, req := range phase36RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 36 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 36 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase36RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDefaultConstructorsDoNotConfigureOrSelectFirecrackerHost"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendDefaultOptionsStartRemainsPlanningOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendInjectedAdapterWithoutLiveStartRemainsPlanningOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase36_live_lifecycle_delegation_test.go"), testName: "TestPhase36LiveStartedStopAndDeleteDelegateToInjectedProcessManager"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveBackendOptionsComposesExplicitFirecrackerLiveDependencies"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveDriverUsesExplicitBackendAndCapabilityOverride"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveDriverStartUsesFakeHostRunnerAndBootAcceptance"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveDriverReportsHonestLiveFirecrackerRuntimeMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveDriverDoesNotReportAcceptedLaunchWhenBootAcceptanceFails"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveDriverBootAcceptanceFailureCleansUpFakeHostProcess"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveBackendOptionsRejectsInvalidExplicitInputs"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36DefaultCommandPathsDoNotImportOrConstructExplicitFirecrackerLiveDriver"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36FactoryDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36SandboxexecDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36WorkerDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36SchedulerDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36SandboxdDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36FirecrackerExplicitLiveDriverGuardCoversRequiredSurfaces"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_default_guard_test.go", testName: "TestPhase36FirecrackerExplicitLiveDriverGuardRejectsFixtures"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_docs_test.go", testName: "TestPhase36FirecrackerExplicitLiveDriverVerificationDocs"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_docs_test.go", testName: "TestPhase36FirecrackerExplicitLiveDriverFakeSafeVerification"},
		{pkg: "./cmd", file: "phase36_firecracker_live_driver_docs_test.go", testName: "TestPhase36FirecrackerExplicitLiveDriverOptionalLiveVerificationDocs"},
	}
}

func phase36ForbiddenDefaultFocusedCommandRequirements() []string {
	var forbidden []string
	for _, marker := range phase34ForbiddenDefaultFocusedCommandRequirements() {
		if marker == "firecracker " {
			continue
		}
		forbidden = append(forbidden, marker)
	}
	return forbidden
}

func phase36AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase36_live_lifecycle_delegation_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"),
		"phase36_firecracker_live_driver_default_guard_test.go",
		"phase36_firecracker_live_driver_docs_test.go",
	} {
		phase34AssertNoLiveIntegrationBuildTag(t, file)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}

func phase36AssertLiveVerificationCommand(t *testing.T, doc string) {
	t.Helper()
	var liveCommands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "firecracker_live") {
			liveCommands = append(liveCommands, command)
		}
	}
	if len(liveCommands) != 1 {
		t.Fatalf("phase 36 verification documentation live command count = %d, want 1: %#v", len(liveCommands), liveCommands)
	}
	command := liveCommands[0]
	want := "go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost"
	if command != want {
		t.Fatalf("phase 36 live verification command = %q, want %q", command, want)
	}
	for _, forbidden := range []string{
		"-tags=integration",
		"-tags=kvm_integration",
		"docker ",
		"podman ",
		"hal sandboxd",
		"--live",
	} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("phase 36 live verification command %q contains unrelated live dependency marker %q", command, forbidden)
		}
	}
	for _, req := range []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLiveBootWithRealProcess"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_live_test.go"), testName: "TestOSExecProcessRunnerLiveStartsFirecrackerAPISocket"},
	} {
		covered := phase34FocusedCommandCoveringTest(t, []string{command}, req.pkg, req.testName)
		if covered == "" {
			t.Fatalf("phase 36 live verification command does not cover %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 36 live test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase36AssertLiveIntegrationFilesMatchDocumentation(t *testing.T) {
	t.Helper()

	backendLivePath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go")
	backendLiveSource := phase36ReadFile(t, backendLivePath)
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
	hostLiveSource := phase36ReadFile(t, hostLivePath)
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

func phase36ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
