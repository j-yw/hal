package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase37FirecrackerGuestReadinessVerificationDocs(t *testing.T) {
	doc := readPhase37FirecrackerGuestReadinessDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 37 adds an explicit, redaction-safe guest readiness boundary for live-started Firecracker microVMs.",
		"`internal/sandboxruntime` owns the additive guest readiness runtime metadata contract.",
		"`internal/sandboxruntime/microvm/firecracker` owns the optional backend `GuestReadinessWaiter` contract, request/result sanitization, and live-start sequencing.",
		"`internal/sandboxruntime/microvm/firecrackerhost` owns host-side polling through an injected `GuestReadinessProbe`.",
		"Live Firecracker start waits for host process and API socket acceptance before invoking guest readiness.",
		"When no guest readiness waiter is configured, live start must skip guest readiness and leave runtime guest readiness metadata absent.",
		"When guest readiness succeeds, runtime metadata records only `ready`, a sanitized transport label such as `vsock`, and safe labels such as `ready` and `probe_ok`.",
		"When guest readiness fails or returns a non-ready result, live start cleans up the accepted host process and returns a redaction-safe operation error.",
		"Default command, factory, sandboxexec, worker, scheduler, and sandboxd paths must not import Firecracker backend or host readiness packages, configure `GuestReadinessWaiter`, configure `GuestReadinessProbe`, call readiness wait/probe methods, or construct guest readiness metadata.",
		"Default `hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox` must not select Firecracker or microVM guest readiness unless explicit runtime metadata selects that path.",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase3[4567].*Firecracker|MicroVM|GuestReadiness|LiveDriver'",
		"go test -tags firecracker_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`golangci-lint run ./...` should run only when `golangci-lint` is installed.",
		"If `golangci-lint` is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Passing this matrix satisfies the Phase 37 tests and typecheck gates.",
		"Guest exec, guest copy in or out, real guest agent implementation, concrete vsock protocol implementation, Firecracker SDK dependency, machine configuration API calls, image/rootfs/kernel provisioning, network proxy, credential broker, default command enablement, default worker routing, default scheduler selection, default sandboxd enablement, and default live E2E guest-readiness verification are non-goals.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 37 Firecracker guest readiness verification documentation missing %q", want)
		}
	}

	phase37AssertVerificationCommands(t, doc)
	phase37AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"default `hal run --sandbox` selects Firecracker",
		"default `hal auto --sandbox` selects Firecracker",
		"default `hal factory run --sandbox` selects Firecracker",
		"default command paths configure `GuestReadinessWaiter`",
		"default command paths configure `GuestReadinessProbe`",
		"guest exec is implemented",
		"guest copy in is implemented",
		"guest copy out is implemented",
		"real guest agent implementation is included",
		"concrete vsock protocol implementation is included",
		"Firecracker SDK dependency is required",
		"machine configuration API calls are implemented",
		"network proxy is implemented",
		"credential broker is implemented",
		"default live E2E guest-readiness verification is implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 37 Firecracker guest readiness documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase37FirecrackerGuestReadinessFakeSafeVerification(t *testing.T) {
	doc := readPhase37FirecrackerGuestReadinessDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 37 verification is fake-safe and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, provider/runtime integration, host-specific kernel or rootfs images, a live guest, or a guest readiness agent.",
		"Default Phase 37 tests use pure runtime metadata contracts, backend fake process adapters, fake boot acceptance waiters, fake guest readiness waiters, injected fake host probes, fake clocks and sleepers, fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, temporary stores, and temporary state directories only.",
		"Default Phase 37 verification must not use integration build tags, the `firecracker_live` build tag, require live environment variables, start a real Firecracker process, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase3[4567].*Firecracker|MicroVM|GuestReadiness|LiveDriver'",
		"go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/firecrackerhost",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 37 Firecracker guest readiness fake-safe documentation missing %q", want)
		}
	}

	commands := phase37DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 37 Firecracker guest readiness verification documentation must list default focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase36ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 37 default focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase37AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase37AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func TestPhase37FirecrackerGuestReadinessOptionalLiveVerificationDocs(t *testing.T) {
	doc := readPhase37FirecrackerGuestReadinessDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 37 keeps optional live integration coverage behind the `firecracker_live` build tag.",
		"It is not part of default verification.",
		"The tagged command compiles optional live Firecracker host-process coverage and should pass or skip only live-gated cases when prerequisites are absent.",
		"Guest readiness itself remains tested through injected fake waiters and probes in default Phase 37 tests; the tagged command does not require a real guest readiness agent.",
		"go test -tags firecracker_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
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
		"It does not wire guest readiness into default `hal run`, `hal auto`, `hal factory run`, `sandboxexec`, worker routing, scheduler selection, or `hal sandboxd` paths.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 37 Firecracker guest readiness optional live documentation missing %q", want)
		}
	}

	phase37AssertLiveVerificationCommand(t, doc)
	phase37AssertLiveIntegrationFilesMatchDocumentation(t)
}

func readPhase37FirecrackerGuestReadinessDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase37-firecracker-guest-readiness-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 37 Firecracker guest readiness verification doc) error: %v", err)
	}
	return string(data)
}

func phase37DefaultFocusedGoTestCommands(doc string) []string {
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

func phase37AssertVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase3[4567].*Firecracker|MicroVM|GuestReadiness|LiveDriver'",
		"go test -tags firecracker_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 37 Firecracker guest readiness verification documentation missing command line %q", want)
		}
	}
}

func phase37AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase37DefaultFocusedGoTestCommands(doc)
	for _, req := range phase37RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 37 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 37 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase37RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeMetadataIncludesOptionalGuestReadinessMetadata"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeGuestReadinessMetadataStatesAreStable"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeGuestReadinessMetadataSanitizesUnsafeValues"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeGuestReadinessMetadataDoesNotClaimExecOrCopySupport"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestPhase37MicroVMNewRemainsInertForFirecrackerGuestReadiness"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestApplyRuntimeMetadataSanitizesGuestReadinessMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_readiness_test.go"), testName: "TestGuestReadinessRequestShapeIncludesOnlyHandleAndRuntimeIdentity"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_readiness_test.go"), testName: "TestGuestReadinessRequestSanitizesUnsafeInputs"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_readiness_test.go"), testName: "TestGuestReadinessResultShapeAndRuntimeMetadataAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_readiness_test.go"), testName: "TestGuestReadinessResultRejectsUnknownState"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendGuestReadinessWaiterIsOptionalAndInertUntilLiveWiring"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_default_behavior_test.go"), testName: "TestPhase37DefaultPlanningBackendRemainsInertAndUnsupported"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_guest_readiness_live_start_test.go"), testName: "TestPhase37LiveStartSkipsGuestReadinessWhenNoWaiterConfigured"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_guest_readiness_live_start_test.go"), testName: "TestPhase37LiveStartWaitsForGuestReadinessAfterHostAcceptance"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_guest_readiness_live_start_test.go"), testName: "TestPhase37LiveStartDoesNotWaitForGuestReadinessBeforeHostAcceptance"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_guest_readiness_live_start_test.go"), testName: "TestPhase37GuestReadinessFailureCleansUpLiveStartedProcessAndRedactsError"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_guest_readiness_live_start_test.go"), testName: "TestPhase37LiveStartRejectsNonReadyGuestReadinessResult"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_readiness_test.go"), testName: "TestAdapterPollsGuestReadinessUntilReady"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_readiness_test.go"), testName: "TestAdapterGuestReadinessPollingTimesOutDeterministically"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_readiness_test.go"), testName: "TestAdapterGuestReadinessProbeErrorsAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveBackendOptionsConfiguresOptionalGuestReadinessProbe"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveDriverStartUsesOptionalGuestReadinessProbe"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37DefaultCommandPathsDoNotWireFirecrackerGuestReadiness"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37FactoryDefaultsDoNotWireFirecrackerGuestReadiness"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37SandboxexecDefaultsDoNotWireFirecrackerGuestReadiness"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37WorkerDefaultsDoNotWireFirecrackerGuestReadiness"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37SchedulerDefaultsDoNotWireFirecrackerGuestReadiness"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37SandboxdDefaultsDoNotWireFirecrackerGuestReadiness"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37FirecrackerGuestReadinessGuardCoversRequiredDefaultSurfaces"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37RunAutoFactoryDefaultsDoNotSelectFirecrackerRuntime"},
		{pkg: "./cmd", file: "phase37_firecracker_default_guard_test.go", testName: "TestPhase37FirecrackerGuestReadinessGuardRejectsFixtures"},
		{pkg: "./cmd", file: "phase37_firecracker_guest_readiness_docs_test.go", testName: "TestPhase37FirecrackerGuestReadinessVerificationDocs"},
		{pkg: "./cmd", file: "phase37_firecracker_guest_readiness_docs_test.go", testName: "TestPhase37FirecrackerGuestReadinessFakeSafeVerification"},
		{pkg: "./cmd", file: "phase37_firecracker_guest_readiness_docs_test.go", testName: "TestPhase37FirecrackerGuestReadinessOptionalLiveVerificationDocs"},
	}
}

func phase37AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range []string{
		filepath.Join("..", "internal", "sandboxruntime", "types_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_readiness_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_default_behavior_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase37_guest_readiness_live_start_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_readiness_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"),
		"phase37_firecracker_default_guard_test.go",
		"phase37_firecracker_guest_readiness_docs_test.go",
	} {
		phase34AssertNoLiveIntegrationBuildTag(t, file)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}

func phase37AssertLiveVerificationCommand(t *testing.T, doc string) {
	t.Helper()
	var liveCommands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "firecracker_live") {
			liveCommands = append(liveCommands, command)
		}
	}
	if len(liveCommands) != 1 {
		t.Fatalf("phase 37 verification documentation live command count = %d, want 1: %#v", len(liveCommands), liveCommands)
	}
	command := liveCommands[0]
	want := "go test -tags firecracker_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost"
	if command != want {
		t.Fatalf("phase 37 live verification command = %q, want %q", command, want)
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
			t.Fatalf("phase 37 live verification command %q contains unrelated live dependency marker %q", command, forbidden)
		}
	}
	for _, req := range []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLiveBootWithRealProcess"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_live_test.go"), testName: "TestOSExecProcessRunnerLiveStartsFirecrackerAPISocket"},
	} {
		covered := phase34FocusedCommandCoveringTest(t, []string{command}, req.pkg, req.testName)
		if covered == "" {
			t.Fatalf("phase 37 live verification command does not cover %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 37 live test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase37AssertLiveIntegrationFilesMatchDocumentation(t *testing.T) {
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
