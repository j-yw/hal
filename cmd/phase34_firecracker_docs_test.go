package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestPhase34FirecrackerBootVerticalSliceVerificationDocs(t *testing.T) {
	doc := readPhase34FirecrackerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 34 adds an explicitly opt-in Firecracker live boot vertical slice on top of the existing fake-only Firecracker backend foundation and Phase 33 process launch adapter boundary.",
		"`internal/sandboxruntime/microvm/firecracker`",
		"Default `firecracker.NewBackend(BackendOptions{})` and backends without `LiveStart: true` remain planning-only.",
		"Live boot requires explicit `BackendOptions.LiveStart`, an injected `ProcessAdapter` or `ProcessLaunchAdapter`, an injected boot acceptance waiter, and an injected live process manager.",
		"Before an injected process starter is called, Phase 34 renders the Firecracker machine configuration, boot source, root drive payload, log path, metrics path, and API socket path into the planned state directory.",
		"Successful fake-backed live boot records accepted host-side process metadata only after the injected boot acceptance waiter reports host process acceptance and API socket availability.",
		"This is a host-side acceptance signal only; it is not a guest readiness or guest health claim.",
		"Stop, delete, and failed-acceptance cleanup use injected live process manager hooks only for targets that were live-started.",
		"No default command, scheduler, factory, sandboxexec, sandboxd, or worker path starts Firecracker or wires Phase 34 live boot options.",
		"go test -timeout=120s ./internal/sandboxruntime/microvm",
		"go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase34'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` should run only when `golangci-lint` is installed.",
		"If `golangci-lint` is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Guest exec, copy, Docker/Podman, guest readiness, networking enforcement, credential delivery, workspace sync, and default production enablement remain unsupported.",
		"Phase 34 does not implement guest exec, guest copy, Docker/Podman guest engines, guest readiness checks, guest health checks, guest agent or vsock transport, SSH access, workspace synchronization, credential delivery, network proxy/firewall enforcement, Firecracker SDK integration, API socket machine configuration calls, jailer/root setup, cgroups, default registration, or default live E2E tests.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 34 Firecracker verification documentation missing %q", want)
		}
	}

	phase34AssertBroadVerificationCommands(t, doc)
	phase34AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
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
		"default registration is implemented",
		"default live E2E tests are implemented",
		"default commands start Firecracker",
		"default sandboxd launches Firecracker",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 34 Firecracker verification documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase34FirecrackerBootVerticalSliceFakeOnlyVerification(t *testing.T) {
	doc := readPhase34FirecrackerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 34 verification is fake-only and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, provider/runtime integration, host-specific kernel or rootfs images, or a live guest.",
		"Default Phase 34 tests must use pure contracts, deterministic path and payload rendering, injected fake process starters and adapters, injected fake boot acceptance waiters, injected fake live process managers, fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, temporary stores, and temporary state directories only.",
		"Default Phase 34 verification must not use integration build tags, the `firecracker_live` build tag, require live environment variables, start a real Firecracker process, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase34'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 34 Firecracker fake-only documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"default verification requires KVM",
		"default verification requires a Firecracker binary",
		"default verification requires root privileges",
		"default verification requires live network sockets",
		"default verification requires Firecracker SDKs",
		"default verification requires cloud credentials",
		"default verification requires Docker",
		"default verification requires Podman",
		"default verification requires worker daemons",
		"default verification requires provider/runtime integration",
		"default verification requires a live guest",
		"KVM is required for default verification",
		"Firecracker binary is required for default verification",
		"root privileges are required for default verification",
		"live network sockets are required for default verification",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 34 Firecracker fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase34DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 34 Firecracker verification documentation must list default focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase34ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 34 default focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase34AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase34AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func TestPhase34FirecrackerOptionalLiveVerificationDocs(t *testing.T) {
	doc := readPhase34FirecrackerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 34 includes an optional live integration test behind the `firecracker_live` build tag.",
		"It is not part of default verification.",
		"go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker -run 'TestFirecrackerLiveBootWithRealProcess|TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted'",
		"`HAL_FIRECRACKER_LIVE_FIRECRACKER`: executable regular file for the Firecracker binary.",
		"`HAL_FIRECRACKER_LIVE_KERNEL`: readable regular file for the kernel image.",
		"`HAL_FIRECRACKER_LIVE_ROOTFS`: read/write regular file for the rootfs image.",
		"Linux host with `/dev/kvm` present and read/write accessible to the test process.",
		"`HAL_FIRECRACKER_LIVE_INITRD`: readable regular file for an initrd image.",
		"`HAL_FIRECRACKER_LIVE_TIMEOUT`: positive Go duration for host-side API socket acceptance, defaulting to `10s`.",
		"`HAL_FIRECRACKER_LIVE_CPU_COUNT`: integer greater than or equal to `1`, defaulting to `1`.",
		"`HAL_FIRECRACKER_LIVE_MEMORY_MIB`: integer greater than or equal to `1`, defaulting to `256`.",
		"The optional live command starts a real Firecracker process through the same injected `ProcessRunnerStartRequest` boundary used by fake tests.",
		"The harness passes an empty environment to the process, waits only for host-side API socket availability, stops or kills remaining process state during cleanup, and removes only the Firecracker-owned state directory.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 34 Firecracker optional live documentation missing %q", want)
		}
	}

	phase34AssertLiveVerificationCommand(t, doc)
	phase34AssertLiveIntegrationFileMatchesDocumentation(t)
}

func readPhase34FirecrackerDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase34-firecracker-boot-vertical-slice-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 34 Firecracker verification doc) error: %v", err)
	}
	return string(data)
}

func phase34AllGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase34DefaultFocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "-tags=firecracker_live") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase34AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 34 Firecracker verification documentation missing broad verification command line %q", want)
		}
	}
}

func phase34DocumentedShellCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "go test "):
			commands[line] = true
		case strings.HasPrefix(line, "go vet "):
			commands[line] = true
		case strings.HasPrefix(line, "make "):
			commands[line] = true
		case strings.HasPrefix(line, "git diff "):
			commands[line] = true
		}
	}
	return commands
}

func phase34ForbiddenDefaultFocusedCommandRequirements() []string {
	return []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"-tags=microvm_integration",
		"-tags=kvm_integration",
		"-tags=firecracker_live",
		"worker_integration",
		"podman_integration",
		"microvm_integration",
		"kvm_integration",
		"firecracker_live",
		"HAL_FIRECRACKER_LIVE_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"HAL_WORKER_INTEGRATION_",
		"DOCKER_HOST",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"docker ",
		"podman ",
		"firecracker ",
		"cloud-hypervisor ",
		"/dev/kvm",
		"curl ",
		"hal sandboxd",
		"--live",
	}
}

func phase34AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DefaultFocusedGoTestCommands(doc)
	for _, req := range phase34RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 34 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 34 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase34RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMProductionImportBoundaries"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMProductionSourceOmitsLiveBackendOperations"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestPhase34FirecrackerProductionLiveBootDoesNotCallOSExecDirectly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestFirecrackerProductionSourceDoesNotIntroduceDockerOrPodmanGuestEngine"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestFirecrackerDefaultTestBoundaryExcludesOptInLiveTests"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_live_boot_contract_test.go"), testName: "TestPhase34DefaultBackendOptionsKeepLiveBootPlanningOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_live_boot_contract_test.go"), testName: "TestPhase34BackendOptionsZeroValueKeepsLiveStartDefaultOff"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_live_boot_contract_test.go"), testName: "TestPhase34LiveBootRequiresCompleteOptionsBeforeProcessStart"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_live_boot_contract_test.go"), testName: "TestPhase34LiveBootMissingProcessBoundaryReturnsPlanningOrConfigError"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_render_launch_boundary_test.go"), testName: "TestPhase34LiveBootRendersBootFilesIntoStateDirBeforeLaunch"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_render_launch_boundary_test.go"), testName: "TestPhase34LiveBootRenderFailurePreventsLaunchAndSanitizesError"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_boot_acceptance_cleanup_contract_test.go"), testName: "TestPhase34LiveBootWaitsForHostSideAcceptanceBeforeAcceptedMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_boot_acceptance_cleanup_contract_test.go"), testName: "TestPhase34BootAcceptanceFailuresCleanupLiveStartedProcessState"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_boot_acceptance_cleanup_contract_test.go"), testName: "TestPhase34StopDeleteUseLiveProcessManagerOnlyForLiveStartedTargets"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_boot_acceptance_cleanup_contract_test.go"), testName: "TestPhase34LiveProcessManagerFailuresAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_boot_acceptance_cleanup_contract_test.go"), testName: "TestPhase34BootAcceptanceCleanupKeepsCallerOwnedPathsOutsideStateDir"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_failure_redaction_test.go"), testName: "TestPhase34LiveBootFailurePathsRedactSeededSensitiveValues"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_failure_redaction_test.go"), testName: "TestPhase34NestedProcessBoundaryFailureDetailsAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_metadata_redaction_guard_test.go"), testName: "TestPhase34LiveBootMissingSafetyOptionsDoesNotLaunchAndKeepsPublicOutputRedacted"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_metadata_redaction_guard_test.go"), testName: "TestPhase34LiveBootPublicMetadataRedactsSensitiveInputsAndUnsupportedClaims"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_metadata_redaction_guard_test.go"), testName: "TestPhase34LiveBootPublicJSONErrorRedactsRunnerDetails"},
		{pkg: "./cmd", file: "phase34_firecracker_default_guard_test.go", testName: "TestPhase34DefaultPathsDoNotWireFirecrackerLiveBoot"},
		{pkg: "./cmd", file: "phase34_firecracker_default_guard_test.go", testName: "TestPhase34DefaultRunAutoFactoryPathsDoNotStartFirecracker"},
		{pkg: "./cmd", file: "phase34_firecracker_default_guard_test.go", testName: "TestPhase34DefaultFirecrackerGuardCoversRequiredSurfaces"},
		{pkg: "./cmd", file: "phase34_firecracker_default_guard_test.go", testName: "TestPhase34DefaultFirecrackerGuardRejectsLiveBootFixtures"},
		{pkg: "./cmd", file: "phase34_firecracker_docs_test.go", testName: "TestPhase34FirecrackerBootVerticalSliceVerificationDocs"},
		{pkg: "./cmd", file: "phase34_firecracker_docs_test.go", testName: "TestPhase34FirecrackerBootVerticalSliceFakeOnlyVerification"},
		{pkg: "./cmd", file: "phase34_firecracker_docs_test.go", testName: "TestPhase34FirecrackerOptionalLiveVerificationDocs"},
	}
}

type phase34FocusedTest struct {
	pkg      string
	file     string
	testName string
}

func phase34FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase34FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector, ok := phase34FocusedCommandRunSelector(t, command)
		if !ok {
			return command
		}
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 34 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase34FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase34FocusedCommandRunSelector(t *testing.T, command string) (string, bool) {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 34 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\""), true
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\""), true
		}
	}
	return "", false
}

func phase34TestFileDefinesFunction(t *testing.T, path, testName string) bool {
	t.Helper()
	file := phase34ParseGoFile(t, path, parser.ParseComments)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == testName {
			return true
		}
	}
	return false
}

func phase34AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range phase34FakeOnlyGuardedTestFiles() {
		phase34AssertNoLiveIntegrationBuildTag(t, file)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}

func phase34FakeOnlyGuardedTestFiles() []string {
	return []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_live_boot_contract_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_render_launch_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_boot_acceptance_cleanup_contract_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_failure_redaction_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase34_metadata_redaction_guard_test.go"),
		"phase34_firecracker_default_guard_test.go",
		"phase34_firecracker_docs_test.go",
		"sandbox_runtime_compat_test.go",
		"sandboxd_test.go",
	}
}

func phase34AssertNoLiveIntegrationBuildTag(t *testing.T, path string) {
	t.Helper()
	file := phase34ParseGoFile(t, path, parser.ParseComments)
	for _, group := range file.Comments {
		if group.End() > file.Package {
			continue
		}
		for _, comment := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
			text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
			text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
			if strings.HasPrefix(text, "go:build") {
				for _, tag := range []string{"integration", "worker_integration", "podman_integration", "microvm_integration", "kvm_integration", "firecracker_live"} {
					if strings.Contains(text, tag) {
						t.Fatalf("%s uses integration build tag %q; Phase 34 focused tests must stay fake-only by default", phase34FirecrackerDisplayPath(t, path), tag)
					}
				}
			}
		}
	}
}

func phase34AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
	t.Helper()
	file := phase34ParseGoFile(t, path, parser.ImportsOnly)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
		}
		if forbidden := phase34ForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 34 fake-only guard avoids %s", phase34FirecrackerDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase34AssertLiveVerificationCommand(t *testing.T, doc string) {
	t.Helper()
	commands := phase34AllGoTestCommands(doc)
	var liveCommands []string
	for _, command := range commands {
		if strings.Contains(command, "-tags=firecracker_live") {
			liveCommands = append(liveCommands, command)
		}
	}
	if len(liveCommands) != 1 {
		t.Fatalf("phase 34 verification documentation live command count = %d, want 1: %#v", len(liveCommands), liveCommands)
	}
	command := liveCommands[0]
	want := "go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker -run 'TestFirecrackerLiveBootWithRealProcess|TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted'"
	if command != want {
		t.Fatalf("phase 34 live verification command = %q, want %q", command, want)
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
			t.Fatalf("phase 34 live verification command %q contains unrelated live dependency marker %q", command, forbidden)
		}
	}
	for _, req := range []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLiveBootWithRealProcess"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), testName: "TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted"},
	} {
		covered := phase34FocusedCommandCoveringTest(t, []string{command}, req.pkg, req.testName)
		if covered == "" {
			t.Fatalf("phase 34 live verification command does not cover %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 34 live test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase34AssertLiveIntegrationFileMatchesDocumentation(t *testing.T) {
	t.Helper()
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	if !strings.Contains(string(source), "//go:build firecracker_live") {
		t.Fatalf("%s missing firecracker_live build tag", phase34FirecrackerDisplayPath(t, path))
	}
	for _, envName := range []string{
		"HAL_FIRECRACKER_LIVE_FIRECRACKER",
		"HAL_FIRECRACKER_LIVE_KERNEL",
		"HAL_FIRECRACKER_LIVE_ROOTFS",
		"HAL_FIRECRACKER_LIVE_INITRD",
		"HAL_FIRECRACKER_LIVE_TIMEOUT",
		"HAL_FIRECRACKER_LIVE_CPU_COUNT",
		"HAL_FIRECRACKER_LIVE_MEMORY_MIB",
	} {
		if !strings.Contains(string(source), envName) {
			t.Fatalf("%s missing documented live prerequisite %s", phase34FirecrackerDisplayPath(t, path), envName)
		}
	}
	for _, marker := range []string{
		"/dev/kvm",
		"exec.CommandContext",
		"cmd.Env = []string{}",
		"firecrackerLiveAPISocketAvailable",
		"os.RemoveAll(cleaned.StateDir)",
	} {
		if !strings.Contains(string(source), marker) {
			t.Fatalf("%s missing documented live behavior marker %q", phase34FirecrackerDisplayPath(t, path), marker)
		}
	}
}

func phase34ParseGoFile(t *testing.T, path string, mode parser.Mode) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, mode)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	return file
}

func phase34ForbiddenDefaultTestImport(importPath string) string {
	switch importPath {
	case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
		return "network sockets or live proxy servers"
	case "os/exec":
		return "process launch"
	case "syscall":
		return "host privilege or KVM access"
	}
	for _, forbidden := range []struct {
		prefix string
		label  string
	}{
		{prefix: "github.com/docker/docker", label: "Docker clients"},
		{prefix: "github.com/containers/podman", label: "Podman clients"},
		{prefix: "github.com/containers/image", label: "container image clients"},
		{prefix: "github.com/containers/storage", label: "container storage clients"},
		{prefix: "github.com/firecracker-microvm", label: "Firecracker SDKs"},
		{prefix: "libvirt.org/go/libvirt", label: "KVM or microVM integrations"},
		{prefix: "golang.org/x/sys", label: "host privilege or KVM access"},
		{prefix: "github.com/digitalocean/godo", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go-v2", label: "cloud SDKs"},
		{prefix: "github.com/Azure/azure-sdk-for-go", label: "cloud SDKs"},
		{prefix: "github.com/hetznercloud/hcloud-go", label: "cloud SDKs"},
		{prefix: "cloud.google.com/go", label: "cloud SDKs"},
		{prefix: "google.golang.org/api", label: "cloud SDKs"},
		{prefix: "google.golang.org/grpc", label: "network clients"},
	} {
		if strings.HasPrefix(importPath, forbidden.prefix) {
			return forbidden.label
		}
	}
	return ""
}

func phase34FirecrackerDisplayPath(t *testing.T, path string) string {
	t.Helper()
	if !strings.HasPrefix(filepath.ToSlash(path), "../") {
		return filepath.ToSlash(filepath.Join("cmd", path))
	}
	rel, err := filepath.Rel(filepath.Join(".."), path)
	if err != nil {
		t.Fatalf("Rel(%s, %s) error: %v", filepath.Join(".."), path, err)
	}
	return filepath.ToSlash(rel)
}
