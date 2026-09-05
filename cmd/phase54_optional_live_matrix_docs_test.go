package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	phase54OptionalLiveGuardCommand = "go test -count=1 -timeout=180s ./internal/livegate ./cmd -run 'Test(LiveGate|RequireLiveGate|MicroVME2ELiveGate|Phase50.*Live|US003MicroVMLiveE2E|US010.*Live)'"
	phase54FirecrackerLiveCommand   = "env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost"
	phase54NetworkLiveCommand       = "env HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'"
	phase54CredentialLiveCommand    = "env HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'"
	phase54TrustPolicyCommand       = "go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition -run 'Test(TrustPolicy|EvaluateTrustPolicy|ProjectTemplateProvenance|ProjectRuntimeTemplateLockMetadata|SandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection)'"
	phase54TemplateGuardCommand     = "go test -count=1 -timeout=180s ./cmd -run 'TestPhase52Template'"
	phase54OptionalLiveGuardFile    = "cmd/phase54_optional_live_matrix_docs_test.go"
)

func TestPhase54OptionalLiveVerificationMatrixDocumentsSuites(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"## Optional Live Verification Matrix",
		"These commands are optional operator-run checks for prepared live infrastructure.",
		"They are not part of the fake-only checks job, not release package prerequisites, and not post-run PRD validation.",
		"Run the focused live-gate and live-marker guard suite without live tags or live environment markers:",
		"Run Firecracker host/process and microVM live checks only on a prepared host:",
		"Run network enforcement live checks only when proxy and firewall/runtime-rule prerequisites are deliberately enabled:",
		"Run credential delivery live checks only when the global delivery gate and at least one delivery-mode gate are deliberately enabled:",
		"Run the template provenance and trust-policy suite as fake/local verification:",
		"No standalone template/provenance live build tag is present.",
		"Run the composed Firecracker, network enforcement, credential delivery, and template trust live E2E only on a host prepared for every listed gate:",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("%s optional live matrix missing %q", phase50SafeDisplayPath(phase54ReleasePackageDesignDocPath()), want)
		}
	}
}

func TestPhase54OptionalLiveVerificationMatrixListsDiscoveredTagsAndMarkers(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())

	for _, tag := range []string{
		"`firecracker_live`",
		"`microvm_e2e_live`",
		"`network_enforcement_live`",
		"`credential_delivery_live`",
	} {
		if !strings.Contains(doc, tag) {
			t.Fatalf("Phase 54 optional live matrix missing build tag %s", tag)
		}
	}

	for _, marker := range []string{
		"`HAL_FIRECRACKER_LIVE`",
		"`HAL_FIRECRACKER_LIVE_FIRECRACKER`",
		"`HAL_FIRECRACKER_LIVE_KERNEL`",
		"`HAL_FIRECRACKER_LIVE_ROOTFS`",
		"`HAL_FIRECRACKER_LIVE_INITRD`",
		"`HAL_FIRECRACKER_LIVE_TIMEOUT`",
		"`HAL_FIRECRACKER_LIVE_CPU_COUNT`",
		"`HAL_FIRECRACKER_LIVE_MEMORY_MIB`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE_ENV`",
		"`HAL_TEMPLATE_TRUST_LIVE`",
	} {
		if !strings.Contains(doc, marker) {
			t.Fatalf("Phase 54 optional live matrix missing environment marker %s", marker)
		}
	}
}

func TestPhase54OptionalLiveVerificationMatrixCommandsAreExactAndRedactionSafe(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	commands := phase54OptionalLiveDocumentedCommands(doc)

	for _, want := range []string{
		phase54OptionalLiveGuardCommand,
		phase54FirecrackerLiveCommand,
		phase54NetworkLiveCommand,
		phase54CredentialLiveCommand,
		phase54TrustPolicyCommand,
		phase54TemplateGuardCommand,
		phase53LiveE2ECommand,
	} {
		if !commands[want] {
			t.Fatalf("Phase 54 optional live matrix missing command line %q", want)
		}
		phase54AssertOptionalLiveCommandRedactionSafe(t, want)
	}

	for _, command := range phase54DefaultDocumentedCommands(doc) {
		if marker := phase54ForbiddenDefaultCommandMarker(command); marker != "" {
			t.Fatalf("Phase 54 default command scan included optional live marker %q in command %q", marker, command)
		}
	}
}

func TestPhase54OptionalLiveVerificationMatrixReusesPhase53FinalLiveE2ECommand(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	phase53Doc := readPhase53FinalVerificationDoc(t)
	phase53FinalDocRef := "docs/design/" + phase53FinalVerificationDocPath

	if !strings.Contains(doc, phase53FinalDocRef) {
		t.Fatalf("%s must reference %s before documenting the composed live E2E command", phase50SafeDisplayPath(phase54ReleasePackageDesignDocPath()), phase53FinalDocRef)
	}
	if !strings.Contains(phase53Doc, phase53LiveE2ECommand) {
		t.Fatalf("%s no longer contains the canonical Phase 53 live E2E command", phase53FinalDocRef)
	}

	var composedCommands []string
	for command := range phase54OptionalLiveDocumentedCommands(doc) {
		if strings.Contains(command, "TestMicroVMLiveE2EComposedLiveExecutionPath") ||
			strings.Contains(command, "microvm_e2e_live") {
			composedCommands = append(composedCommands, command)
		}
	}
	if len(composedCommands) != 1 {
		t.Fatalf("Phase 54 optional live matrix documented composed live E2E commands = %#v, want exactly one", composedCommands)
	}
	if composedCommands[0] != phase53LiveE2ECommand {
		t.Fatalf("Phase 54 composed live E2E command diverged from Phase 53 final verification:\n got: %q\nwant: %q", composedCommands[0], phase53LiveE2ECommand)
	}
}

func TestPhase54OptionalLiveVerificationMatrixCommandSelectorsMatchTestsAndPackages(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	commands := phase54OptionalLiveDocumentedCommands(doc)

	for command := range commands {
		packages := phase54CommandPackageSelectors(command)
		if len(packages) == 0 {
			t.Fatalf("Phase 54 optional live command %q has no package selector", command)
		}
		for _, packageSelector := range packages {
			phase54AssertPackageSelectorExists(t, packageSelector, command)
		}
		runSelector, ok := phase54CommandRunSelector(command)
		if !ok {
			continue
		}
		for _, packageSelector := range packages {
			phase54AssertRunSelectorMatchesPackageTests(t, runSelector, packageSelector, command)
		}
	}
}

func TestPhase54DocumentedFocusedGoTestSelectorsMatchTestsAndPackages(t *testing.T) {
	for _, docPath := range []string{
		phase54ReleasePackageDesignDocPath(),
		phase54OperatorReleaseHandoffDocPath(),
	} {
		doc := phase50ReadFile(t, docPath)
		for command := range phase34DocumentedShellCommands(doc) {
			runSelector, ok := phase54CommandRunSelector(command)
			if !ok || runSelector == "^$" {
				continue
			}
			packages := phase54CommandPackageSelectors(command)
			if len(packages) == 0 {
				t.Fatalf("%s focused go test command %q has no package selector", phase50SafeDisplayPath(docPath), command)
			}
			for _, packageSelector := range packages {
				phase54AssertPackageSelectorExists(t, packageSelector, command)
				phase54AssertRunSelectorMatchesPackageTests(t, runSelector, packageSelector, command)
			}
		}
	}
}

func TestPhase54OptionalLiveVerificationMatrixGuardFileStaysInLiveMarkerAllowlists(t *testing.T) {
	if !phase50ApprovedLiveMarkerFiles()[phase54OptionalLiveGuardFile] {
		t.Fatalf("%s must stay in the Phase 50 live marker allowlist because it documents optional live marker names", phase54OptionalLiveGuardFile)
	}
	if !us010ApprovedLiveE2EGuardFiles()[phase54OptionalLiveGuardFile] {
		t.Fatalf("%s must stay in the Phase 53 live E2E marker allowlist because it documents the composed live E2E command", phase54OptionalLiveGuardFile)
	}
}

func TestPhase54OptionalLiveVerificationMatrixExplainsSkipBehavior(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"When required build tags are absent, Go excludes the tagged live test files from default package builds.",
		"When required environment markers are absent, live gate tests skip with sanitized missing-prerequisite messages before Firecracker launch, listener or firewall mutation, credential delivery, template trust live execution, provider probing, or any runtime state change.",
		"The standalone network enforcement and credential delivery live harnesses currently remain opt-in placeholders after their gates are satisfied",
		"the composed microVM live E2E command is the only documented live execution path.",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("Phase 54 optional live matrix missing skip behavior %q", want)
		}
	}
}

func phase54OptionalLiveDocumentedCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	inOptionalLiveSection := false
	optionalLiveHeadingDepth := 0
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			depth := phase54MarkdownHeadingDepth(line)
			lower := strings.ToLower(line)
			if inOptionalLiveSection && depth <= optionalLiveHeadingDepth {
				inOptionalLiveSection = false
				optionalLiveHeadingDepth = 0
			}
			if strings.Contains(lower, "optional") && strings.Contains(lower, "live") && strings.Contains(lower, "verification") {
				inOptionalLiveSection = true
				optionalLiveHeadingDepth = depth
			}
			continue
		}
		if inOptionalLiveSection && phase54IsShellCommandLine(line) {
			commands[line] = true
		}
	}
	return commands
}

func phase54AssertOptionalLiveCommandRedactionSafe(t *testing.T, command string) {
	t.Helper()
	lower := strings.ToLower(command)
	for _, unsafe := range []string{
		"127.0.0.1",
		"localhost",
		"http://",
		"https://",
		"unix://",
		"/tmp/",
		"/users/",
		".sock",
		"authorization:",
		"bearer ",
		"token=",
		"secret=",
		"credential=",
		"providerconfig",
		"iptables",
		"nft ",
		" pf ",
		"--api-sock",
		"--kernel",
		"--rootfs",
		"port=",
	} {
		if strings.Contains(lower, unsafe) {
			t.Fatalf("Phase 54 optional live command %q contains unsafe detail marker %q", command, unsafe)
		}
	}

	for _, field := range strings.Fields(command) {
		if strings.HasPrefix(field, "HAL_") && !strings.HasSuffix(field, "=<set>") {
			t.Fatalf("Phase 54 optional live command %q uses non-placeholder environment assignment %q", command, field)
		}
	}
}

func phase54CommandPackageSelectors(command string) []string {
	var packages []string
	for _, field := range strings.Fields(command) {
		field = strings.Trim(field, "'\"")
		if strings.HasPrefix(field, "./") {
			packages = append(packages, field)
		}
	}
	return packages
}

func phase54CommandRunSelector(command string) (string, bool) {
	fields := strings.Fields(command)
	for i, field := range fields {
		field = strings.Trim(field, "\"")
		if strings.HasPrefix(field, "-run=") {
			return phase54TrimShellQuotes(strings.TrimPrefix(field, "-run=")), true
		}
		if field == "-run" && i+1 < len(fields) {
			return phase54TrimShellQuotes(fields[i+1]), true
		}
	}
	return "", false
}

func phase54TrimShellQuotes(value string) string {
	return strings.Trim(value, "'\"")
}

func phase54AssertPackageSelectorExists(t *testing.T, packageSelector, command string) {
	t.Helper()
	dir := phase54PackageSelectorDir(t, packageSelector)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Phase 54 optional live command %q uses missing package selector %q: %v", command, packageSelector, err)
	}
	if !info.IsDir() {
		t.Fatalf("Phase 54 optional live command %q uses non-directory package selector %q", command, packageSelector)
	}
}

func phase54AssertRunSelectorMatchesPackageTests(t *testing.T, runSelector, packageSelector, command string) {
	t.Helper()
	re, err := regexp.Compile(runSelector)
	if err != nil {
		t.Fatalf("Phase 54 optional live command %q has invalid -run selector %q: %v", command, runSelector, err)
	}
	for _, testName := range phase54PackageTestNames(t, packageSelector) {
		if re.MatchString(testName) {
			return
		}
	}
	t.Fatalf("Phase 54 optional live command %q -run selector %q matched no tests in %s", command, runSelector, packageSelector)
}

func phase54PackageTestNames(t *testing.T, packageSelector string) []string {
	t.Helper()
	dir := phase54PackageSelectorDir(t, packageSelector)
	paths, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatalf("Glob(%s/*_test.go) error: %v", phase50SafeDisplayPath(dir), err)
	}
	if len(paths) == 0 {
		t.Fatalf("Phase 54 optional live package selector %s contains no test files", packageSelector)
	}

	var names []string
	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", phase50SafeDisplayPath(path), err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", phase50SafeDisplayPath(path), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			names = append(names, fn.Name.Name)
		}
	}
	if len(names) == 0 {
		t.Fatalf("Phase 54 optional live package selector %s contains no Test functions", packageSelector)
	}
	return names
}

func phase54PackageSelectorDir(t *testing.T, packageSelector string) string {
	t.Helper()
	if !strings.HasPrefix(packageSelector, "./") || strings.Contains(packageSelector, "...") {
		t.Fatalf("Phase 54 optional live command uses unsupported package selector %q", packageSelector)
	}
	return filepath.Join("..", filepath.FromSlash(strings.TrimPrefix(packageSelector, "./")))
}
