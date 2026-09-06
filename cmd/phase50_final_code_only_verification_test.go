package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase50FinalCodeOnlyVerificationDocPath = "sandbox-runtime-v2-phase50-final-code-only-verification.md"

func TestPhase50FinalCodeOnlyVerificationDocumentation(t *testing.T) {
	doc := readPhase50FinalCodeOnlyVerificationDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 50 final verification is code-only.",
		"Default verification is fake-only.",
		"Default Fake-Only Verification",
		"Optional Manual Live Verification",
		"Manual live checks are optional operator evidence only.",
		"Manual live checks are not part of default verification.",
		"focused live gate contract, evaluator, helper, guard, documentation, and final barrier checks",
		"`go test -count=1 -run '^$' ./...` is the typecheck-only pass.",
		"`golangci-lint run ./...` is conditional.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 50 final code-only verification documentation missing %q", want)
		}
	}

	phase50FinalAssertDocumentedDefaultCommands(t, doc)
	phase50FinalAssertDocumentedOptionalLiveCommands(t, doc)
}

func TestPhase50FinalVerificationCommandsStayCodeOnly(t *testing.T) {
	doc := readPhase50FinalCodeOnlyVerificationDoc(t)
	commands := phase50FinalDocumentedCommandLines(doc)
	if len(commands) == 0 {
		t.Fatal("phase 50 final code-only verification documentation must list command lines")
	}

	for _, command := range commands {
		if !phase50FinalIsCodeOnlyCommand(command) {
			t.Fatalf("phase 50 final verification command %q is not an approved code-only command", command)
		}
		for _, forbidden := range phase50FinalForbiddenWorkflowMarkers() {
			if strings.Contains(strings.ToLower(command), forbidden) {
				t.Fatalf("phase 50 final verification command %q contains forbidden workflow marker %q", command, forbidden)
			}
		}
	}

	if forbidden := phase50FinalForbiddenDocumentationMarker(doc); forbidden != "" {
		t.Fatalf("phase 50 final code-only verification documentation contains forbidden marker %q", forbidden)
	}
}

func TestPhase50FinalWorkflowCommandGuardRejectsFixtures(t *testing.T) {
	for _, fixture := range []string{
		"```bash\nhal validate\n```",
		"```bash\nhal convert --granular\n```",
		"```bash\nhal plan 'feature'\n```",
		"```bash\nhal auto\n```",
		"```bash\nhal run\n```",
		"```bash\nhal report\n```",
		"Run PRD validation before final verification.",
		"Run PRD audit before final verification.",
		"Run PRD regeneration before final verification.",
	} {
		if forbidden := phase50FinalForbiddenDocumentationMarker(fixture); forbidden == "" {
			t.Fatalf("phase 50 final documentation guard did not reject fixture %q", fixture)
		}
	}
}

func TestPhase50FinalDefaultMatrixStaysFakeOnly(t *testing.T) {
	doc := readPhase50FinalCodeOnlyVerificationDoc(t)
	defaultCommands := phase50FinalDocumentedDefaultCommands(doc)
	if len(defaultCommands) == 0 {
		t.Fatal("phase 50 final documentation must list default verification commands")
	}

	for _, command := range defaultCommands {
		if strings.HasPrefix(command, "env ") {
			t.Fatalf("phase 50 default verification command %q must not require live env gates", command)
		}
		for _, forbidden := range phase50FinalForbiddenDefaultCommandMarkers() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 50 default verification command %q contains forbidden live/default marker %q", command, forbidden)
			}
		}
	}

	optionalCommands := phase50FinalDocumentedOptionalLiveCommands(doc)
	if len(optionalCommands) == 0 {
		t.Fatal("phase 50 final documentation must keep optional live commands in a separate manual section")
	}
	for _, command := range optionalCommands {
		if !strings.HasPrefix(command, "env ") || !strings.Contains(command, " go test ") || !strings.Contains(command, "-tags=") {
			t.Fatalf("phase 50 optional live command %q must remain an explicit env-gated go test command", command)
		}
	}
}

func TestPhase50FinalFocusedCommandsCoverPhase50Guards(t *testing.T) {
	doc := readPhase50FinalCodeOnlyVerificationDoc(t)
	commands := phase50FinalFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 50 final documentation must list focused go test selectors")
	}

	for _, req := range phase50FinalRequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 50 final documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 50 final verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase50FinalCodeOnlyGuardFileStaysInDefaultSuite(t *testing.T) {
	source := phase50FinalReadFile(t, "phase50_final_code_only_verification_test.go")
	header := phase19SourceHeader(source)
	for _, tag := range []string{
		"integration",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
	} {
		if strings.Contains(header, tag) {
			t.Fatalf("phase50_final_code_only_verification_test.go uses build tag %q; final documentation guards must run under go test ./cmd", tag)
		}
	}
}

func TestPhase50FinalCodeOnlyVerificationDocPathStable(t *testing.T) {
	if got, want := phase50FinalCodeOnlyVerificationDocPath, "sandbox-runtime-v2-phase50-final-code-only-verification.md"; got != want {
		t.Fatalf("phase50 final code-only verification doc path = %q, want %q", got, want)
	}
}

func readPhase50FinalCodeOnlyVerificationDoc(t *testing.T) string {
	t.Helper()
	return phase50FinalReadFile(t, filepath.Join("..", "docs", "design", phase50FinalCodeOnlyVerificationDocPath))
}

func phase50FinalReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func phase50FinalAssertDocumentedDefaultCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase50FinalDocumentedDefaultCommandSet(doc)
	for _, want := range []string{
		"go test -count=1 ./internal/livegate -run 'Test(GateCategoryConstantsAreStable|LiveGateContractConstantsAreStable|LiveGateJSON|EvaluateGate|GatePreflight|RequireLiveGate|LiveGate)'",
		"go test -count=1 ./cmd -run 'TestPhase50(Default|Optional|Manual|Final|Live|Guard)'",
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"gofmt -l cmd internal main.go",
		"git diff --check",
		"golangci-lint run ./...",
	} {
		if !commands[want] {
			t.Fatalf("phase 50 final code-only verification documentation missing default command line %q", want)
		}
	}
}

func phase50FinalAssertDocumentedOptionalLiveCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase50FinalDocumentedOptionalLiveCommandSet(doc)
	for _, req := range phase50ManualLiveCommandRequirements() {
		if !commands[req.wantCommand] {
			t.Fatalf("phase 50 final code-only verification documentation missing optional manual live command line %q", req.wantCommand)
		}
	}
}

func phase50FinalDocumentedDefaultCommandSet(doc string) map[string]bool {
	commands := make(map[string]bool)
	for _, command := range phase50FinalDocumentedDefaultCommands(doc) {
		commands[command] = true
	}
	return commands
}

func phase50FinalDocumentedOptionalLiveCommandSet(doc string) map[string]bool {
	commands := make(map[string]bool)
	for _, command := range phase50FinalDocumentedOptionalLiveCommands(doc) {
		commands[command] = true
	}
	return commands
}

func phase50FinalFocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase50FinalDocumentedDefaultCommands(doc) {
		if strings.HasPrefix(command, "go test ") && strings.Contains(command, " -run ") {
			commands = append(commands, command)
		}
	}
	return commands
}

func phase50FinalDocumentedDefaultCommands(doc string) []string {
	return phase50FinalDocumentedCommandsInSection(doc, "Default Fake-Only Verification")
}

func phase50FinalDocumentedOptionalLiveCommands(doc string) []string {
	return phase50FinalDocumentedCommandsInSection(doc, "Optional Manual Live Verification")
}

func phase50FinalDocumentedCommandLines(doc string) []string {
	var commands []string
	for _, heading := range []string{"Default Fake-Only Verification", "Optional Manual Live Verification"} {
		commands = append(commands, phase50FinalDocumentedCommandsInSection(doc, heading)...)
	}
	return commands
}

func phase50FinalDocumentedCommandsInSection(doc, heading string) []string {
	section := phase50FinalMarkdownSection(doc, heading)
	var commands []string
	for _, raw := range strings.Split(section, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "env "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "go test "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "go vet "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "gofmt "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "git diff "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "golangci-lint "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "hal "):
			commands = append(commands, line)
		}
	}
	return commands
}

func phase50FinalMarkdownSection(doc, heading string) string {
	marker := "## " + heading
	start := strings.Index(doc, marker)
	if start < 0 {
		return ""
	}
	section := doc[start+len(marker):]
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	return section
}

func phase50FinalIsCodeOnlyCommand(command string) bool {
	switch {
	case strings.HasPrefix(command, "go test "):
		return true
	case strings.HasPrefix(command, "go vet "):
		return true
	case strings.HasPrefix(command, "gofmt "):
		return true
	case strings.HasPrefix(command, "git diff "):
		return true
	case strings.HasPrefix(command, "golangci-lint "):
		return true
	case strings.HasPrefix(command, "env ") && strings.Contains(command, " go test "):
		return true
	default:
		return false
	}
}

func phase50FinalForbiddenWorkflowMarkers() []string {
	return []string{
		"hal validate",
		"hal convert",
		"hal convert --granular",
		"hal plan",
		"hal auto",
		"hal run",
		"hal report",
	}
}

func phase50FinalForbiddenPlanningPhrases() []string {
	return []string{
		"prd regeneration",
		"prd audit",
		"prd validation",
	}
}

func phase50FinalForbiddenDocumentationMarker(doc string) string {
	lowerDoc := strings.ToLower(doc)
	for _, forbidden := range append(phase50FinalForbiddenWorkflowMarkers(), phase50FinalForbiddenPlanningPhrases()...) {
		if strings.Contains(lowerDoc, forbidden) {
			return forbidden
		}
	}
	return ""
}

func phase50FinalForbiddenDefaultCommandMarkers() []string {
	return append(phase49ForbiddenDefaultCommandMarkers(),
		"HAL_WORKER_INTEGRATION_LIVE",
		"HAL_PODMAN_INTEGRATION_LIVE",
		"env ",
	)
}

func phase50FinalRequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase50FinalFocusedTest("./internal/livegate", "internal/livegate/contracts_test.go", "TestLiveGateContractConstantsAreStable"),
		phase50FinalFocusedTest("./internal/livegate", "internal/livegate/contracts_test.go", "TestLiveGateJSONContainsOnlySafeContractFields"),
		phase50FinalFocusedTest("./internal/livegate", "internal/livegate/evaluator_test.go", "TestEvaluateGateMissingBuildTagReturnsSkipSafePreflightResult"),
		phase50FinalFocusedTest("./internal/livegate", "internal/livegate/evaluator_test.go", "TestGatePreflightResultJSONRedactsUnsafeDynamicValues"),
		phase50FinalFocusedTest("./internal/livegate", "internal/livegate/helpers_test.go", "TestRequireLiveGateMissingBuildTagSkipsWithSafeMessage"),
		phase50FinalFocusedTest("./internal/livegate", "internal/livegate/helpers_test.go", "TestLiveGateSkipAndRemediationOutputAreRedactionSafe"),
		phase50FinalFocusedTest("./internal/livegate", "internal/livegate/import_boundary_test.go", "TestLiveGateImportBoundaries"),
		{pkg: "./cmd", file: "phase50_default_live_gate_guard_test.go", testName: "TestPhase50DefaultGoTestSuiteDoesNotRequireLivePrerequisites"},
		{pkg: "./cmd", file: "phase50_default_live_gate_guard_test.go", testName: "TestPhase50OptionalLiveMarkersStayBehindBuildTagsOrApprovedFiles"},
		{pkg: "./cmd", file: "phase50_default_live_gate_guard_test.go", testName: "TestPhase50DefaultGuardRejectsUnsafeFixturePatterns"},
		{pkg: "./cmd", file: "phase50_default_live_gate_guard_test.go", testName: "TestPhase50LiveGatePackageStaysPureMetadataOnly"},
		{pkg: "./cmd", file: "phase50_optional_live_placeholders_test.go", testName: "TestPhase50OptionalLivePlaceholderTestsStayOutsideDefaultSuiteAndUseSharedGateHelpers"},
		{pkg: "./cmd", file: "phase50_manual_live_opt_in_docs_test.go", testName: "TestPhase50ManualLiveOptInDocumentation"},
		{pkg: "./cmd", file: "phase50_manual_live_opt_in_docs_test.go", testName: "TestPhase50ManualLiveOptInDoesNotDocumentDefaultOrPRDWorkflowCommands"},
		{pkg: "./cmd", file: "phase50_final_code_only_verification_test.go", testName: "TestPhase50FinalCodeOnlyVerificationDocumentation"},
		{pkg: "./cmd", file: "phase50_final_code_only_verification_test.go", testName: "TestPhase50FinalDefaultMatrixStaysFakeOnly"},
	}
}

func phase50FinalFocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}
