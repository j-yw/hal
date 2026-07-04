package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	phase59RolloutDocPath = "sandbox-runtime-v2-phase59-templates-kits-rollout.md"

	phase59AcquisitionTrustFocusedCommand = "go test -count=1 -timeout=180s ./internal/sandboxtemplate ./internal/sandboxtemplate/acquisition -run 'Test(ClassifyTemplateSourceReference|TemplateSourceIntake|SandboxTemplateProduction|SandboxTemplateImportBoundary|SandboxTemplateAcquisition|TrustPolicy|EvaluateTrustPolicy|ProjectTemplateProvenance|ProjectRuntimeTemplateLockMetadata)'"
	phase59WorkerRuntimeFocusedCommand    = "go test -count=1 -timeout=180s ./internal/sandboxworker ./internal/sandboxruntime -run 'Test(US005(Worker|Runtime)|SandboxworkerImportsStayCommandAgnostic|SandboxworkerForbiddenImportListCoversCommandCouplingSurfaces|SandboxruntimeImportsStayCommandAgnostic|SandboxruntimeForbiddenImportListCoversCommandCouplingSurfaces)'"
	phase59ReadinessStatusFocusedCommand  = "go test -count=1 -timeout=180s ./internal/sandbox ./cmd -run 'Test(US006SelectedTemplate|US006RuntimeStatusProjectsSelectedTemplateTrustReadinessInput|US007(RuntimeStatusJSONSelectedTemplateStates|RuntimeListHumanOutputShowsTemplateTrustProvenanceAndBlockedReasons|RuntimeStatusHumanOutputShowsAbsentSelectedTemplate|SandboxStatusHumanOutputShowsSelectedTemplate)|Phase59)'"
)

func TestPhase59SandboxTemplateUserDocs(t *testing.T) {
	doc := readPhase59SandboxTemplateReadme(t)
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"Phase 59 selected-template semantics",
		"`selectedTemplate`",
		"`trustPolicy`",
		"`trusted`, `unresolved`, `rejected`, or `absent`",
		"local paths, Git URLs, and OCI/artifact references",
		"`local_file`",
		"`git`",
		"`oci_artifact`",
		"Fake-only acquisition",
		"Git and OCI acquisition use injected adapters/fakes in default verification",
		"does not clone Git repositories, fetch Git remotes, contact live OCI registries, use Docker or Podman, read cloud credentials, start worker daemons, start `hal sandboxd`, or run `hal run` as part of template acquisition.",
		"Templates alone do not prove deny-by-default network enforcement, credential delivery, live runtime isolation proof, or strict secure-default readiness.",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("%s missing required Phase 59 text %q", phase50SafeDisplayPath(phase59SandboxTemplateReadmePath()), want)
		}
	}
}

func TestPhase59RolloutVerificationDocumentation(t *testing.T) {
	doc := readPhase59RolloutDoc(t)
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"Phase 59 final rollout documentation and fake-only guard barrier for sandbox templates/kits.",
		"Default Phase 59 verification is fake-only.",
		"`internal/sandboxtemplate`",
		"`internal/sandboxtemplate/acquisition`",
		"`internal/sandboxworker`",
		"`internal/sandboxruntime`",
		"`cmd` and `internal/factory` remain projection, status, persistence, and formatting boundaries.",
		"Phase 59 does not choose, rank, prefer, or decide the global secure-default runtime or template.",
		"Templates alone do not prove deny-by-default network enforcement, credential delivery, live runtime isolation proof, or strict secure-default readiness.",
		"Optional live acquisition behavior is outside default verification.",
		"focused fake-only commands for template acquisition/trust, worker/runtime projection, secure-default readiness, and CLI/status UX",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("%s missing required Phase 59 text %q", phase50SafeDisplayPath(phase59RolloutDocFile()), want)
		}
	}
	phase59AssertDocumentedCommands(t, doc)
}

func TestPhase59DefaultCommandsStayFakeOnly(t *testing.T) {
	doc := readPhase59RolloutDoc(t)
	defaultCommands := phase54DefaultDocumentedCommands(doc)
	if len(defaultCommands) == 0 {
		t.Fatalf("%s must list default fake-only commands", phase50SafeDisplayPath(phase59RolloutDocFile()))
	}
	for _, command := range defaultCommands {
		if marker := phase59ForbiddenDefaultCommandMarker(command); marker != "" {
			t.Fatalf("%s default command %q contains forbidden live/default dependency marker %q", phase50SafeDisplayPath(phase59RolloutDocFile()), command, marker)
		}
	}
}

func TestPhase59OptionalLiveAcquisitionStaysOutsideDefaultVerification(t *testing.T) {
	doc := readPhase59RolloutDoc(t)
	if !strings.Contains(doc, "Optional live acquisition behavior is outside default verification.") {
		t.Fatalf("%s must document optional live acquisition outside default verification", phase50SafeDisplayPath(phase59RolloutDocFile()))
	}
	defaultCommands := map[string]bool{}
	for _, command := range phase54DefaultDocumentedCommands(doc) {
		defaultCommands[command] = true
	}
	for command := range phase54OptionalLiveDocumentedCommands(doc) {
		if defaultCommands[command] {
			t.Fatalf("optional live command %q also appeared in default Phase 59 commands", command)
		}
		if !strings.HasPrefix(command, "env ") || !strings.Contains(command, "-tags=") {
			t.Fatalf("optional live command %q must stay explicit, env-gated, and tagged", command)
		}
	}
}

func TestPhase59DocumentedFocusedSelectorsMatchTestsAndPackages(t *testing.T) {
	doc := readPhase59RolloutDoc(t)
	commands := phase59DefaultGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatalf("%s must list focused go test commands", phase50SafeDisplayPath(phase59RolloutDocFile()))
	}
	for _, command := range commands {
		runSelector, ok := phase54CommandRunSelector(command)
		if !ok || runSelector == "^$" {
			continue
		}
		packages := phase54CommandPackageSelectors(command)
		if len(packages) == 0 {
			t.Fatalf("%s focused go test command %q has no package selector", phase50SafeDisplayPath(phase59RolloutDocFile()), command)
		}
		for _, packageSelector := range packages {
			phase54AssertPackageSelectorExists(t, packageSelector, command)
			phase54AssertRunSelectorMatchesPackageTests(t, runSelector, packageSelector, command)
		}
	}
	for _, req := range phase59RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("Phase 59 documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 59 focused test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase59ImportBoundaryCoverageCoversRequiredPackages(t *testing.T) {
	doc := readPhase59RolloutDoc(t)
	for _, want := range []string{
		"`internal/sandboxtemplate` import boundary",
		"`internal/sandboxtemplate/acquisition` import boundary",
		"`internal/sandboxworker` import boundary",
		"`internal/sandboxruntime` import boundary",
		"`cmd` and `internal/factory` boundary",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing import-boundary coverage text %q", phase50SafeDisplayPath(phase59RolloutDocFile()), want)
		}
	}
}

func TestPhase59CommandAndFactoryBoundariesAvoidTemplateAcquisitionDecisions(t *testing.T) {
	for _, path := range phase59CommandFactoryProductionFiles(t) {
		source := phase50ReadFile(t, path)
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", phase50SafeDisplayPath(path), err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, phase50SafeDisplayPath(path), err)
			}
			if message := phase59CommandFactoryImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
		if message := phase59CommandFactorySourceBoundaryMessage(path, source); message != "" {
			t.Fatal(message)
		}
	}
}

func TestPhase59DocsAndStatusOutputDoNotOverclaimSecureDefaultSelection(t *testing.T) {
	sources := map[string]string{
		"phase59 rollout doc":             readPhase59RolloutDoc(t),
		"sandbox template README":         readPhase59SandboxTemplateReadme(t),
		"sandbox runtime command help":    phase50ReadFile(t, "sandbox_runtime.go"),
		"sandbox status command output":   phase50ReadFile(t, "sandbox_status.go"),
		"sandbox runtime list CLI docs":   phase50ReadFile(t, filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_list.md")),
		"sandbox runtime status CLI docs": phase50ReadFile(t, filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_status.md")),
		"sandbox status CLI docs":         phase50ReadFile(t, filepath.Join("..", "docs", "cli", "hal_sandbox_status.md")),
		"runtime status human output":     us007RuntimeStatusHuman(t, "phase59-status-human", us006CommandSelectedTemplateTrustedLock()),
		"runtime list human output":       us007RuntimeListHuman(t, "phase59-list-human", us006CommandSelectedTemplateUnresolvedLock()),
		"runtime status selected JSON":    phase59RuntimeStatusJSONOutput(t),
	}
	for label, source := range sources {
		if message := phase59OverclaimMessage(label, source); message != "" {
			t.Fatal(message)
		}
	}
}

func TestPhase59GuardRejectsUnsafeFixtures(t *testing.T) {
	for _, command := range []string{
		"go test -tags=template_acquisition ./internal/sandboxtemplate/acquisition",
		"docker ai run template-check",
		"docker pull docker.io/library/alpine",
		"podman run registry.example.invalid/template",
		"oras pull ghcr.io/acme/template:latest",
		"crane digest ghcr.io/acme/template:latest",
		"env AWS_ACCESS_KEY_ID=<set> go test ./...",
		"env HAL_TEMPLATE_REGISTRY_TOKEN=<set> go test ./...",
		"git clone https://example.invalid/template.git",
		"hal run --sandbox",
		"hal sandboxd",
	} {
		if marker := phase59ForbiddenDefaultCommandMarker(command); marker == "" {
			t.Fatalf("fixture command %q should fail Phase 59 default fake-only guard", command)
		}
	}

	for _, source := range []string{
		"Phase 59 selects the global secure-default runtime.",
		"Phase 59 ranks secure-default templates for operators.",
		"Templates alone provide deny-by-default network enforcement.",
		"Selected template provides credential delivery.",
		"Template trust satisfies strict secure-default readiness.",
	} {
		if message := phase59OverclaimMessage("fixture", source); message == "" {
			t.Fatalf("fixture source %q should fail Phase 59 overclaim guard", source)
		}
	}

	fixtureImportMessage := phase59CommandFactoryImportBoundaryMessage("fixture.go", "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition")
	if !strings.Contains(fixtureImportMessage, "template acquisition implementation") {
		t.Fatalf("fixture import boundary message = %q, want template acquisition implementation rejection", fixtureImportMessage)
	}
	fixtureSourceMessage := phase59CommandFactorySourceBoundaryMessage("fixture.go", `func f() { _ = EvaluateTrustPolicy }`)
	if !strings.Contains(fixtureSourceMessage, "EvaluateTrustPolicy") {
		t.Fatalf("fixture source boundary message = %q, want trust policy rejection", fixtureSourceMessage)
	}
}

func readPhase59RolloutDoc(t *testing.T) string {
	t.Helper()
	return phase50ReadFile(t, phase59RolloutDocFile())
}

func readPhase59SandboxTemplateReadme(t *testing.T) string {
	t.Helper()
	return phase50ReadFile(t, phase59SandboxTemplateReadmePath())
}

func phase59RolloutDocFile() string {
	return filepath.Join("..", "docs", "design", phase59RolloutDocPath)
}

func phase59SandboxTemplateReadmePath() string {
	return filepath.Join("..", "docs", "sandboxtemplate", "README.md")
}

func phase59AssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	for _, want := range []string{
		phase59AcquisitionTrustFocusedCommand,
		phase59WorkerRuntimeFocusedCommand,
		phase59ReadinessStatusFocusedCommand,
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	} {
		if !commands[want] {
			t.Fatalf("%s missing command line %q", phase50SafeDisplayPath(phase59RolloutDocFile()), want)
		}
	}
}

func phase59DefaultGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase54DefaultDocumentedCommands(doc) {
		if strings.HasPrefix(command, "go test ") {
			commands = append(commands, command)
		}
	}
	return commands
}

func phase59RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase59FocusedTest("./internal/sandboxtemplate", "internal/sandboxtemplate/import_boundary_test.go", "TestSandboxTemplateProductionImportsStayPure"),
		phase59FocusedTest("./internal/sandboxtemplate", "internal/sandboxtemplate/import_boundary_test.go", "TestSandboxTemplateImportBoundaryCoversProductionFiles"),
		phase59FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/source_intake_test.go", "TestClassifyTemplateSourceReferenceBuildsSourcesAndSafeStatus"),
		phase59FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/import_boundary_test.go", "TestSandboxTemplateAcquisitionProductionImportsStayFakeSafe"),
		phase59FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_import_boundary_test.go", "TestTrustPolicyProductionImportsStayDataOnly"),
		phase59FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictRejectsEveryRolloutPolicyCode"),
		phase59FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_runtime_projection_test.go", "TestProjectRuntimeTemplateLockMetadataSurfacesSanitizedTrustPolicyOutcome"),
		phase59FocusedTest("./internal/sandboxworker", "internal/sandboxworker/import_boundary_test.go", "TestSandboxworkerImportsStayCommandAgnostic"),
		phase59FocusedTest("./internal/sandboxworker", "internal/sandboxworker/template_metadata_projection_test.go", "TestUS005WorkerProtocolCarriesTemplateMetadataStates"),
		phase59FocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/import_boundary_test.go", "TestSandboxruntimeImportsStayCommandAgnostic"),
		phase59FocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/template_status_projection_test.go", "TestUS005RuntimeTemplateStatusProjectionStates"),
		phase59FocusedTest("./internal/sandbox", "internal/sandbox/security_capability_template_trust_readiness_test.go", "TestUS006SelectedTemplateTrustReadinessInput"),
		{pkg: "./cmd", file: "us006_template_trust_readiness_test.go", testName: "TestUS006RuntimeStatusProjectsSelectedTemplateTrustReadinessInput"},
		{pkg: "./cmd", file: "us007_operator_cli_template_status_test.go", testName: "TestUS007RuntimeStatusJSONSelectedTemplateStates"},
		{pkg: "./cmd", file: "us007_operator_cli_template_status_test.go", testName: "TestUS007RuntimeListHumanOutputShowsTemplateTrustProvenanceAndBlockedReasons"},
		{pkg: "./cmd", file: "phase59_templates_kits_rollout_docs_test.go", testName: "TestPhase59CommandAndFactoryBoundariesAvoidTemplateAcquisitionDecisions"},
		{pkg: "./cmd", file: "phase59_templates_kits_rollout_docs_test.go", testName: "TestPhase59DocsAndStatusOutputDoNotOverclaimSecureDefaultSelection"},
	}
}

func phase59FocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase59ForbiddenDefaultCommandMarker(command string) string {
	lower := strings.ToLower(command)
	for _, marker := range []string{
		"-tags=",
		"docker ai",
		"docker hub",
		"docker ",
		"podman ",
		"docker.sock",
		"/var/run/docker.sock",
		"registry login",
		"oras ",
		"crane ",
		"skopeo ",
		"cosign ",
		"aws_access_key_id",
		"google_application_credentials",
		"hcloud_token",
		"digitalocean_access_token",
		"github_token=",
		"token=",
		"secret=",
		"password=",
		"hal run",
		"hal sandboxd",
		"worker daemon",
		"live worker",
		"git clone",
		"git fetch",
		"git ls-remote",
		"curl ",
		"wget ",
		"http://",
		"https://",
		"ssh_auth_sock",
	} {
		if strings.Contains(lower, marker) {
			return marker
		}
	}
	return ""
}

func phase59CommandFactoryProductionFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, root := range []string{".", filepath.Join("..", "internal", "factory")} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("ReadDir(%s) error: %v", phase50SafeDisplayPath(root), err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			paths = append(paths, filepath.Join(root, name))
		}
	}
	if len(paths) == 0 {
		t.Fatal("Phase 59 command/factory boundary matched no production files")
	}
	sort.Strings(paths)
	return paths
}

func phase59CommandFactoryImportBoundaryMessage(fileName, importPath string) string {
	switch {
	case importPath == "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/"):
		return phase50SafeDisplayPath(fileName) + " imports forbidden template acquisition implementation package " + importPath
	case importPath == "github.com/jywlabs/hal/internal/sandboxtemplate" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxtemplate/"):
		return phase50SafeDisplayPath(fileName) + " imports forbidden template parsing/classification package " + importPath
	}
	lower := strings.ToLower(importPath)
	for _, marker := range []string{
		"github.com/go-git/",
		"github.com/libgit2/",
		"github.com/google/go-containerregistry",
		"oras.land/",
		"github.com/containerd/containerd/remotes",
		"github.com/regclient/regclient",
		"github.com/docker/docker",
		"github.com/containers/podman",
		"github.com/containers/image",
		"github.com/containers/storage",
		"github.com/containers/buildah",
	} {
		if strings.HasPrefix(lower, marker) {
			return phase50SafeDisplayPath(fileName) + " imports forbidden live template acquisition dependency " + importPath
		}
	}
	return ""
}

func phase59CommandFactorySourceBoundaryMessage(fileName, source string) string {
	for _, marker := range []string{
		"ClassifyTemplateSourceReference",
		"EvaluateTrustPolicy",
		"NewLocalResolver",
		"NewGitResolver",
		"NewOCIResolver",
		"ResolveOCIArtifact",
		"PlainClone",
		"remote.Get",
		"crane.Pull",
		"oras.Copy",
		"docker." + "NewClient",
		"/var/run/docker.sock",
		"docker.sock",
	} {
		if strings.Contains(source, marker) {
			return phase50SafeDisplayPath(fileName) + " contains forbidden Phase 59 command/factory acquisition or live dependency marker " + marker
		}
	}
	return ""
}

func phase59RuntimeStatusJSONOutput(t *testing.T) string {
	t.Helper()
	_, output := us007RuntimeStatusJSON(t, "phase59-status-json", us006CommandSelectedTemplateRejectedLock())
	return output
}

func phase59OverclaimMessage(label, source string) string {
	lower := strings.ToLower(strings.Join(strings.Fields(source), " "))
	for _, claim := range []string{
		"phase 59 selects the global secure-default",
		"phase 59 selects a global secure-default",
		"phase 59 ranks secure-default",
		"phase 59 prefers secure-default",
		"phase 59 decides the global secure-default",
		"globally selects a secure-default",
		"global secure-default runtime/template is selected",
		"template alone provides deny-by-default network enforcement",
		"templates alone provide deny-by-default network enforcement",
		"selected template provides deny-by-default network enforcement",
		"template trust provides credential delivery",
		"selected template provides credential delivery",
		"template proves live runtime isolation",
		"selected template proves live runtime isolation",
		"template lock proves live runtime isolation",
		"template alone satisfies strict secure-default readiness",
		"templates alone satisfy strict secure-default readiness",
		"selected template satisfies strict secure-default readiness",
		"template trust satisfies strict secure-default readiness",
	} {
		if strings.Contains(lower, claim) {
			return label + " contains forbidden Phase 59 secure-default overclaim " + strconv.Quote(claim)
		}
	}
	return ""
}
