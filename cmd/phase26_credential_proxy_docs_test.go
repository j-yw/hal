package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestPhase26CredentialProxyVerificationDocs(t *testing.T) {
	doc := readPhase26CredentialProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase26-credential-proxy-plumbing-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 26 adds additive, sanitized, metadata-only credential proxy plumbing",
		"`internal/sandboxexecution.Manifest`",
		"`internal/factory.SandboxMetadata`",
		"`credentialProxyPlan`",
		"`credentialProxySession`",
		"`credentialProxyBindings`",
		"Phase 26 does not add a standalone `credentialProxy` field.",
		"Non-factory `hal run --sandbox` and `hal auto --sandbox` manifests project credential proxy metadata from safe command-boundary inputs only",
		"Factory sandbox metadata projects from safe factory-side metadata only",
		"Factory timeline events do not add or mirror credential proxy plan, session, or binding metadata.",
		"Command result envelopes, worker metadata, runtime metadata, provider metadata, and factory timeline event records remain free of direct Phase 26 credential proxy persistence fields.",
		"Legacy manifests, factory run records, and factory timeline events without credential proxy metadata must continue to load and round-trip without adding credential proxy fields by default.",
		"schema, projection, persistence, redaction, compatibility, guard, and documentation coverage",
		"Phase 26 verification is fake-only.",
		"Phase 26 fake-only verification has no real network access, live proxy server, credential delivery, credential injection, tmpfs mount, SSH-agent forwarding, firewall mutation, network enforcement, Docker, Podman, KVM, cloud credentials, worker daemon, microVM, runtime/provider integration, live credential proxy support, or provider credential requirement.",
		"Default Phase 26 test commands must not use integration build tags or require live environment variables.",
		"No live credential delivery",
		"No credential injection",
		"No live proxy server",
		"No network enforcement",
		"No firewall enforcement",
		"No tmpfs delivery",
		"No SSH-agent forwarding",
		"No worker daemon support",
		"No runtime support",
		"No provider integration",
		"No command-result envelope credential proxy fields",
		"No factory timeline credential proxy fields",
		"No credential proxy support beyond metadata projection",
		"go test -timeout=120s ./internal/sandbox -run 'TestCredentialProxy|TestProjectSandboxCredentialProxyMetadata'",
		"go test -timeout=120s ./internal/sandboxexecution -run 'TestManifestJSONFieldsAndSandboxMetadataTypes|TestManifestUnmarshalWithoutArtifactMetadata'",
		"go test -timeout=120s ./internal/factory -run 'Test(CredentialProxy|ProjectCredentialProxy|FactoryCredentialProxy|SandboxMetadataCredentialProxy)'",
		"go test -timeout=120s ./cmd -run 'Test(RunSandboxManifestPersistsSanitizedCredentialProxyMetadata|RunSandboxCredentialProxyManifestSanitizesProjectionBeforePersistence|AutoSandboxManifest(PersistsSanitizedCredentialProxyMetadata|OmitsCredentialProxyMetadataWithoutSafeSources)|AutoSandboxCredentialProxyMetadataStaysOutOfJSONOutput|RunFactorySandboxExecutorWithDepsPersistsSanitizedCredentialProxyMetadata|RunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault|FactoryPersistenceOmitsCredentialProxyMetadataByDefault|Phase26CredentialProxy(LegacyJSONCompatibility|UnsafeFixtureEnumeratesRequiredValueClasses|PersistenceFieldsUseApprovedSurfaces|MetadataRejectedFromUnapprovedSurfaces|MetadataRejectedFromCommandResultEnvelopes|FactoryTimeline(OmissionAfterSanitization|PersistenceAndRenderingOmitMetadata|DocsStateOmission)|Plumbing(GuardsCoverProductionFiles|ImportBoundaries|ForbiddenImportListCoversLiveBehaviorDependencies|ImportBoundaryAllowsCurrentMetadataOnlyDependencies|SourceGuardsOmitLiveBehaviorMarkers|SourceGuardCoversForbiddenMarkers|SourceGuardAllowsSafeMetadataLabels)|VerificationDocs|FakeOnlyVerification))'",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"git diff --check",
		"make build",
		"make lint",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 26 credential proxy verification documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"live credential delivery is implemented",
		"credential injection is implemented",
		"live proxy server is implemented",
		"network enforcement is implemented",
		"firewall enforcement is implemented",
		"tmpfs delivery is implemented",
		"SSH-agent forwarding is implemented",
		"worker daemon support is implemented",
		"runtime support is implemented",
		"provider integration is implemented",
		"command-result envelope credential proxy fields are implemented",
		"factory timeline credential proxy fields are implemented",
		"credential proxy support is implemented",
		"live credential proxy support is implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 26 credential proxy documentation makes unsupported implementation claim %q", claim)
		}
	}

	phase26AssertFocusedVerificationCoversRequiredAreas(t, doc)
}

func TestPhase26CredentialProxyFakeOnlyVerification(t *testing.T) {
	doc := readPhase26CredentialProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase26-credential-proxy-plumbing-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 26 verification is fake-only.",
		"Phase 26 fake-only verification has no real network access, live proxy server, credential delivery, credential injection, tmpfs mount, SSH-agent forwarding, firewall mutation, network enforcement, Docker, Podman, KVM, cloud credentials, worker daemon, microVM, runtime/provider integration, live credential proxy support, or provider credential requirement.",
		"Default Phase 26 test commands must not use integration build tags or require live environment variables.",
		"go test -timeout=120s ./cmd -run 'Test(RunSandboxManifestPersistsSanitizedCredentialProxyMetadata|RunSandboxCredentialProxyManifestSanitizesProjectionBeforePersistence|AutoSandboxManifest(PersistsSanitizedCredentialProxyMetadata|OmitsCredentialProxyMetadataWithoutSafeSources)|AutoSandboxCredentialProxyMetadataStaysOutOfJSONOutput|RunFactorySandboxExecutorWithDepsPersistsSanitizedCredentialProxyMetadata|RunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault|FactoryPersistenceOmitsCredentialProxyMetadataByDefault|Phase26CredentialProxy(LegacyJSONCompatibility|UnsafeFixtureEnumeratesRequiredValueClasses|PersistenceFieldsUseApprovedSurfaces|MetadataRejectedFromUnapprovedSurfaces|MetadataRejectedFromCommandResultEnvelopes|FactoryTimeline(OmissionAfterSanitization|PersistenceAndRenderingOmitMetadata|DocsStateOmission)|Plumbing(GuardsCoverProductionFiles|ImportBoundaries|ForbiddenImportListCoversLiveBehaviorDependencies|ImportBoundaryAllowsCurrentMetadataOnlyDependencies|SourceGuardsOmitLiveBehaviorMarkers|SourceGuardCoversForbiddenMarkers|SourceGuardAllowsSafeMetadataLabels)|VerificationDocs|FakeOnlyVerification))'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 26 credential proxy fake-only verification documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires real network access",
		"requires network access",
		"requires live proxy",
		"requires credential delivery",
		"requires credential injection",
		"requires tmpfs",
		"requires SSH-agent",
		"requires firewall",
		"requires network enforcement",
		"requires Docker",
		"requires Podman",
		"requires KVM",
		"requires cloud credentials",
		"requires worker daemon",
		"requires microVM",
		"requires runtime/provider integration",
		"requires live credential proxy support",
		"requires provider credentials",
		"requires integration build tags",
		"requires live environment variables",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 26 credential proxy fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase26FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 26 credential proxy verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase26ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 26 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase26AssertFocusedVerificationCoversRequiredAreas(t, doc)

	for _, path := range phase26CredentialProxyDefaultTestFiles(t) {
		source := readPhase26CredentialProxyDoc(t, path)
		rel := phase26CredentialProxyDisplayPath(t, path)
		header := phase26CredentialProxySourceHeader(source)
		for _, tag := range []string{"integration", "worker_integration", "podman_integration"} {
			if strings.Contains(header, tag) {
				t.Fatalf("%s uses integration build tag %q; Phase 26 default credential proxy tests must stay fake-only", rel, tag)
			}
		}
		if phase26CredentialProxyRequiresLiveEnv(source) {
			t.Fatalf("%s requires live integration environment variables; Phase 26 default credential proxy tests must stay fake-only", rel)
		}
		phase26AssertDefaultTestFileAvoidsLiveImports(t, path)
	}
}

func readPhase26CredentialProxyDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase26FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase26ForbiddenFocusedCommandRequirements() []string {
	return []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"worker_integration",
		"podman_integration",
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"DOCKER_HOST",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"docker ",
		"podman ",
		"curl ",
		"hal sandboxd",
		"--live",
	}
}

func phase26AssertFocusedVerificationCoversRequiredAreas(t *testing.T, doc string) {
	t.Helper()
	commands := phase26FocusedGoTestCommands(doc)
	required := []struct {
		pkg      string
		file     string
		testName string
	}{
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_test.go"),
			testName: "TestCredentialProxyContractConstants",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_validation_test.go"),
			testName: "TestCredentialProxyValidationErrorsDoNotExposeRejectedInputs",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_sanitize_test.go"),
			testName: "TestCredentialProxySanitizeDoesNotExposeUnsafeValues",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_projection_test.go"),
			testName: "TestProjectSandboxCredentialProxyMetadataProjectsSafeNetworkProxyAndSecurityIntent",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_import_boundary_test.go"),
			testName: "TestCredentialProxyImportBoundaries",
		},
		{
			pkg:      "./internal/sandboxexecution",
			file:     filepath.Join("..", "internal", "sandboxexecution", "types_test.go"),
			testName: "TestManifestJSONFieldsAndSandboxMetadataTypes",
		},
		{
			pkg:      "./internal/factory",
			file:     filepath.Join("..", "internal", "factory", "types_test.go"),
			testName: "TestSandboxMetadataCredentialProxyMetadataTypesAndJSONShape",
		},
		{
			pkg:      "./internal/factory",
			file:     filepath.Join("..", "internal", "factory", "secret_broker_credential_proxy_test.go"),
			testName: "TestProjectCredentialProxyMetadataFromSafeSecretBrokerNetworkAndSecurityIntent",
		},
		{
			pkg:      "./internal/factory",
			file:     filepath.Join("..", "internal", "factory", "types_test.go"),
			testName: "TestFactoryCredentialProxyLegacyRecordsAndEventsLoadWithoutMetadata",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_credential_proxy_test.go",
			testName: "TestRunSandboxManifestPersistsSanitizedCredentialProxyMetadata",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_credential_proxy_test.go",
			testName: "TestRunSandboxCredentialProxyManifestSanitizesProjectionBeforePersistence",
		},
		{
			pkg:      "./cmd",
			file:     "auto_sandbox_credential_proxy_test.go",
			testName: "TestAutoSandboxManifestPersistsSanitizedCredentialProxyMetadata",
		},
		{
			pkg:      "./cmd",
			file:     "auto_sandbox_credential_proxy_test.go",
			testName: "TestAutoSandboxCredentialProxyMetadataStaysOutOfJSONOutput",
		},
		{
			pkg:      "./cmd",
			file:     "factory_sandbox_executor_test.go",
			testName: "TestRunFactorySandboxExecutorWithDepsPersistsSanitizedCredentialProxyMetadata",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestRunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestFactoryPersistenceOmitsCredentialProxyMetadataByDefault",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyLegacyJSONCompatibility",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_phase26_fixture_test.go",
			testName: "TestPhase26CredentialProxyUnsafeFixtureEnumeratesRequiredValueClasses",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyPersistenceFieldsUseApprovedSurfaces",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyMetadataRejectedFromUnapprovedSurfaces",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyMetadataRejectedFromCommandResultEnvelopes",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyFactoryTimelineOmissionAfterSanitization",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyPlumbingGuardsCoverProductionFiles",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyPlumbingImportBoundaries",
		},
		{
			pkg:      "./cmd",
			file:     "credential_proxy_manifest_test.go",
			testName: "TestPhase26CredentialProxyPlumbingSourceGuardsOmitLiveBehaviorMarkers",
		},
		{
			pkg:      "./cmd",
			file:     "phase26_credential_proxy_docs_test.go",
			testName: "TestPhase26CredentialProxyVerificationDocs",
		},
		{
			pkg:      "./cmd",
			file:     "phase26_credential_proxy_docs_test.go",
			testName: "TestPhase26CredentialProxyFakeOnlyVerification",
		},
	}
	for _, req := range required {
		command := phase26FocusedCommandForPackage(t, commands, req.pkg)
		selector := phase26FocusedCommandRunSelector(t, command)
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 26 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if !compiled.MatchString(req.testName) {
			t.Fatalf("phase 26 focused command %q does not cover required test %s", command, req.testName)
		}
		source := readPhase26CredentialProxyDoc(t, req.file)
		if !strings.Contains(source, "func "+req.testName+"(") {
			t.Fatalf("%s does not define required Phase 26 verification test %s", phase26CredentialProxyDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase26FocusedCommandForPackage(t *testing.T, commands []string, pkg string) string {
	t.Helper()
	for _, command := range commands {
		for _, field := range strings.Fields(command) {
			if strings.Trim(field, "'\"") == pkg {
				return command
			}
		}
	}
	t.Fatalf("phase 26 verification documentation missing focused go test command for %s", pkg)
	return ""
}

func phase26FocusedCommandRunSelector(t *testing.T, command string) string {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 26 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\"")
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\"")
		}
	}
	t.Fatalf("phase 26 focused command %q missing -run selector", command)
	return ""
}

func phase26CredentialProxyDefaultTestFiles(t *testing.T) []string {
	t.Helper()
	patterns := []string{
		"phase26_credential_proxy_docs_test.go",
		"credential_proxy_manifest_test.go",
		"credential_proxy_phase26_fixture_test.go",
		"run_sandbox_credential_proxy_test.go",
		"auto_sandbox_credential_proxy_test.go",
		filepath.Join("..", "internal", "sandbox", "credential_proxy*_test.go"),
		filepath.Join("..", "internal", "sandboxexecution", "types_test.go"),
		filepath.Join("..", "internal", "factory", "secret_broker_credential_proxy_test.go"),
		filepath.Join("..", "internal", "factory", "types_test.go"),
	}
	var files []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("Glob(%s) error: %v", pattern, err)
		}
		if len(matches) == 0 {
			t.Fatalf("phase 26 fake-only guard pattern %s matched no files", pattern)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	return files
}

func phase26CredentialProxyDisplayPath(t *testing.T, path string) string {
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

func phase26CredentialProxySourceHeader(source string) string {
	lines := strings.Split(source, "\n")
	var header []string
	for _, line := range lines {
		if strings.HasPrefix(line, "package ") {
			break
		}
		header = append(header, line)
	}
	return strings.Join(header, "\n")
}

func phase26CredentialProxyRequiresLiveEnv(source string) bool {
	getenvCall := "os." + "Getenv"
	lookupEnvCall := "os." + "LookupEnv"
	if !strings.Contains(source, getenvCall) && !strings.Contains(source, lookupEnvCall) {
		return false
	}
	for _, marker := range phase26CredentialProxyLiveEnvironmentMarkers() {
		if strings.Contains(source, marker) {
			return true
		}
	}
	return false
}

func phase26CredentialProxyLiveEnvironmentMarkers() []string {
	return []string{
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"DOCKER_HOST",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"CLOUDSDK_",
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
	}
}

func phase26AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
		}
		if forbidden := phase26CredentialProxyForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 26 default credential proxy tests must stay fake-only and avoid %s", phase26CredentialProxyDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase26CredentialProxyForbiddenDefaultTestImport(importPath string) string {
	switch importPath {
	case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
		return "network clients or live proxy servers"
	case "os/exec":
		return "process execution"
	}
	for _, forbidden := range []struct {
		prefix string
		label  string
	}{
		{prefix: "github.com/docker/docker", label: "Docker clients"},
		{prefix: "github.com/containers/podman", label: "Podman clients"},
		{prefix: "github.com/digitalocean/godo", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go-v2", label: "cloud SDKs"},
		{prefix: "github.com/Azure/azure-sdk-for-go", label: "cloud SDKs"},
		{prefix: "github.com/hetznercloud/hcloud-go", label: "cloud SDKs"},
		{prefix: "cloud.google.com/go", label: "cloud SDKs"},
		{prefix: "google.golang.org/api", label: "cloud SDKs"},
		{prefix: "google.golang.org/grpc", label: "network clients"},
		{prefix: "golang.org/x/net/proxy", label: "HTTP proxy implementations"},
		{prefix: "golang.org/x/crypto/ssh", label: "SSH or SSH-agent implementations"},
		{prefix: "github.com/firecracker-microvm", label: "microVM integrations"},
		{prefix: "libvirt.org/go/libvirt", label: "KVM or microVM integrations"},
	} {
		if strings.HasPrefix(importPath, forbidden.prefix) {
			return forbidden.label
		}
	}
	return ""
}
