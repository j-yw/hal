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

func TestPhase25CredentialProxyVerificationDocs(t *testing.T) {
	doc := readPhase25CredentialProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase25-credential-proxy-plan-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 25 establishes the metadata-only and fake-only credential proxy plan foundation",
		"`internal/sandbox/credential_proxy.go`",
		"`internal/sandbox/credential_proxy_test.go`",
		"`internal/sandbox/credential_proxy_validation.go`",
		"`internal/sandbox/credential_proxy_normalization.go`",
		"`internal/sandbox/credential_proxy_sanitize.go`",
		"`internal/factory/secret_broker_credential_proxy.go`",
		"`internal/sandbox/credential_proxy_network_proxy.go`",
		"`internal/sandbox/credential_proxy_import_boundary_test.go`",
		"Credential proxy contracts",
		"Safe References",
		"Guard Coverage",
		"Unchanged JSON Surfaces",
		"Command JSON, run/auto manifest JSON, factory run record JSON, and factory timeline event JSON surfaces remain unchanged in Phase 25.",
		"No command, manifest, factory record, or timeline JSON surface gains credential proxy fields in Phase 25.",
		"`credentialProxy`, `credentialProxyPlan`, `credentialProxySession`, and `credentialProxyBindings`",
		"Phase 25 verification is fake-only.",
		"Phase 25 fake-only verification has no real network access, live proxy server, credential injection, tmpfs mount, SSH-agent forwarding, firewall mutation, Docker, Podman, KVM, cloud credentials, worker daemon, microVM, runtime/provider integration, or provider credential requirement.",
		"Default Phase 25 test commands must not use integration build tags or require live environment variables.",
		"No live proxying",
		"No credential injection",
		"No tmpfs delivery",
		"No SSH-agent forwarding",
		"No firewall enforcement",
		"No worker daemon changes",
		"No runtime/provider integration",
		"No command JSON surface changes",
		"No manifest JSON surface changes",
		"No factory record JSON surface changes",
		"No timeline JSON surface changes",
		"Future phases are responsible for live credential proxy delivery, credential injection, tmpfs delivery integration, SSH-agent forwarding integration, firewall enforcement integration, worker daemon support, concrete runtime/provider integration, and durable command/factory plumbing.",
		"go test -timeout=120s ./internal/sandbox -run 'TestCredentialProxy'",
		"go test -timeout=120s ./internal/factory -run 'TestCredentialProxyReferencesSecretBrokerMetadataBySafeIDs|TestCredentialProxySecretBrokerHelperDropsUnsafeSecretReferences'",
		"go test -timeout=120s ./cmd -run 'Test(RunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault|FactoryPersistenceOmitsCredentialProxyMetadataByDefault|Phase26CredentialProxy(PersistenceFieldsUseApprovedSurfaces|MetadataRejectedFromUnapprovedSurfaces|MetadataRejectedFromCommandResultEnvelopes)|Phase25CredentialProxy(VerificationDocs|FakeOnlyVerification))'",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"git diff --check",
		"make build",
		"make lint",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 25 credential proxy verification documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"live proxying is implemented",
		"live credential proxy delivery is implemented",
		"credential injection is implemented",
		"tmpfs delivery is implemented",
		"SSH-agent forwarding is implemented",
		"firewall enforcement is implemented",
		"worker daemon support is implemented",
		"runtime/provider integration is implemented",
		"command JSON surface changes are implemented",
		"manifest JSON surface changes are implemented",
		"factory record JSON surface changes are implemented",
		"timeline JSON surface changes are implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 25 credential proxy documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase25CredentialProxyFakeOnlyVerification(t *testing.T) {
	doc := readPhase25CredentialProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase25-credential-proxy-plan-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 25 verification is fake-only.",
		"Phase 25 fake-only verification has no real network access, live proxy server, credential injection, tmpfs mount, SSH-agent forwarding, firewall mutation, Docker, Podman, KVM, cloud credentials, worker daemon, microVM, runtime/provider integration, or provider credential requirement.",
		"Default Phase 25 test commands must not use integration build tags or require live environment variables.",
		"go test -timeout=120s ./cmd -run 'Test(RunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault|FactoryPersistenceOmitsCredentialProxyMetadataByDefault|Phase26CredentialProxy(PersistenceFieldsUseApprovedSurfaces|MetadataRejectedFromUnapprovedSurfaces|MetadataRejectedFromCommandResultEnvelopes)|Phase25CredentialProxy(VerificationDocs|FakeOnlyVerification))'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 25 credential proxy fake-only verification documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires real network access",
		"requires network access",
		"requires live proxy",
		"requires credential injection",
		"requires tmpfs",
		"requires SSH-agent",
		"requires firewall",
		"requires Docker",
		"requires Podman",
		"requires KVM",
		"requires cloud credentials",
		"requires worker daemon",
		"requires microVM",
		"requires runtime/provider integration",
		"requires provider credentials",
		"requires integration build tags",
		"requires live environment variables",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 25 credential proxy fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase25FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 25 credential proxy verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase25ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 25 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase25AssertFocusedVerificationCoversRequiredAreas(t, doc)

	for _, path := range phase25CredentialProxyDefaultTestFiles(t) {
		source := readPhase25CredentialProxyDoc(t, path)
		rel := phase25CredentialProxyDisplayPath(t, path)
		header := phase25CredentialProxySourceHeader(source)
		for _, tag := range []string{"integration", "worker_integration", "podman_integration"} {
			if strings.Contains(header, tag) {
				t.Fatalf("%s uses integration build tag %q; Phase 25 default credential proxy tests must stay fake-only", rel, tag)
			}
		}
		if phase25CredentialProxyRequiresLiveEnv(source) {
			t.Fatalf("%s requires live integration environment variables; Phase 25 default credential proxy tests must stay fake-only", rel)
		}
		phase25AssertDefaultTestFileAvoidsLiveImports(t, path)
	}
}

func readPhase25CredentialProxyDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase25FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase25ForbiddenFocusedCommandRequirements() []string {
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

func phase25AssertFocusedVerificationCoversRequiredAreas(t *testing.T, doc string) {
	t.Helper()
	commands := phase25FocusedGoTestCommands(doc)
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
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_test.go"),
			testName: "TestCredentialProxyJSONTagsAreStable",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_validation_test.go"),
			testName: "TestCredentialProxyValidationAcceptsSafeMetadata",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_validation_test.go"),
			testName: "TestCredentialProxyValidationErrorsDoNotExposeRejectedInputs",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_normalization_test.go"),
			testName: "TestCredentialProxyNormalizationTrimsIDFieldsBeforeValidation",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_sanitize_test.go"),
			testName: "TestCredentialProxySanitizeDoesNotExposeUnsafeValues",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_network_proxy_test.go"),
			testName: "TestCredentialProxyReferencesNetworkProxyMetadataBySafeIDs",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_import_boundary_test.go"),
			testName: "TestCredentialProxyImportBoundaries",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "credential_proxy_import_boundary_test.go"),
			testName: "TestCredentialProxyContractSourceOmitsLiveProxyBehaviorMarkers",
		},
		{
			pkg:      "./internal/factory",
			file:     filepath.Join("..", "internal", "factory", "secret_broker_credential_proxy_test.go"),
			testName: "TestCredentialProxyReferencesSecretBrokerMetadataBySafeIDs",
		},
		{
			pkg:      "./internal/factory",
			file:     filepath.Join("..", "internal", "factory", "secret_broker_credential_proxy_test.go"),
			testName: "TestCredentialProxySecretBrokerHelperDropsUnsafeSecretReferences",
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
			file:     "phase25_credential_proxy_docs_test.go",
			testName: "TestPhase25CredentialProxyFakeOnlyVerification",
		},
	}
	for _, req := range required {
		command := phase25FocusedCommandForPackage(t, commands, req.pkg)
		selector := phase25FocusedCommandRunSelector(t, command)
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 25 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if !compiled.MatchString(req.testName) {
			t.Fatalf("phase 25 focused command %q does not cover required test %s", command, req.testName)
		}
		source := readPhase25CredentialProxyDoc(t, req.file)
		if !strings.Contains(source, "func "+req.testName+"(") {
			t.Fatalf("%s does not define required Phase 25 verification test %s", phase25CredentialProxyDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase25FocusedCommandForPackage(t *testing.T, commands []string, pkg string) string {
	t.Helper()
	for _, command := range commands {
		for _, field := range strings.Fields(command) {
			if strings.Trim(field, "'\"") == pkg {
				return command
			}
		}
	}
	t.Fatalf("phase 25 verification documentation missing focused go test command for %s", pkg)
	return ""
}

func phase25FocusedCommandRunSelector(t *testing.T, command string) string {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 25 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\"")
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\"")
		}
	}
	t.Fatalf("phase 25 focused command %q missing -run selector", command)
	return ""
}

func phase25CredentialProxyDefaultTestFiles(t *testing.T) []string {
	t.Helper()
	patterns := []string{
		"phase25_credential_proxy_docs_test.go",
		"credential_proxy_manifest_test.go",
		filepath.Join("..", "internal", "sandbox", "credential_proxy*_test.go"),
		filepath.Join("..", "internal", "factory", "secret_broker_credential_proxy_test.go"),
	}
	var files []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("Glob(%s) error: %v", pattern, err)
		}
		if len(matches) == 0 {
			t.Fatalf("phase 25 fake-only guard pattern %s matched no files", pattern)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	return files
}

func phase25CredentialProxyDisplayPath(t *testing.T, path string) string {
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

func phase25CredentialProxySourceHeader(source string) string {
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

func phase25CredentialProxyRequiresLiveEnv(source string) bool {
	getenvCall := "os." + "Getenv"
	lookupEnvCall := "os." + "LookupEnv"
	if !strings.Contains(source, getenvCall) && !strings.Contains(source, lookupEnvCall) {
		return false
	}
	for _, marker := range phase25CredentialProxyLiveEnvironmentMarkers() {
		if strings.Contains(source, marker) {
			return true
		}
	}
	return false
}

func phase25CredentialProxyLiveEnvironmentMarkers() []string {
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

func phase25AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
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
		if forbidden := phase25CredentialProxyForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 25 default credential proxy tests must stay fake-only and avoid %s", phase25CredentialProxyDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase25CredentialProxyForbiddenDefaultTestImport(importPath string) string {
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
