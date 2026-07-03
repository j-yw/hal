package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase43CredentialDeliveryVerificationDocs(t *testing.T) {
	doc := readPhase43CredentialDeliveryDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 43 adds fake-safe credential delivery planning, activation, sanitized projection, and durable metadata surfaces for sandbox runtime v2.",
		"Phase 43 does not make credential delivery production-active by default.",
		"If Phase 42 network enforcement is absent, network/proxy-dependent delivery remains planning-only and must not be reported as active credential delivery.",
		"`internal/credentialdelivery` owns credential delivery contracts, normalization, validation, secret-resolution planning, fake activation adapters, sanitized activation results, and import-boundary guards.",
		"`internal/sandbox` owns durable public credential delivery status metadata.",
		"`internal/sandboxexecution.Manifest`, `internal/factory.SandboxMetadata`, `internal/sandboxruntime.RuntimeMetadata`, and `internal/sandboxworker.SecurityControls` can carry optional sanitized credential delivery metadata.",
		"Command wiring projects credential delivery status from safe credential proxy planning inputs for `hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox`.",
		"This command projection is plan-only: active modes are not projected unless an explicit sanitized activation result reports `active`.",
		"Legacy auth sync remains compatibility-only.",
		"go test -count=1 ./internal/credentialdelivery",
		"go test -count=1 ./internal/sandbox",
		"go test -count=1 ./internal/factory",
		"go test -count=1 ./internal/sandboxexecution",
		"go test -count=1 ./internal/sandboxruntime",
		"go test -count=1 ./internal/sandboxworker",
		"go test -count=1 ./cmd -run 'TestCredentialDelivery|TestCredentialProxyIntent|TestRunSandboxManifestPersistsSanitizedCredentialProxyMetadata|TestAutoSandboxManifestPersistsSanitizedCredentialProxyMetadata|TestRunFactorySandboxExecutorWithDepsPersistsCredentialProxyMetadata|TestPhase43CredentialDelivery'",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`golangci-lint run ./...` only when `golangci-lint` is installed.",
		"If it is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Passing this matrix satisfies the Phase 43 tests and typecheck gates.",
		"Phase 43 does not implement real proxy servers, upstream API calls, tmpfs mounts, SSH-agent forwarding, environment secret injection, provider credentials, templates/kits, OCI template acquisition, real credential broker delivery, real credential injection, host firewall changes, production microVM egress, guest network configuration, provider/runtime live integration, or live E2E credential-delivery verification.",
		"Active modes are projected only from sanitized activation results that explicitly report active status.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 43 credential delivery verification documentation missing %q", want)
		}
	}

	phase43AssertVerificationCommands(t, doc)
	phase43AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"real proxy servers are implemented",
		"upstream API calls are implemented",
		"tmpfs mounts are implemented",
		"SSH-agent forwarding is implemented",
		"environment secret injection is implemented",
		"provider credentials are implemented",
		"templates/kits are implemented",
		"real credential broker delivery is implemented",
		"real credential injection is implemented",
		"production microVM egress is implemented",
		"live E2E credential-delivery verification is implemented",
		"requested modes prove active credential delivery",
		"legacy auth sync proves active credential delivery",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 43 credential delivery documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase43CredentialDeliveryFakeOnlyVerification(t *testing.T) {
	doc := readPhase43CredentialDeliveryDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 43 verification is fake-only.",
		"Phase 43 verification is fake-only. It does not require real network access, real proxy servers, upstream API calls, tmpfs mounts, SSH-agent forwarding, environment secret injection, provider credentials, templates/kits, Docker, Podman, KVM, Firecracker, root privileges, cloud credentials, worker daemons, provider/runtime live integration, a live guest, guest-agent transport, vsock, or a running `hal sandboxd`.",
		"Default Phase 43 tests use pure DTOs, deterministic planner inputs, sanitized public JSON assertions, fake activation adapters, source guards, parsed imports, command-boundary fakes, temporary state directories, and explicit metadata only.",
		"Default Phase 43 verification must not use integration build tags, require live environment variables, start real proxy servers, bind listener sockets, perform upstream API calls, create tmpfs mounts, forward an SSH agent, inject environment secrets, read provider credentials, run template or kit acquisition, start worker daemons, run `hal sandboxd`, start Firecracker, access KVM, require root, call Docker or Podman, contact cloud APIs, or depend on live providers or runtime adapters.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 43 credential delivery fake-only documentation missing %q", want)
		}
	}

	commands := phase43DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 43 credential delivery verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase43ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 43 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase43AssertFocusedVerificationCoversRequiredSelectors(t, doc)
}

func readPhase43CredentialDeliveryDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase43-credential-delivery-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 43 credential delivery verification doc) error: %v", err)
	}
	return string(data)
}

func phase43DefaultFocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "./...") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase43AssertVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 ./internal/credentialdelivery",
		"go test -count=1 ./internal/sandbox",
		"go test -count=1 ./internal/factory",
		"go test -count=1 ./internal/sandboxexecution",
		"go test -count=1 ./internal/sandboxruntime",
		"go test -count=1 ./internal/sandboxworker",
		"go test -count=1 ./cmd -run 'TestCredentialDelivery|TestCredentialProxyIntent|TestRunSandboxManifestPersistsSanitizedCredentialProxyMetadata|TestAutoSandboxManifestPersistsSanitizedCredentialProxyMetadata|TestRunFactorySandboxExecutorWithDepsPersistsCredentialProxyMetadata|TestPhase43CredentialDelivery'",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 43 credential delivery verification documentation missing command line %q", want)
		}
	}
}

func phase43AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase43DefaultFocusedGoTestCommands(doc)
	for _, req := range phase43RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 43 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 43 verification test %s", req.file, req.testName)
		}
	}
}

func phase43RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/credentialdelivery", file: filepath.Join("..", "internal", "credentialdelivery", "projection_test.go"), testName: "TestStatusMetadataFromPlanDoesNotProjectActiveModes"},
		{pkg: "./internal/credentialdelivery", file: filepath.Join("..", "internal", "credentialdelivery", "projection_test.go"), testName: "TestStatusMetadataFromActivationProjectsActiveModesOnlyForActiveResult"},
		{pkg: "./cmd", file: "credential_delivery_projection_test.go", testName: "TestCredentialDeliveryProjectionAcrossRunAutoAndFactoryIsPlanOnly"},
		{pkg: "./cmd", file: "credential_delivery_projection_test.go", testName: "TestCredentialDeliveryProjectionRepresentsLegacyAuthSyncAsRequestedOnly"},
		{pkg: "./cmd", file: "credential_delivery_projection_test.go", testName: "TestCredentialProxyIntentKeepsLegacyAuthSyncRequestedOnly"},
		{pkg: "./cmd", file: "credential_delivery_redaction_test.go", testName: "TestCredentialDeliveryRedactionAcrossDurableSurfaces"},
		{pkg: "./cmd", file: "credential_delivery_redaction_test.go", testName: "TestCredentialDeliveryActivationRedactionForSuccessAndFailure"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeMetadataIncludesOptionalCredentialDeliveryMetadata"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "types_test.go"), testName: "TestWorkerSecurityControlsCarryOptionalCredentialDeliveryMetadata"},
		{pkg: "./cmd", file: "phase43_credential_delivery_docs_test.go", testName: "TestPhase43CredentialDeliveryVerificationDocs"},
		{pkg: "./cmd", file: "phase43_credential_delivery_docs_test.go", testName: "TestPhase43CredentialDeliveryFakeOnlyVerification"},
	}
}

func phase43ForbiddenDefaultFocusedCommandRequirements() []string {
	return []string{
		"integration",
		"firecracker_live",
		"podman_integration",
		"worker_integration",
		"HAL_",
		"DOCKER_",
		"PODMAN_",
		"KVM",
		"SSH_AUTH_SOCK",
	}
}
