package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase40MicroVMGuestAgentTransportVerificationDocs(t *testing.T) {
	doc := readPhase40MicroVMGuestAgentTransportDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 40 adds a conservative guest-agent transport foundation for Firecracker microVM readiness, exec, copy-in, and copy-out.",
		"`internal/sandboxruntime/microvm/guestagent` owns the versioned guest-agent protocol contract.",
		"The stable protocol version is `guest-agent-v1`, with operation identifiers for `readiness`, `exec`, `copy_in`, and `copy_out`.",
		"Environment values, credential values, host paths, URLs, headers, request bodies, and Docker socket details are not protocol fields.",
		"The guest-agent client dispatches readiness, exec, copy-in, and copy-out only through an injected `guestagent.Transport`.",
		"It does not call Firecracker APIs, use SSH, shell out, open the host Docker socket, or start guest processes.",
		"`GuestAgentTransport` satisfies the existing `firecracker.GuestTransport` interface and translates Firecracker guest exec and copy requests into guest-agent protocol requests.",
		"Exec stdin, copy-in, and copy-out payloads are bounded and base64 encoded on the JSON wire.",
		"Copy-in sends only the guest destination path plus bounded payload content.",
		"Copy-out sends only the guest source path and receives bounded payload content.",
		"Host-local copy paths and raw environment values do not cross the protocol boundary.",
		"`GuestAgentReadinessProbe` adapts guest-agent readiness responses onto the existing Firecracker guest readiness probe boundary.",
		"`hal sandboxd` exposes optional guest-agent wiring through `--firecracker-guest-agent-endpoint`.",
		"The configured endpoint must be a local Unix socket endpoint.",
		"Default microVM support remains lifecycle-only.",
		"A configured guest-agent endpoint builds compatibility and test client adapters, but it does not authorize capability advertisement.",
		"Exec, copy-in, and copy-out remain omitted until an exact readiness handshake proves the server contract.",
		"Host Docker socket access is not part of Phase 40.",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/guestagent",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase4[0].*MicroVM|Phase4[0].*Firecracker|Sandboxd.*MicroVM|GuestTransport|GuestReadiness'",
		"go test -count=1 -timeout=180s ./internal/sandboxworker",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`golangci-lint run ./...` only when `golangci-lint` is installed.",
		"If it is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Passing this matrix satisfies the Phase 40 tests and typecheck gates.",
		"Phase 40 does not implement a production guest agent, concrete vsock transport, SSH transport, Docker or Podman guest engine, Firecracker SDK integration, machine configuration API calls, image/rootfs/kernel provisioning, workspace sync, credential broker/proxy delivery, network proxy/firewall enforcement, deny-by-default guest networking, jailer/root setup, cgroups, default command enablement, default worker routing, default scheduler selection, or default live E2E guest exec and copy verification.",
		"L4 is responsible for the production Linux guest-agent server behind injected transport boundaries.",
		"L5 is responsible for vsock and image integration, live transport binding, guest boot/readiness proof, capability activation, and operator documentation for preparing guest images.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 40 microVM guest-agent transport verification documentation missing %q", want)
		}
	}

	phase40AssertVerificationCommands(t, doc)
	phase40AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"default microVM support includes exec",
		"default microVM support includes copy",
		"default microVM workers advertise exec",
		"default microVM workers advertise copy",
		"sandboxd microVM drivers without a configured guest-agent endpoint advertise exec",
		"sandboxd microVM drivers without a configured guest-agent endpoint advertise copy",
		"production guest agent is implemented",
		"concrete vsock transport is implemented",
		"SSH transport is implemented",
		"Docker or Podman guest engine is implemented",
		"Firecracker SDK integration is implemented",
		"machine configuration API calls are implemented",
		"network proxy/firewall enforcement is implemented",
		"default live E2E guest exec and copy verification is implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 40 microVM guest-agent transport documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase40MicroVMGuestAgentTransportFakeSafeVerification(t *testing.T) {
	doc := readPhase40MicroVMGuestAgentTransportDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 40 verification is fake-safe and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, provider/runtime integration, host-specific kernel or rootfs images, a live guest, a guest agent, vsock, SSH, or a running `hal sandboxd`.",
		"Default Phase 40 tests use pure protocol DTOs, injected fake guest-agent transports, fake guest readiness probes, fake command dependencies, parsed imports, source guards, JSON redaction assertions, temporary state directories, and optional endpoint validation only.",
		"Default Phase 40 verification must not use integration build tags, the `firecracker_live` build tag, require live environment variables, start a real Firecracker process, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 40 microVM guest-agent transport fake-safe documentation missing %q", want)
		}
	}

	commands := phase40DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 40 microVM guest-agent transport verification documentation must list default focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase36ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 40 default focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase40AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase40AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func readPhase40MicroVMGuestAgentTransportDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase40-microvm-guest-agent-transport-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 40 microVM guest-agent transport verification doc) error: %v", err)
	}
	return string(data)
}

func phase40DefaultFocusedGoTestCommands(doc string) []string {
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

func phase40AssertVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/guestagent",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase4[0].*MicroVM|Phase4[0].*Firecracker|Sandboxd.*MicroVM|GuestTransport|GuestReadiness'",
		"go test -count=1 -timeout=180s ./internal/sandboxworker",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 40 microVM guest-agent transport verification documentation missing command line %q", want)
		}
	}
}

func phase40AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase40DefaultFocusedGoTestCommands(doc)
	for _, req := range phase40RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 40 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 40 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase40RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts_test.go"), testName: "TestProtocolContractConstants"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts_test.go"), testName: "TestProtocolDTOJSONShapes"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts_test.go"), testName: "TestProtocolDTOsDoNotCarryRawEnvironmentValues"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "validation_test.go"), testName: "TestValidateProtocolRequestsAndResponsesAcceptValidContracts"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "validation_test.go"), testName: "TestProtocolErrorsAreRedactionSafeInStringsAndJSON"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "client_test.go"), testName: "TestClientUsesFakeTransportForReadinessExecAndCopyRequests"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "client_test.go"), testName: "TestClientReturnsRedactionSafePublicErrors"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "import_boundary_test.go"), testName: "TestGuestAgentProtocolProductionImportsStayDataOnly"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "import_boundary_test.go"), testName: "TestGuestAgentForbiddenImportListCoversRequiredBoundaries"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_transport_test.go"), testName: "TestGuestTransportInterfaceIncludesExecCopyInAndCopyOut"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_transport_test.go"), testName: "TestGuestTransportRequestsOmitRawBoundaryDataFromJSON"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase38_default_behavior_test.go"), testName: "TestPhase38DefaultPlanningBackendDoesNotExposeLiveGuestTransportMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase38_exec_delegation_test.go"), testName: "TestPhase38FirecrackerExecRequiresLiveGuestTransportAndReadyGuestReadiness"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportSatisfiesFirecrackerGuestTransport"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportExecDelegatesBoundedProtocolRequestAndPropagatesOutput"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportCopyInSendsBoundedHostSourceBytes"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportCopyOutWritesBoundedGuestPayloadBytes"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportExecRejectsOversizedStdinBeforeDispatch"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportCopyInRejectsUnsafeOrOversizedSourceBeforeDispatch"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportCopyOutRejectsMalformedPayloadBeforeWritingDestination"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"), testName: "TestGuestAgentTransportErrorsAreRedactionSafe"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_endpoint_test.go"), testName: "TestNewGuestAgentEndpointAdaptersBuildTransportAndReadinessProbe"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_endpoint_test.go"), testName: "TestNewGuestAgentEndpointAdaptersIsOptional"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_endpoint_test.go"), testName: "TestValidateGuestAgentEndpointRejectsUnsafeEndpointWithoutRawDetails"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_agent_unix_transport_test.go"), testName: "TestGuestAgentUnixSocketPathFromEndpointRejectsUnsafeEndpointWithoutLeakingRawValues"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_readiness_test.go"), testName: "TestGuestAgentReadinessProbeDelegatesProtocolReadinessAndSanitizesMetadata"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdCommandConfiguredMicroVMGuestAgentEndpointKeepsCapabilitiesLifecycleOnly"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdCommandRejectsInvalidGuestAgentEndpointBeforeMicroVMDriverConstruction"},
		{pkg: "./cmd", file: "phase40_microvm_guest_agent_transport_guard_test.go", testName: "TestPhase40MicroVMDefaultCapabilitiesStayLifecycleOnlyWithoutGuestTransport"},
		{pkg: "./cmd", file: "phase40_microvm_guest_agent_transport_guard_test.go", testName: "TestPhase40MicroVMGuestTransportCodeAvoidsHostDockerSocketUse"},
		{pkg: "./cmd", file: "phase40_microvm_guest_agent_transport_guard_test.go", testName: "TestPhase40MicroVMGuestProtocolPackagesDoNotImportCommandFactoryOrWorker"},
		{pkg: "./cmd", file: "phase40_microvm_guest_agent_transport_guard_test.go", testName: "TestPhase40MicroVMGuestTransportPublicErrorsAndJSONAreRedactionSafe"},
		{pkg: "./cmd", file: "phase40_microvm_guest_agent_transport_docs_test.go", testName: "TestPhase40MicroVMGuestAgentTransportVerificationDocs"},
		{pkg: "./cmd", file: "phase40_microvm_guest_agent_transport_docs_test.go", testName: "TestPhase40MicroVMGuestAgentTransportFakeSafeVerification"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "service_test.go"), testName: "TestServiceMicroVMCapabilityReportsConservativeRuntimeMetadata"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "service_test.go"), testName: "TestServiceMicroVMWorkerIORequestsAreRejectedBeforeDriverDispatch"},
	}
}

func phase40AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "validation_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "client_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "import_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "guest_transport_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase38_default_behavior_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "phase38_exec_delegation_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_transport_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_endpoint_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_agent_unix_transport_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "guest_readiness_test.go"),
		filepath.Join("..", "internal", "sandboxworker", "service_test.go"),
		"sandboxd_test.go",
		"phase40_microvm_guest_agent_transport_guard_test.go",
		"phase40_microvm_guest_agent_transport_docs_test.go",
	} {
		phase34AssertNoLiveIntegrationBuildTag(t, file)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}
