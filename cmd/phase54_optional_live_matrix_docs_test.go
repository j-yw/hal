package cmd

import (
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
)

func TestPhase54OptionalLiveVerificationMatrixDocumentsSuites(t *testing.T) {
	doc := phase50ReadFile(t, phase54ReleasePackageDesignDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"## Optional Live Verification Matrix",
		"These commands are optional operator-run checks for prepared live infrastructure.",
		"They are not default CI, not release package prerequisites, and not post-run PRD validation.",
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
	for _, command := range phase50ManualDocumentedShellCommands(doc) {
		commands[command] = true
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
