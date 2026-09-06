package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase50ManualLiveOptInDocPath = "sandbox-runtime-v2-phase50-manual-live-opt-in-verification.md"
const phase50ManualPodmanTestImageEnv = "HAL_PODMAN_" + "TEST_IMAGE"

func TestPhase50ManualLiveOptInDocumentation(t *testing.T) {
	doc := readPhase50ManualLiveOptInDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 50 manual live opt-in commands are optional operator-run commands.",
		"They are not part of default Phase 50 verification.",
		"Every live command requires both an optional Go build tag and explicit environment gates.",
		"Missing prerequisites must produce a skip or remediation result before any live action starts.",
		"Skip and remediation output may include gate IDs, build tags, env var names, reason codes, and safe remediation commands.",
		"Skip and remediation output must not include env values, raw paths, hostnames, URLs, socket paths, tokens, credentials, provider config, process args, firewall details, or proxy details.",
		"Use `<set>` placeholders in examples instead of real environment values.",
		"Phase 50 verification excludes PRD regeneration, PRD audit, PRD validation, and Hal workflow commands.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 50 manual live opt-in documentation missing %q", want)
		}
	}

	phase50ManualAssertDocumentedLiveCommands(t, doc)
}

func TestPhase50ManualLiveOptInCommandMatrixCoversRequiredCategories(t *testing.T) {
	doc := readPhase50ManualLiveOptInDoc(t)
	commands := phase50ManualDocumentedLiveCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 50 manual live opt-in documentation must list explicit live commands")
	}

	for _, req := range phase50ManualLiveCommandRequirements() {
		if !commands[req.wantCommand] {
			t.Fatalf("phase 50 manual live opt-in documentation missing %s command %q", req.name, req.wantCommand)
		}
		command := req.wantCommand
		if !strings.Contains(command, "-tags="+req.buildTag) {
			t.Fatalf("%s command %q missing build tag %q", req.name, command, req.buildTag)
		}
		for _, envVar := range req.envVars {
			if !strings.Contains(command, envVar+"=<set>") {
				t.Fatalf("%s command %q missing safe env gate assignment for %s", req.name, command, envVar)
			}
		}
		phase50ManualAssertCommandRedactionSafe(t, command)
	}
}

func TestPhase50ManualLiveOptInSkipsArePreActionAndRedactionSafe(t *testing.T) {
	doc := readPhase50ManualLiveOptInDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	requiredSemantics := []string{
		"skip before opening listeners, changing firewall or runtime rules, launching Firecracker, starting worker-backed execution, invoking Podman, delivering credentials, reading credential material, or probing provider configuration.",
		"Allowed skip output fields are gate IDs, category names, build tags, env var names, reason codes, capability IDs, and remediation command templates that use `<set>` placeholders.",
		"Forbidden skip output fields are env values, raw paths, hostnames, URLs, socket paths, tokens, credentials, provider config, process args, firewall details, and proxy details.",
	}
	for _, want := range requiredSemantics {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 50 manual live opt-in documentation missing skip/remediation semantic %q", want)
		}
	}
}

func TestPhase50ManualLiveOptInDoesNotDocumentDefaultOrPRDWorkflowCommands(t *testing.T) {
	doc := readPhase50ManualLiveOptInDoc(t)
	for _, command := range phase50ManualDocumentedShellCommands(doc) {
		for _, forbidden := range []string{
			"hal validate",
			"hal convert --granular",
			"hal plan",
			"hal auto",
			"hal run",
			"hal report",
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 50 manual live opt-in documentation must not document PRD/workflow command %q in command %q", forbidden, command)
			}
		}
	}

	for _, phrase := range []string{
		"run hal validate",
		"run hal convert --granular",
		"run hal plan",
		"run hal auto",
		"run hal run",
		"run hal report",
		"run PRD regeneration",
		"run PRD audit",
		"run PRD validation",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(phrase)) {
			t.Fatalf("phase 50 manual live opt-in documentation must not instruct %q", phrase)
		}
	}
}

func TestPhase50ManualLiveOptInDocPathStable(t *testing.T) {
	if got, want := phase50ManualLiveOptInDocPath, "sandbox-runtime-v2-phase50-manual-live-opt-in-verification.md"; got != want {
		t.Fatalf("phase 50 manual live opt-in doc path = %q, want %q", got, want)
	}
}

func readPhase50ManualLiveOptInDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", phase50ManualLiveOptInDocPath))
	if err != nil {
		t.Fatalf("ReadFile(phase 50 manual live opt-in verification doc) error: %v", err)
	}
	return string(data)
}

func phase50ManualAssertDocumentedLiveCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase50ManualDocumentedLiveCommands(doc)
	for _, req := range phase50ManualLiveCommandRequirements() {
		if !commands[req.wantCommand] {
			t.Fatalf("phase 50 manual live opt-in documentation missing %s command line %q", req.name, req.wantCommand)
		}
	}
}

func phase50ManualDocumentedLiveCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	for _, command := range phase50ManualDocumentedShellCommands(doc) {
		if strings.Contains(command, " -tags=") && strings.HasPrefix(command, "env ") {
			commands[command] = true
		}
	}
	return commands
}

func phase50ManualDocumentedShellCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "env "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "go test "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "go vet "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "make "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "git diff "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "hal "):
			commands = append(commands, line)
		}
	}
	return commands
}

func phase50ManualLiveCommandRequirements() []struct {
	name        string
	buildTag    string
	envVars     []string
	wantCommand string
} {
	return []struct {
		name        string
		buildTag    string
		envVars     []string
		wantCommand string
	}{
		{
			name:     "Firecracker",
			buildTag: "firecracker_live",
			envVars: []string{
				"HAL_FIRECRACKER_LIVE",
				"HAL_FIRECRACKER_LIVE_FIRECRACKER",
				"HAL_FIRECRACKER_LIVE_KERNEL",
				"HAL_FIRECRACKER_LIVE_ROOTFS",
			},
			wantCommand: "env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		},
		{
			name:     "network enforcement",
			buildTag: "network_enforcement_live",
			envVars: []string{
				"HAL_NETWORK_ENFORCEMENT_LIVE",
				"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
				"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
			},
			wantCommand: "env HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'",
		},
		{
			name:     "credential delivery",
			buildTag: "credential_delivery_live",
			envVars: []string{
				"HAL_CREDENTIAL_DELIVERY_LIVE",
				"HAL_CREDENTIAL_DELIVERY_LIVE_ENV",
			},
			wantCommand: "env HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'",
		},
		{
			name:     "worker integration",
			buildTag: "worker_integration",
			envVars: []string{
				"HAL_WORKER_INTEGRATION_ENDPOINT",
				"HAL_WORKER_INTEGRATION_HOST_NAME",
				"HAL_WORKER_INTEGRATION_RUNTIME_DRIVER",
				"HAL_WORKER_INTEGRATION_IMAGE",
			},
			wantCommand: "env HAL_WORKER_INTEGRATION_ENDPOINT=<set> HAL_WORKER_INTEGRATION_HOST_NAME=<set> HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=<set> HAL_WORKER_INTEGRATION_IMAGE=<set> go test -tags=worker_integration -count=1 -timeout=120s ./cmd -run TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver",
		},
		{
			name:     "Podman integration",
			buildTag: "podman_integration",
			envVars: []string{
				phase50ManualPodmanTestImageEnv,
			},
			wantCommand: "env " + phase50ManualPodmanTestImageEnv + "=<set> go test -tags=podman_integration -count=1 -timeout=120s ./internal/sandboxruntime/rootlesspodman -run TestPodmanIntegrationLifecycleExecAndCopy",
		},
	}
}

func phase50ManualAssertCommandRedactionSafe(t *testing.T, command string) {
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
	} {
		if strings.Contains(lower, unsafe) {
			t.Fatalf("phase 50 manual live command %q contains unsafe detail marker %q", command, unsafe)
		}
	}
}
