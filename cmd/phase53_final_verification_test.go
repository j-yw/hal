package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase53FinalVerificationDocPath = "sandbox-runtime-v2-phase53-final-verification.md"

func TestPhase53FinalVerificationDocumentation(t *testing.T) {
	doc := readPhase53FinalVerificationDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 53 final verification barrier proves the live microVM E2E harness is safe to merge",
		"The default verification matrix is fake-only.",
		"metadata, diagnostics, live gates, preflight, network readiness, credential delivery, template trust, live harness, marker guards, and operator documentation",
		"Focused Checks",
		"Broad Checks",
		"Optional Live E2E",
		"`go test ./...` remains fake-only",
		"The live command is optional, tagged, and safe to skip when prerequisites are missing.",
		"sanitized skip diagnostics before live execution starts",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 53 final verification documentation missing %q", want)
		}
	}

	phase53FinalAssertDocumentedCommands(t, doc)
}

func TestPhase53FinalDefaultCommandsStayFakeOnly(t *testing.T) {
	doc := readPhase53FinalVerificationDoc(t)
	commands := phase53FinalDefaultCommandLines(doc)
	if len(commands) == 0 {
		t.Fatal("phase 53 final verification documentation must list default command lines")
	}

	for _, command := range commands {
		for _, forbidden := range phase53FinalForbiddenDefaultCommandMarkers() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 53 final default command %q contains live or external dependency marker %q", command, forbidden)
			}
		}
	}
}

func TestPhase53FinalOptionalLiveCommandIsTaggedAndSafeToSkip(t *testing.T) {
	doc := readPhase53FinalVerificationDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"The live E2E command remains an operator-run diagnostic for prepared hosts only.",
		"It is not part of the default quality gate matrix:",
		phase53LiveE2ECommand,
		"The live command is optional, tagged, and safe to skip when prerequisites are missing.",
		"Missing Firecracker, KVM, proxy, firewall, credential delivery, env",
		"delivery mode, or template trust prerequisites must produce sanitized skip",
		"diagnostics before live execution starts.",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 53 final verification documentation missing optional live command boundary %q", want)
		}
	}
	phase53AssertLiveE2ECommandRedactionSafe(t, phase53LiveE2ECommand)
}

func TestPhase53FinalVerificationDocPathStable(t *testing.T) {
	if got, want := phase53FinalVerificationDocPath, "sandbox-runtime-v2-phase53-final-verification.md"; got != want {
		t.Fatalf("phase53 final verification doc path = %q, want %q", got, want)
	}
}

func readPhase53FinalVerificationDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", phase53FinalVerificationDocPath))
	if err != nil {
		t.Fatalf("ReadFile(phase 53 final verification doc) error: %v", err)
	}
	return string(data)
}

func phase53FinalAssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 ./cmd -run 'Test(US004|US010|Phase53)'",
		"go test -count=1 ./internal/sandboxruntime/microvm -run 'Test(LiveE2E|MissingLiveE2E|MicroVMLiveE2E)'",
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 53 final verification documentation missing command line %q", want)
		}
	}
	if !strings.Contains(doc, phase53LiveE2ECommand) {
		t.Fatal("phase 53 final verification documentation missing optional live E2E command")
	}
}

func phase53FinalDefaultCommandLines(doc string) []string {
	var commands []string
	for command := range phase34DocumentedShellCommands(doc) {
		commands = append(commands, command)
	}
	return commands
}

func phase53FinalForbiddenDefaultCommandMarkers() []string {
	return []string{
		"-tags=microvm_e2e_live",
		"-tags=firecracker_live",
		"-tags=network_enforcement_live",
		"-tags=credential_delivery_live",
		"microvm_e2e_live",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
		"HAL_FIRECRACKER_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_TEMPLATE_TRUST_LIVE",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"HAL_WORKER_INTEGRATION_",
		"DOCKER_HOST",
		"SSH_AUTH_SOCK",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"docker ",
		"podman ",
		"firecracker ",
		"/dev/kvm",
		"curl ",
		"hal sandboxd",
		"hal auto",
		"hal run",
	}
}
