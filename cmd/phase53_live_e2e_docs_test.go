package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	phase53LiveE2EDocPath         = "sandbox-runtime-v2-phase53-live-e2e-verification.md"
	phase53LiveE2EPackageSelector = "./internal/sandboxruntime/microvm"
	phase53LiveE2ECommand         = "env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> HAL_TEMPLATE_TRUST_LIVE=<set> go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath"
)

func TestPhase53LiveE2EDocumentationNamesExactPackageSelector(t *testing.T) {
	doc := readPhase53LiveE2EDoc(t)

	for _, want := range []string{
		"Phase 53 adds one narrow operator-run live E2E command for prepared hosts.",
		"Exact package selector: `" + phase53LiveE2EPackageSelector + "`.",
		phase53LiveE2ECommand,
		"The test composes the shared live gate, Firecracker microVM preflight, network proxy and firewall readiness metadata, credential delivery activation metadata, and template trust metadata before the Firecracker live driver creates or starts a target.",
		"Explicit readiness claims that do not prove active proxy plus active firewall under a `proxy_firewall` default-deny result fail with sanitized diagnostics.",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("phase 53 live E2E documentation missing %q", want)
		}
	}
}

func TestPhase53LiveE2EDocumentationContainsNoPackageSelectorPlaceholderOrConditionalWording(t *testing.T) {
	doc := readPhase53LiveE2EDoc(t)
	lowerDoc := strings.ToLower(doc)

	for _, forbidden := range []string{
		"<package-selector>",
		"{{package_selector}}",
		"package_selector",
		"PACKAGE_SELECTOR",
		"TODO",
		"TBD",
		"adjust the package selector",
		"replace the package selector",
		"choose the package selector",
		"package selector as needed",
		"if available",
		"when available",
		"if needed",
		"if your host",
		"use a different package",
		"or another package",
	} {
		if strings.Contains(lowerDoc, strings.ToLower(forbidden)) {
			t.Fatalf("phase 53 live E2E documentation contains unresolved or conditional wording %q", forbidden)
		}
	}
}

func TestPhase53LiveE2EDocumentedCommandIsNarrowAndRedactionSafe(t *testing.T) {
	doc := readPhase53LiveE2EDoc(t)
	commands := phase53LiveE2EDocumentedShellCommands(doc)
	if len(commands) != 1 {
		t.Fatalf("phase 53 live E2E documented shell commands = %#v, want exactly one command", commands)
	}
	command := commands[0]
	if command != phase53LiveE2ECommand {
		t.Fatalf("phase 53 live E2E command = %q, want exact command %q", command, phase53LiveE2ECommand)
	}
	if !strings.Contains(command, " -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live ") {
		t.Fatalf("phase 53 live E2E command missing required live build tags: %q", command)
	}
	if !strings.Contains(command, " "+phase53LiveE2EPackageSelector+" ") {
		t.Fatalf("phase 53 live E2E command missing exact package selector %q: %q", phase53LiveE2EPackageSelector, command)
	}
	if !strings.Contains(command, "-run TestMicroVMLiveE2EComposedLiveExecutionPath") {
		t.Fatalf("phase 53 live E2E command missing focused test selector: %q", command)
	}
	for _, envVar := range []string{
		"HAL_FIRECRACKER_LIVE",
		"HAL_FIRECRACKER_LIVE_FIRECRACKER",
		"HAL_FIRECRACKER_LIVE_KERNEL",
		"HAL_FIRECRACKER_LIVE_ROOTFS",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
		"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE_ENV",
		"HAL_TEMPLATE_TRUST_LIVE",
	} {
		if !strings.Contains(command, envVar+"=<set>") {
			t.Fatalf("phase 53 live E2E command missing safe placeholder for %s: %q", envVar, command)
		}
	}
	phase53AssertLiveE2ECommandRedactionSafe(t, command)
}

func TestPhase53LiveE2EDocumentationListsRequiredOptInMarkers(t *testing.T) {
	doc := readPhase53LiveE2EDoc(t)

	for _, buildTag := range []string{
		"`microvm_e2e_live`",
		"`firecracker_live`",
		"`network_enforcement_live`",
		"`credential_delivery_live`",
	} {
		if !strings.Contains(doc, buildTag) {
			t.Fatalf("phase 53 live E2E documentation missing required build tag %s", buildTag)
		}
	}

	for _, envVar := range []string{
		"`HAL_FIRECRACKER_LIVE`",
		"`HAL_FIRECRACKER_LIVE_FIRECRACKER`",
		"`HAL_FIRECRACKER_LIVE_KERNEL`",
		"`HAL_FIRECRACKER_LIVE_ROOTFS`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE_ENV`",
		"`HAL_TEMPLATE_TRUST_LIVE`",
	} {
		if !strings.Contains(doc, envVar) {
			t.Fatalf("phase 53 live E2E documentation missing required env marker %s", envVar)
		}
	}

	for _, want := range []string{
		"The marker list is intentionally names-only.",
		"example secret values",
		"credential material",
		"absolute host paths",
		"proxy endpoints",
		"firewall rules",
		"Firecracker command-line",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("phase 53 live E2E documentation missing redaction guidance %q", want)
		}
	}
}

func TestPhase53LiveE2EDocumentationExplainsSkipAndValidationBoundaries(t *testing.T) {
	doc := readPhase53LiveE2EDoc(t)

	for _, want := range []string{
		"Missing build tags, marker variables, Firecracker launch assets, KVM host",
		"capability, network proxy readiness, firewall readiness, credential delivery",
		"activation, credential mode selection, env-delivery marker, or template trust",
		"metadata produce sanitized skips before live execution starts.",
		"`go test ./...` remains fake-only.",
		"firewall, credential delivery, template trust, live build tags, or live",
		"environment markers.",
		"This live E2E command is an explicit operator diagnostic for prepared live",
		"hosts. It must not be used as post-run PRD validation.",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("phase 53 live E2E documentation missing skip or validation boundary %q", want)
		}
	}
}

func readPhase53LiveE2EDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", phase53LiveE2EDocPath))
	if err != nil {
		t.Fatalf("ReadFile(phase 53 live E2E verification doc) error: %v", err)
	}
	return string(data)
}

func phase53LiveE2EDocumentedShellCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "env ") || strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase53AssertLiveE2ECommandRedactionSafe(t *testing.T, command string) {
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
			t.Fatalf("phase 53 live E2E command %q contains unsafe detail marker %q", command, unsafe)
		}
	}
}
