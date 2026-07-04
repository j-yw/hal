package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func phase55VerificationDocPath() string {
	return filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase55-secure-default-policy-proxy-verification.md")
}

func TestPhase55VerificationDocumentationDefinesProxyOnlyScope(t *testing.T) {
	doc := phase50ReadFile(t, phase55VerificationDocPath())
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"Phase 55 activates the worker-owned policy proxy proof path",
		"active proxy proof may appear as `networkEnforcement=proxy`",
		"strict secure-default readiness remains blocked until firewall or runtime rule proof also exists",
		"`internal/sandboxruntime/networkenforcement` owns the policy proxy service contracts",
		"`internal/sandboxworker` projects sanitized proxy-active proof into worker status security metadata",
		"`cmd` remains a status and summary boundary",
		"`networkPolicy=best_effort`",
		"does not own proxy decision behavior",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("%s missing required Phase 55 scope text %q", phase50SafeDisplayPath(phase55VerificationDocPath()), want)
		}
	}
}

func TestPhase55VerificationDocumentationStatesFakeOnlyNonGoals(t *testing.T) {
	doc := phase50ReadFile(t, phase55VerificationDocPath())
	normalized := strings.Join(strings.Fields(strings.ToLower(doc)), " ")
	for _, want := range []string{
		"phase 55 does not add production firewall or runtime rule mutation",
		"credential broker delivery",
		"templates or kits rollout",
		"global default-on secure runtime selection",
		"live kvm e2e",
		"default phase 55 verification is fake-only",
		"must not require root, firewall mutation, docker, podman, kvm, firecracker, cloud apis, live network egress, real proxy listener binding, real credentials, live worker daemons, or optional live build tags",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("%s missing fake-only/non-goal text %q", phase50SafeDisplayPath(phase55VerificationDocPath()), want)
		}
	}
	for command := range phase34DocumentedShellCommands(doc) {
		lower := strings.ToLower(command)
		for _, forbidden := range []string{
			"-tags=network_enforcement_live",
			"-tags=firecracker_live",
			"-tags=microvm_e2e_live",
			"hal_network_enforcement_live=",
			"hal_firecracker_live=",
			"hal_credential_delivery_live=",
			"docker ",
			"podman ",
			"iptables",
			"nftables",
			"pfctl",
			"/dev/kvm",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s default documented command %q contains live/default-forbidden marker %q", phase50SafeDisplayPath(phase55VerificationDocPath()), command, forbidden)
			}
		}
	}
}

func TestPhase55DocumentedFocusedGoTestSelectorsMatchTestsAndPackages(t *testing.T) {
	doc := phase50ReadFile(t, phase55VerificationDocPath())
	for command := range phase34DocumentedShellCommands(doc) {
		runSelector, ok := phase54CommandRunSelector(command)
		if !ok || runSelector == "^$" {
			continue
		}
		packages := phase54CommandPackageSelectors(command)
		if len(packages) == 0 {
			t.Fatalf("%s focused go test command %q has no package selector", phase50SafeDisplayPath(phase55VerificationDocPath()), command)
		}
		for _, packageSelector := range packages {
			phase54AssertPackageSelectorExists(t, packageSelector, command)
			phase54AssertRunSelectorMatchesPackageTests(t, runSelector, packageSelector, command)
		}
	}
}
