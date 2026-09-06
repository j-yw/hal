package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestUS007SandboxRuntimeListStatusRedactSeededHostStatusMetadata(t *testing.T) {
	setSandboxHostRegistryHome(t)

	readiness := us009UnsafeReadinessWithSafeFallback()
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	gate := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility, diagnostics)
	host := us009RuntimeHostWithSecurity("us007-runtime-redaction", readiness, gate)
	host.Endpoint = "https://user:pass@runtime.example.invalid/api?token=ghp_US007RuntimeRemote1234567890"
	host.Health = &sandbox.HostHealth{Status: "degraded", Message: "checked /Users/alice/.ssh/id_ed25519 with ghp_US007RuntimeHealth1234567890"}
	if err := sandbox.SaveHost(host); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	var combined bytes.Buffer
	for _, args := range [][]string{
		{"list", "us007-runtime-redaction", "--json"},
		{"status", "us007-runtime-redaction", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"},
		{"list", "us007-runtime-redaction"},
		{"status", "us007-runtime-redaction", sandbox.SandboxRuntimeDriverRootlessPodman},
	} {
		cmd, stdout, stderr := newTestSandboxRuntimeCommand(us007RuntimeDepsNoWorker(t))
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute(%v) error = %v; stderr=%q", args, err, stderr.String())
		}
		if args[0] == "list" && args[len(args)-1] == "--json" {
			resp := decodeOneSandboxRuntimeListJSON(t, stdout.Bytes())
			if resp.Host.Endpoint.Summary != "https endpoint" {
				t.Fatalf("runtime list endpoint = %#v, want safe endpoint summary", resp.Host.Endpoint)
			}
		}
		if args[0] == "status" && args[len(args)-1] == "--json" {
			resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
			if resp.Host.Endpoint.Summary != "https endpoint" {
				t.Fatalf("runtime status endpoint = %#v, want safe endpoint summary", resp.Host.Endpoint)
			}
			if resp.Security.SecurityReadinessGate == nil {
				t.Fatalf("runtime status security = %#v, want sanitized readiness gate", resp.Security)
			}
		}
		combined.WriteString(stdout.String())
		combined.WriteString(stderr.String())
		combined.WriteByte('\n')
	}

	output := combined.String()
	forbidden := append([]string{
		"runtime.example.invalid",
		"user:pass",
		"ghp_US007RuntimeRemote1234567890",
		"ghp_US007RuntimeHealth1234567890",
		"/Users/alice/.ssh/id_ed25519",
	}, us009ForbiddenRuntimeSecureDefaultFragments()...)
	for _, value := range forbidden {
		if strings.Contains(output, value) {
			t.Fatalf("runtime list/status output leaked forbidden value %q:\n%s", value, output)
		}
	}
}

func us007RuntimeDepsNoWorker(t *testing.T) sandboxRuntimeDeps {
	t.Helper()
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("US-007 runtime redaction tests must stay cached/fake-only and must not contact worker daemons")
		return nil, nil
	}
	return deps
}
