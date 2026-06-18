package cmd

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestSandboxRedactorPreservesSandboxNameWhenHostnameMatches(t *testing.T) {
	redactor := sandboxRedactor(false, nil, &sandbox.SandboxState{
		Name:              "dev",
		IP:                "203.0.113.10",
		TailscaleHostname: "dev",
	})

	got := redactor.Redact(`Sandbox "dev" uses 203.0.113.10`)
	if !strings.Contains(got, `"dev"`) {
		t.Fatalf("redacted sandbox name: %q", got)
	}
	if strings.Contains(got, "203.0.113.10") {
		t.Fatalf("did not redact IP address: %q", got)
	}
}

func TestSandboxRedactorRedactsGeneratedTailscaleHostname(t *testing.T) {
	redactor := sandboxRedactor(false, nil, &sandbox.SandboxState{
		Name:              "dev",
		TailscaleHostname: "hal-dev-019ecfb9",
	})

	got := redactor.Redact("Tailscale hostname: hal-dev-019ecfb9")
	if strings.Contains(got, "hal-dev-019ecfb9") {
		t.Fatalf("did not redact generated hostname: %q", got)
	}
}
