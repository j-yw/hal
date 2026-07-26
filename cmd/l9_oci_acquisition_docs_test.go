package cmd

import (
	"os"
	"strings"
	"testing"
)

const l9OCIArchitecturePath = "../docs/design/sandbox-runtime-v2-l9-production-oci-acquisition.md"

func TestL9OCIArchitectureDefinesRequiredPhaseSections(t *testing.T) {
	content, err := os.ReadFile(l9OCIArchitecturePath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", l9OCIArchitecturePath, err)
	}
	text := string(content)
	for _, marker := range []string{
		"## 1. Inputs, outputs, states, and failure codes",
		"## 2. Package ownership and import boundaries",
		"## 3. Durable and machine-contract schema changes",
		"## 4. Redaction and containment rules",
		"## 5. Crash, retry, cancellation, and cleanup semantics",
		"## 6. Red-first fake and live acceptance tests",
		"## 7. Non-goals and next-phase handoff",
		"`--sandbox-template REFERENCE`",
		"`--sandbox-template-trust strict|advisory`",
		"`TestOCIRegistryIntegrationStrictTrust`",
		"signature",
		"transparency",
		"tag_mutated",
		"never forwards `Authorization` to a different host",
		"before target provisioning",
		"Dry-run with template flags remains L1-pure",
		"exact normalized registry origin",
		"exact configured HTTPS",
		"`request_canceled`",
		"`request_timeout`",
		"`response_headers_oversize`",
		"ambient proxy discovery disabled",
		"TLS 1.2 as the minimum",
		"revalidated on every registry",
		"exact field allowlist",
		"`schemaVersion`, `mediaType`, `artifactType`, `config`, and `layers`",
		"`Content-Encoding`",
		"descriptor-relatively with no-follow semantics",
		"syncs the parent directory",
		"Cache is an optimization",
		"schema version 2",
		"Exactly one template layer",
		"exact execution manifest and sandbox/runtime state",
		"`internal/sandboxtemplate/selection`",
		"`internal/sandboxtarget` does not import",
		"Mutable tags are intake aliases only",
		"symlink/change-during-read",
		"provider/runtime constructor panic fakes",
		"Any skip is a blocker, not a pass",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("L9 architecture note missing %q", marker)
		}
	}
}

func TestL9OCIArchitectureLocksFocusedCommands(t *testing.T) {
	content, err := os.ReadFile(l9OCIArchitecturePath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", l9OCIArchitecturePath, err)
	}
	text := string(content)
	for _, command := range []string{
		"go test -count=1 ./internal/sandboxtemplate/acquisition ./internal/sandboxtemplate/acquisition/registry",
		"go test -race -count=1 ./internal/sandboxtemplate/acquisition ./internal/sandboxtemplate/acquisition/registry",
		"go test -tags=template_oci_integration -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition/registry -run '^TestOCIRegistryIntegrationStrictTrust$'",
		"go test -count=1 ./cmd -run 'TestL9'",
	} {
		if !strings.Contains(text, command) {
			t.Errorf("L9 architecture note missing focused command %q", command)
		}
	}
}
