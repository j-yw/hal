package cmd

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestFactorySandboxMetadataOmitsNetworkProxyMetadataByDefault(t *testing.T) {
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{}, factory.RunRecord{}, &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	})
	if metadata == nil {
		t.Fatal("factorySandboxPersistentMetadataFromState() metadata = nil")
	}
	if metadata.NetworkProxySession != nil {
		t.Fatalf("NetworkProxySession = %#v, want nil by default", metadata.NetworkProxySession)
	}

	data, err := json.Marshal(factory.RunRecord{
		RunID:   "run-no-proxy-metadata",
		Status:  factory.RunStatusRunning,
		Sandbox: metadata,
	})
	if err != nil {
		t.Fatalf("json.Marshal(run record) error = %v", err)
	}
	encoded := string(data)
	for _, forbidden := range []string{"networkProxySession", "networkPolicyDecisionLog", "networkPolicyDecisionLogs"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("factory sandbox record should omit %q by default: %s", forbidden, encoded)
		}
	}
}

func TestFactorySandboxPersistentMetadataSanitizesNetworkProxySession(t *testing.T) {
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{
		NetworkProxySession: unsafeFactoryNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY ")),
	}, factory.RunRecord{}, &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	})
	if metadata == nil {
		t.Fatal("factorySandboxPersistentMetadataFromState() metadata = nil")
	}
	session := metadata.NetworkProxySession
	if session == nil {
		t.Fatal("NetworkProxySession = nil, want sanitized proxy session metadata")
	}
	if session.ID != "proxy-session-01" {
		t.Fatalf("proxy session id = %q, want proxy-session-01", session.ID)
	}
	if session.Source != sandbox.SandboxNetworkPolicyDecisionSourceFactory {
		t.Fatalf("proxy session source = %q, want factory", session.Source)
	}
	if session.EnforcementMode != "" {
		t.Fatalf("proxy session enforcement mode = %q, want unsafe value cleared", session.EnforcementMode)
	}
	if session.PolicySnapshot == nil {
		t.Fatal("policy snapshot = nil, want sanitized snapshot metadata")
	}
	if session.PolicySnapshot.ID != "policy-snapshot-01" {
		t.Fatalf("policy snapshot id = %q, want policy-snapshot-01", session.PolicySnapshot.ID)
	}
	if session.PolicySnapshot.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("policy snapshot preset = %q, want %q", session.PolicySnapshot.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if session.PolicySnapshot.Version != "" || session.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("policy snapshot = %#v, want unsafe version and rule set id cleared", session.PolicySnapshot)
	}

	data, err := json.Marshal(factory.RunRecord{
		RunID:   "run-proxy-metadata",
		Status:  factory.RunStatusRunning,
		Sandbox: metadata,
	})
	if err != nil {
		t.Fatalf("json.Marshal(run record) error = %v", err)
	}
	encoded := string(data)
	for _, forbidden := range []string{
		"api.example.com",
		"169.254.169.254",
		"https://user:secret@example.test/path?token=secret",
		"unix:///tmp/private/proxy.sock",
		"/Users/alice/project",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"raw-header-token-value",
		"raw body secret value",
		"token@example.com",
		"/Users/private",
		"https://",
		"ruleSetId",
		"enforcementMode",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("factory sandbox record leaked unsafe proxy metadata %q: %s", forbidden, encoded)
		}
	}
	for _, want := range []string{
		"networkProxySession",
		"proxy-session-01",
		"policy-snapshot-01",
		string(sandbox.SandboxNetworkPolicyDecisionSourceFactory),
		string(sandbox.SandboxNetworkPolicyPresetDenyByDefault),
	} {
		if !strings.Contains(encoded, want) {
			t.Fatalf("factory sandbox record omitted safe proxy metadata %q: %s", want, encoded)
		}
	}
}

func TestFactorySandboxNetworkProxyMetadataPlumbingAvoidsLiveAdapterImports(t *testing.T) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "factory_sandbox_executor.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile(factory_sandbox_executor.go) error = %v", err)
	}

	forbidden := []struct {
		name  string
		match func(string) bool
	}{
		{name: "worker client package", match: hasImportPrefix("github.com/jywlabs/hal/internal/sandboxworker")},
		{name: "concrete provider adapter package", match: hasImportPrefix("github.com/jywlabs/hal/internal/sandbox/provider")},
		{name: "rootless Podman runtime adapter package", match: hasImportPrefix("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
		{name: "net/http live proxy package", match: importEquals("net/http")},
		{name: "process execution package", match: importEquals("os/exec")},
		{name: "cloud SDK package", match: importHasAny("cloud.google.com/", "github.com/aws/", "github.com/Azure/", "google.golang.org/api/")},
		{name: "Docker or Podman SDK package", match: importHasAny("docker", "podman")},
		{name: "KVM package", match: importHasAny("kvm", "libvirt")},
		{name: "firewall package", match: importHasAny("firewall", "iptables", "pfctl")},
	}

	for _, spec := range parsed.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import path %s: %v", spec.Path.Value, err)
		}
		for _, rule := range forbidden {
			if rule.match(importPath) {
				t.Fatalf("factory network proxy metadata plumbing imports forbidden %s %q", rule.name, importPath)
			}
		}
	}
}

func unsafeFactoryNetworkProxySession(source sandbox.SandboxNetworkPolicyDecisionSource) *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     " proxy-session-01 ",
		Source: source,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   "https://user:secret@example.test/path?token=secret",
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: "/Users/private/rules.json",
		},
		EnforcementMode: "Bearer",
	}
}

func hasImportPrefix(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func importEquals(want string) func(string) bool {
	return func(importPath string) bool {
		return importPath == want
	}
}

func importHasAny(markers ...string) func(string) bool {
	return func(importPath string) bool {
		lower := strings.ToLower(importPath)
		for _, marker := range markers {
			if strings.Contains(lower, strings.ToLower(marker)) {
				return true
			}
		}
		return false
	}
}
