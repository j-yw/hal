package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8PID1GuestInitVerificationDocumentNamesMissingSealedChannel(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d6-pid1-guest-init-verification.md"))
	for _, required := range []string{
		"missing sealed expected-digest channel",
		"L8ProcessCompositionFacts",
		"helperDescriptorSha256",
		"clientDescriptorSha256",
		"compositionSha256",
		"native-bootstrap sealed config pipe",
		"NewPID1StartGateState",
		"AcceptHelperDescriptor",
		"AcceptClientDescriptor",
		"does not construct helper or client",
		"l8composition.NewHelper",
		"l8composition.NewClient",
		"--require-l7-network",
		"go test ./internal/sandboxruntime/microvm/guestagent/l8composition -run 'PID1StartGate' -count=1",
		"go test ./cmd/hal-guest-init -count=1",
		"go test ./cmd -run 'L8CredentialDeliverySourceGuardsCommandComposition|PID1|GuestInit' -count=1",
		"go vet ./cmd/hal-guest-init ./internal/sandboxruntime/microvm/guestagent/l8composition",
		"does not claim live start-gate release",
		"Unsigned file/env/cmdline",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("PID1 guest-init verification omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"live start-gate is production-complete",
		"fixture-as-strict",
		"os.Getenv",
		"hal_l8_helper_digest",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("PID1 guest-init verification contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8PID1GuestInitProductionImportBoundaryIsExact(t *testing.T) {
	entries, err := os.ReadDir("hal-guest-init")
	if err != nil {
		t.Fatal(err)
	}
	foundCompositionImport := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join("hal-guest-init", entry.Name())
		source := readL8CredentialDeliveryFile(t, path)
		if strings.Contains(source, "l8composition.NewHelper") || strings.Contains(source, "l8composition.NewClient") {
			t.Errorf("PID1 production file %s constructs helper or client", filepath.ToSlash(path))
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.ToSlash(path), err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if importPath == l8CompositionImportPath || strings.HasPrefix(importPath, l8CompositionImportPath+"/") {
				foundCompositionImport = true
			}
		}
	}
	if !foundCompositionImport {
		t.Fatal("cmd/hal-guest-init production files do not import l8composition")
	}
	agentEntries, err := os.ReadDir("hal-guest-agent")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range agentEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join("hal-guest-agent", entry.Name())
		source := readL8CredentialDeliveryFile(t, path)
		if strings.Contains(source, l8CompositionImportPath) {
			t.Errorf("hal-guest-agent production file %s imports l8composition", filepath.ToSlash(path))
		}
	}
}

func TestL8GuestInitDoesNotInventUnsignedExpectedDigestInputs(t *testing.T) {
	source := readL8CredentialDeliveryFile(t, filepath.Join("hal-guest-init", "pid1_start_gate_linux.go"))
	for _, forbidden := range []string{
		"go:embed",
		"os.Getenv",
		"os.LookupEnv",
		"os.ReadFile",
		"os.Open(",
		"/proc/cmdline",
		"hal_l8_",
		"json.Unmarshal",
		"ioutil",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("PID1 start-gate production file invents unsigned digest input %q", forbidden)
		}
	}
	if !strings.Contains(source, "return l8composition.PID1StartGateExpected{}, false, nil") {
		t.Fatal("PID1 start-gate loader must fail closed to a missing sealed channel, not a fixture digest")
	}
}
