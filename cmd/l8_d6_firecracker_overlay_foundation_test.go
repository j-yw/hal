package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D6FirecrackerOverlayFoundationDocumentsTruthfulBoundary(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d6-firecracker-overlay-foundation-verification.md"))
	for _, required := range []string{
		"Planning-only/default construction remains inert.",
		"L8 authority is omitted from",
		"JSON and runtime target metadata;",
		"positive accepted-profile start path is deliberately unaccepted",
		"EmbeddedExpectedPinnedCallsiteEvidence",
		"l8_d6_live_firecracker_overlay",
		"dependency_unaccepted",
		"does not add a fake issuer, synthetic proof, active L8 claim, process start, or",
		"go test -count=20 ./internal/sandboxruntime/microvm/firecracker",
		"go test -race -count=5 ./internal/sandboxruntime/microvm/firecracker",
		"GOOS=darwin GOARCH=arm64",
		"GOOS=windows GOARCH=amd64",
		"make build",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D6 Firecracker overlay verification omits %q", required)
		}
	}
}

func TestL8D6FirecrackerOverlayFoundationStaysOffCommandPaths(t *testing.T) {
	for _, path := range phase34DefaultFirecrackerProductionFiles(t) {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"L8LiveConfigProvider", "VerifiedL8Profile", "VerifiedL8AssetLease"} {
			if strings.Contains(string(payload), forbidden) {
				t.Fatalf("default production path %s contains L8 authority marker %q", filepath.ToSlash(path), forbidden)
			}
		}
	}
}

func TestL8D6FirecrackerOverlayDependencyGateRemainsExplicitlyRed(t *testing.T) {
	payload := readL8CredentialDeliveryFile(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "l8_accepted_profile_dependency_test.go"))
	for _, required := range []string{
		"//go:build l8_d6_live_firecracker_overlay",
		"TestL8LiveBootConfigAcceptedAuthorityDependencyGate",
		"dependency_unaccepted: truthful D7 HL8E",
		"VerifiedL8Profile/VerifiedL8AssetLease fixture are required",
	} {
		if !strings.Contains(payload, required) {
			t.Fatalf("L8 D6 accepted-profile dependency gate omits %q", required)
		}
	}
}
