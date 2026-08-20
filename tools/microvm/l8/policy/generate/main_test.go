package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D7ArtifactGenerationIsDeterministicAndMatchesCheckedInOutputs(t *testing.T) {
	root := repositoryRoot(t)
	first, err := generate(root)
	if err != nil {
		t.Fatalf("generate first copy: %v", err)
	}
	second, err := generate(root)
	if err != nil {
		t.Fatalf("generate second copy: %v", err)
	}
	if !bytes.Equal(first.artifact, second.artifact) || !bytes.Equal(first.guestSource, second.guestSource) {
		t.Fatal("identical locked inputs produced different D7 outputs")
	}
	for path, want := range first.files() {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("read checked-in D7 output %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("checked-in D7 output %s is stale", path)
		}
	}
}

func TestL8D7CatalogDerivationPreservesTheFrozenLegacySysctlException(t *testing.T) {
	entries, err := parseCatalog([]byte("const (\n SYS_READ = 0\n SYS__SYSCTL = 156\n)\n"), 450)
	if err != nil {
		t.Fatalf("parseCatalog() error = %v", err)
	}
	if len(entries) != 2 || entries[0] != (catalogEntry{number: 0, name: "read"}) || entries[1] != (catalogEntry{number: 156, name: "_sysctl"}) {
		t.Fatalf("catalog entries = %#v", entries)
	}
	if _, err := parseCatalog([]byte("const (\n SYS__OTHER = 155\n)\n"), 450); err == nil {
		t.Fatal("noncanonical leading-underscore syscall was accepted")
	}
}

func TestL8D7EvidenceIssuanceRejectsBinaryWithoutEmbeddedArtifact(t *testing.T) {
	root := repositoryRoot(t)
	outputs, err := generate(root)
	if err != nil {
		t.Fatalf("generate artifact: %v", err)
	}
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	if _, err := generateEvidence(root, binaryPath, outputs); err == nil || !strings.Contains(err.Error(), "does not embed the exact D7 HL8Q artifact") {
		t.Fatalf("generateEvidence() error = %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
