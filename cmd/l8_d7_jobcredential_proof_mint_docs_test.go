package cmd

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const l8D7JobCredentialProofMintDoc = "sandbox-runtime-v2-l8-d7-jobcredential-proof-mint.md"

func TestL8D7JobCredentialProofMintVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7JobCredentialProofMintDoc))), " ")
	for _, required := range []string{
		"default-off",
		"HL8E remains unissued",
		"does not change live D7 stub fatals",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"D7 prepared-Linux acceptance remains unaccepted",
		"Live D7 remains unaccepted",
		"credentialclient",
		"must not import `firecrackerhost`",
		"L8JobCredentialRuntime",
		"NewJobCredentialActiveProof",
		"NewJobCredentialCleanupProof",
		"ActiveProofID",
		"dependency_unaccepted",
		"ErrJobCredentialIdentityMismatch",
		"ErrJobCredentialRevisionStale",
		"live secret bodies",
		"Default command paths stay unwired",
		"NewProductionL8JobCredentialRuntime",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'JobCredentialRuntime|ProofMint|RecoverMints|RecoverFailsClosed' -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1",
		"go test ./cmd -run '^TestL8D7JobCredentialProofMint' -count=1",
		"go vet ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxruntime/microvm/guestagent/server/credentialclient ./cmd",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"mint JobCredential proofs inside guest `credentialclient`",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
		"treat L5 images as L8 proof",
		"L5-as-L8",
		"sandboxd",
		"`hal run`",
		"`hal auto`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("D7 JobCredential proof mint verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"HL8E is issued",
		"D7 live is accepted",
		"D7 prepared-Linux acceptance is accepted",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("D7 JobCredential proof mint verification document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D7JobCredentialProofMintRemainsDefaultOff(t *testing.T) {
	targets := []string{
		"run_sandbox.go", "auto_sandbox.go", "factory.go", "factory_sandbox_executor.go",
	}
	sandboxdFiles, err := filepath.Glob("sandboxd*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range sandboxdFiles {
		if !strings.HasSuffix(path, "_test.go") {
			targets = append(targets, path)
		}
	}
	for _, path := range targets {
		source := readL8CredentialDeliveryFile(t, path)
		for _, marker := range []string{
			"NewProductionL8JobCredentialRuntime",
			"mintL8JobCredentialActiveProofFromAdmittedHelperSuccess",
			"mintL8JobCredentialCleanupProofFromAdmittedHelperSuccess",
			"NewJobCredentialActiveProof",
			"NewJobCredentialCleanupProof",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("default production path %s wires JobCredential proof mint %s", filepath.ToSlash(path), marker)
			}
		}
	}
}

func TestL8D7JobCredentialProofMintStaysOnHostRuntime(t *testing.T) {
	runtimePath := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_runtime.go")
	source := readL8CredentialDeliveryFile(t, runtimePath)
	for _, required := range []string{
		"mintL8JobCredentialActiveProofFromAdmittedHelperSuccess",
		"mintL8JobCredentialCleanupProofFromAdmittedHelperSuccess",
		"guestResult.ActiveProofID",
		"NewJobCredentialActiveProof",
		"NewJobCredentialCleanupProof",
		"errL8JobCredentialRuntimeDependencyUnaccepted",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("host runtime omits helper-success mint marker %q", required)
		}
	}
	for _, invented := range []string{
		`ProofID: "active-1"`,
		`ProofID: fmt.Sprintf("active-%d"`,
		`ProofID: fmt.Sprintf("cleanup-%d", revision+1)`,
	} {
		if strings.Contains(source, invented) {
			t.Fatalf("host runtime still invents helper-success proof id %q", invented)
		}
	}

	root := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "credentialclient")
	set := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(set, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, spec := range file.Imports {
			if spec.Path == nil {
				continue
			}
			if strings.Contains(spec.Path.Value, "microvm/firecrackerhost") {
				t.Errorf("credentialclient production file %s imports firecrackerhost", filepath.ToSlash(path))
			}
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(payload)
		if strings.Contains(text, "sandboxruntime.NewJobCredentialActiveProof") ||
			strings.Contains(text, "sandboxruntime.NewJobCredentialCleanupProof") {
			t.Errorf("credentialclient production file %s mints host JobCredential proofs", filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestL8D7JobCredentialProofMintDoesNotChangeLiveD7StubFatals(t *testing.T) {
	path := l8D7PreparedLinuxLiveStubPath()
	source := readL8CredentialDeliveryFile(t, path)
	if err := l8D7ValidatePreparedLinuxRedStub(source); err != nil {
		t.Fatalf("proof mint slice changed live D7 stub fatals: %v", err)
	}
}
