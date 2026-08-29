package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7NativeRoleBootstrapDoc = "sandbox-runtime-v2-l8-d7-native-role-bootstrap.md"

func TestL8D7NativeRoleBootstrapVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7NativeRoleBootstrapDoc))), " ")
	for _, required := range []string{
		"default-off",
		"tagged issuer",
		"l8_verified_native_artifact",
		"EmbeddedGeneratedArtifact",
		"generated_artifact_d7_gen.go",
		"PolicySHA256",
		"NativeSourceSHA256",
		"NativeCallsiteSHA256",
		"NativeInstallTableSHA256",
		"freestanding static Linux-amd64 ELF `_start`",
		"as`/`ld`",
		"no gcc libc",
		"ET_EXEC",
		"no `INTERP`",
		"no libc `NEEDED`",
		"does not pull a Go runtime",
		"fails closed with exit 127",
		"does not claim D7 live",
		"does not claim HL8E issuance",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"go test ./internal/sandboxruntime/microvm/guestagent/rolebootstrap -count=1",
		"go test -tags=l8_verified_native_artifact ./internal/sandboxruntime/microvm/guestagent/rolebootstrap -count=1",
		"go test ./tools/microvm/l8/role-bootstrap/generate -count=1",
		"go test ./cmd -run '^TestL8D7NativeRoleBootstrap' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("native role-bootstrap verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"HL8E issuance is accepted",
		"D7 live is accepted",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("native role-bootstrap verification document contains forbidden claim %q", forbidden)
		}
	}
}
