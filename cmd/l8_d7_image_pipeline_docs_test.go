package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7ImagePipelineDoc = "sandbox-runtime-v2-l8-d7-image-pipeline.md"

func TestL8D7ImagePipelineVerificationContract(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7ImagePipelineDoc))), " ")
	for _, required := range []string{
		"scripts exist",
		"Issuance is not accepted",
		"VerifyL8DistributionBundle` remains the sole issuer",
		"Parent L7 evidence is required",
		"seven-file bundle",
		"SHA256SUMS",
		"distribution-manifest.json",
		"final-inspection.json",
		"provenance.json",
		"rootfs.ext4",
		"sources.lock.json",
		"vmlinux",
		"HL8E is still unissued",
		"Builds fail closed",
		"tools/microvm/l8/role-bootstrap/build.sh",
		"as`/`ld` only",
		"tools/microvm/l8/role-bootstrap/hal-guest-role-bootstrap.S",
		"A Go `cmd/hal-guest-role-bootstrap` package is not an L8 native identity",
		"l8-production-credentials-image",
		"guest-agent-v2",
		"credential_delivery_v2",
		"ssh_agent_relay_v1",
		"l8-production-credentials-v1",
		"--pull=never",
		"--network=none",
		"node-v22.22.0.tar.xz",
		"pi-coding-agent-0.82.1.tgz",
		"pi-shrinkwrap-0.82.1.json",
		"exact L8 cache manifest is checked in",
		"external cache directory",
		"tools/microvm/l8/verify-reproducible.sh",
		"tools/microvm/l8/verify-image-profile.sh",
		"65,536 inodes",
		"512 MiB",
		"debugfs ls -p -r",
		"PEM-style private-key marker",
		"not an exhaustive secret detector",
		"--cache \"$HAL_L8_BUILD_CACHE\"",
		"--output \"$HAL_L8_DISTRIBUTION\"",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"go test ./tools/microvm/l8 -count=1",
		"go test ./cmd -run 'TestL8D7ImagePipeline' -count=1",
		"bash -n tools/microvm/l8/build.sh",
		"verify-final-image.sh tools/microvm/l8/verify-image-profile.sh",
		"go vet ./tools/microvm/l8 ./cmd",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
		"fake-only",
		"does not boot a VM",
		"run a full Buildroot build",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D7 image pipeline verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"D7 prepared-Linux acceptance is complete",
		"HL8E is issued",
		"issuance is accepted",
		"D7 live proof is accepted",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 D7 image pipeline verification document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D7ImagePipelineDocumentForbidsCompleteClaims(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7ImagePipelineDoc))
	normalized := strings.Join(strings.Fields(doc), " ")
	if strings.Contains(normalized, "This slice claims L8 complete") {
		t.Fatal("image pipeline document claims L8 complete")
	}
	if !strings.Contains(normalized, "does not generate `verified-pinned-callsites.hl8e` from a fixture") {
		t.Fatal("image pipeline document must forbid generating HL8E from a fixture")
	}
	if !strings.Contains(normalized, "does not treat an L5 rootfs/vmlinux as an L8 production image") {
		t.Fatal("image pipeline document must forbid treating L5 assets as L8 production images")
	}
	if !strings.Contains(normalized, "call `VerifyL8DistributionBundle` with dummy parent L7 as a pass") {
		t.Fatal("image pipeline document must forbid dummy parent L7 issuer passes")
	}
}
