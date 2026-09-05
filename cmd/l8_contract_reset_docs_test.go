package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const l8ContractResetDoc = "sandbox-runtime-v2-l8-credential-runtime-contract-reset.md"

func TestL8ContractResetArchitectureDecision(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8ContractResetDoc))), " ")
	for _, required := range []string{
		"issue #49",
		"00ebb45f",
		"5068151561",
		"5068157402",
		"5068162708",
		"one fresh Firecracker VM per job",
		"hal-init -> hal-guest-agent -> job workload",
		"host owns credential authority, network authority, and job lifecycle",
		"HTTP credential proxy",
		"private tmpfs file",
		"SSH-agent relay",
		"L8 proves usability and cleanup",
		"L10 owns strict secure-default selection",
		"HL8E v1 remains unissued",
		"offline diagnostic",
		"not a runtime CFI control",
		"does not currently install a guest seccomp filter",
		"must not be presented as an active L8 control",
		"future product tests",
		"hal-guest-credential-helper",
		"hal-guest-mount-monitor",
		"hal-guest-workload-shim",
		"not mandatory processes or image roles",
		"unconditional exit 127",
		"later red test proves a missing security property",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("L8 contract-reset document omits %q", required)
		}
	}
}

func TestL8ContractResetSupersedesClaimsWithoutRewritingHistory(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8ContractResetDoc))), " ")
	for _, required := range []string{
		"does not rewrite or delete the D2-D7 slice records",
		"four named blockers",
		"historical decomposition, not the new acceptance checklist",
		"issue comment `5302732597`",
		"fake-only product-guard results",
		"no-skip prepared-Linux credential E2E",
		"does not establish L8 completion",
		"This change is documentation and a documentation guard only",
		"No runtime behavior changes here",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("L8 contract-reset document omits supersession marker %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"prepared-Linux acceptance passed",
		"HL8E is issued",
		"strict secure default is active",
		"depends on exact image identity, default-deny seccomp",
	} {
		if strings.Contains(doc, forbidden) {
			t.Errorf("L8 contract-reset document contains forbidden completion claim %q", forbidden)
		}
	}
}

func TestL8ContractResetImplementationOrder(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8ContractResetDoc))), " ")
	ordered := []string{
		"1. RED: detach HL8E from the runnable L8 path",
		"2. RED: lock the minimum guest topology",
		"3. GREEN: compose one host credential owner",
		"4. GREEN: bind activation to one fresh VM and job",
		"5. LIVE: prove each delivery mode",
		"6. LIVE: run the terminal and restart matrix",
		"7. LIVE: prove absence and redaction",
		"8. HANDOFF: unlock L10 only after L8 passes",
	}
	previous := -1
	for _, marker := range ordered {
		index := strings.Index(doc, marker)
		if index < 0 {
			t.Fatalf("L8 contract-reset implementation order omits %q", marker)
		}
		if index <= previous {
			t.Fatalf("L8 contract-reset implementation marker %q is out of order", marker)
		}
		previous = index
	}
	for _, required := range []string{
		"red test is committed before its minimal implementation",
		"http_only",
		"file_tmpfs_only",
		"ssh_agent_only",
		"all_modes",
		"failure_recovery_matrix",
		"a skip is a blocker",
		"go test ./cmd -run '^TestL8ContractReset' -count=1",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("L8 contract-reset implementation plan omits %q", required)
		}
	}
}

func TestL8ContractResetPreservesLegacyAndStrictBoundaries(t *testing.T) {
	designRoot := filepath.Join("..", "docs", "design")
	reset := readL8CredentialDeliveryFile(t, filepath.Join(designRoot, l8ContractResetDoc))
	canonical := readL8CredentialDeliveryFile(t, filepath.Join(designRoot, "sandbox-runtime-v2-linux-completion-architecture.md"))
	legacy := readL8CredentialDeliveryFile(t, filepath.Join(designRoot, l8CredentialArchitectureDoc))
	hostBoundary := readL8CredentialDeliveryFile(t, filepath.Join(designRoot, l8HostOwnedStrictBoundaryDoc))
	build := readL8CredentialDeliveryFile(t, filepath.Join("..", "tools", "microvm", "l8", "build.sh"))
	finalVerifier := readL8CredentialDeliveryFile(t, filepath.Join("..", "tools", "microvm", "l8", "verify-final-image.sh"))
	liveWrapper := readL8CredentialDeliveryFile(t, filepath.Join("..", "tools", "microvm", "l8", "verify-selected-live.sh"))

	for _, required := range []string{
		"distinct minimal runtime profile, bundle verifier, and selector",
		"Legacy `tools/microvm/l8/build.sh`, `verify-final-image.sh`, and `VerifyL8DistributionBundle`",
		"remain unchanged and fail closed when HL8E is absent",
		"fresh Jailer-owned launch proof",
		"Direct Firecracker credential evidence is insufficient",
	} {
		if !strings.Contains(reset, required) {
			t.Errorf("L8 contract-reset document omits preserved boundary %q", required)
		}
	}
	if !strings.Contains(build, "HL8E is unissued; L8 builds fail closed") ||
		!strings.Contains(finalVerifier, "HL8E is unissued; L8 final-image verification fails closed") {
		t.Fatal("legacy D7 build/final-image HL8E gates must remain fail closed")
	}
	for name, doc := range map[string]string{"canonical architecture": canonical, "historical L8 architecture": legacy} {
		if !strings.Contains(doc, l8ContractResetDoc) || !strings.Contains(doc, "current selected L8 topology") {
			t.Errorf("%s does not resolve the L8 topology authority through %s", name, l8ContractResetDoc)
		}
	}
	for _, required := range []string{"mandatory for every strict launch", "fresh Jailer-owned launch proof"} {
		if !strings.Contains(hostBoundary, required) || !strings.Contains(reset, required) {
			t.Errorf("reset and host boundary do not both preserve Jailer invariant %q", required)
		}
	}
	for _, required := range []string{
		"http_only file_tmpfs_only ssh_agent_only all_modes failure_recovery_matrix",
		"skipped != 0",
		"subtest_pass[required[i]] != 1",
	} {
		if !strings.Contains(liveWrapper, required) {
			t.Errorf("selected live wrapper omits no-skip invariant %q", required)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "tools", "microvm", "l8", "policy", "verified-pinned-callsites.hl8e")); err == nil {
		t.Fatal("HL8E must remain unissued; the contract reset cannot manufacture it")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
