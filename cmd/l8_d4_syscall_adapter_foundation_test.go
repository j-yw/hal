package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D4SyscallAdapterFoundationIsTruthfullyDocumented(t *testing.T) {
	document := readL8D4SyscallAdapterFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d4-syscall-adapter-foundation-verification.md"))
	for _, marker := range []string{
		"does not claim D4 live syscall enforcement",
		"policy_install_inventory_d7_gen.go",
		"hal/l8/d4-native-install-table/linux-amd64/v1",
		"NewSyscallPolicyCoreKernel",
		"adapter-callsite inventory is empty",
		"stable sanitized dependency failure",
		"l8_d4_full_syscall_adapter",
		"unstarted -> claimed -> executed -> finalized",
		"No D7 rule",
	} {
		if !strings.Contains(document, marker) {
			t.Errorf("D4 foundation verification omits %q", marker)
		}
	}
}

func TestL8D4SyscallAdapterFoundationConstructorIsFailClosed(t *testing.T) {
	source := readL8D4SyscallAdapterFile(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "credentialhelper", "linux", "syscall_policy_kernel_linux.go"))
	ordered := []string{
		"coreKernelDependencyError(options.Kernel)",
		"policyInstallInventorySHA256()",
		"syscallpolicy.EmbeddedVerifiedPolicyArtifact()",
		"syscallpolicy.NewPolicy(artifact)",
		"policyAdapterCallsiteInventoryReady(policy)",
		"syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()",
		"rolebootstrap.EmbeddedGeneratedArtifact()",
		"subtle.ConstantTimeCompare",
		"return nil, credentialhelper.ErrContractDependency",
	}
	position := -1
	for _, marker := range ordered {
		next := strings.Index(source[position+1:], marker)
		if next < 0 {
			t.Fatalf("D4 constructor omits ordered marker %q", marker)
		}
		position += next + 1
	}
	for _, forbidden := range []string{"return options.Kernel", "syscall.Syscall", "unix.Syscall", "unsafe.Pointer", "os/exec"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("D4 foundation contains forbidden live behavior %q", forbidden)
		}
	}
}

func readL8D4SyscallAdapterFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(payload)
}
