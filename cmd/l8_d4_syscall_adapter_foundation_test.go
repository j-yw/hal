package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
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
		"guest-side constructor never loads or imports HL8E",
		"local resolver remains the sole production consumer of the host-only expected HL8E issuer",
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
	for _, forbidden := range []string{"return options.Kernel", "syscall.Syscall", "unix.Syscall", "unsafe.Pointer", "os/exec", "EmbeddedExpectedPinnedCallsiteEvidence", "ImportPinnedCallsiteEvidence", "ExpectedPinnedCallsiteEvidence"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("D4 foundation contains forbidden live behavior %q", forbidden)
		}
	}
	if err := validateL8D4GuestPolicyAuthoritySource(source); err != nil {
		t.Fatal(err)
	}
}

func TestL8D4SyscallAdapterFoundationGuestAuthorityGuardRejectsMutations(t *testing.T) {
	source := readL8D4SyscallAdapterFile(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "credentialhelper", "linux", "syscall_policy_kernel_linux.go"))
	artifactCall := "artifact, err := syscallpolicy.EmbeddedVerifiedPolicyArtifact()"
	mutations := []struct {
		name    string
		old     string
		replace string
	}{
		{name: "host evidence issuer", old: artifactCall, replace: artifactCall + "\n\t_, _ = syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()"},
		{name: "host evidence import", old: artifactCall, replace: artifactCall + "\n\t_, _ = syscallpolicy.ImportPinnedCallsiteEvidence(nil, syscallpolicy.VerifiedPolicyArtifact{}, syscallpolicy.ExpectedPinnedCallsiteEvidence{})"},
		{name: "missing embedded artifact", old: artifactCall, replace: "var artifact syscallpolicy.VerifiedPolicyArtifact"},
		{name: "duplicate embedded artifact", old: artifactCall, replace: artifactCall + "\n\t_, _ = syscallpolicy.EmbeddedVerifiedPolicyArtifact()"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(source, mutation.old, mutation.replace, 1)
			if mutated == source {
				t.Fatal("mutation did not change constructor source")
			}
			if err := validateL8D4GuestPolicyAuthoritySource(mutated); err == nil {
				t.Fatal("guest authority guard accepted mutation")
			}
		})
	}
}

func validateL8D4GuestPolicyAuthoritySource(source string) error {
	parsed, err := parser.ParseFile(token.NewFileSet(), "syscall_policy_kernel_linux.go", source, 0)
	if err != nil {
		return err
	}
	var constructor *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "NewSyscallPolicyCoreKernel" {
			constructor = function
			break
		}
	}
	if constructor == nil || constructor.Body == nil {
		return &l8D4GuestAuthorityGuardError{"NewSyscallPolicyCoreKernel is unavailable"}
	}
	counts := map[string]int{}
	ast.Inspect(constructor.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok {
			counts[selector.Sel.Name]++
		}
		return true
	})
	if counts["EmbeddedVerifiedPolicyArtifact"] != 1 {
		return &l8D4GuestAuthorityGuardError{"guest constructor must load the embedded HL8Q artifact exactly once"}
	}
	for _, forbidden := range []string{"EmbeddedExpectedPinnedCallsiteEvidence", "ImportPinnedCallsiteEvidence"} {
		if counts[forbidden] != 0 {
			return &l8D4GuestAuthorityGuardError{"guest constructor reached host-only HL8E authority"}
		}
	}
	return nil
}

type l8D4GuestAuthorityGuardError struct{ message string }

func (err *l8D4GuestAuthorityGuardError) Error() string { return err.message }

func readL8D4SyscallAdapterFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(payload)
}
