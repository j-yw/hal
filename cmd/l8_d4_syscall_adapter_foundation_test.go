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

func TestL8D4HostEvidenceHasOneProductionConsumerOutsideGuest(t *testing.T) {
	sources := readL8D4ProductionSources(t, filepath.Join("..", "internal", "sandboxruntime", "microvm"))
	if err := validateL8D4ProductionHostEvidenceBoundary(sources); err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name   string
		path   string
		source string
	}{
		{
			name: "extra guest issuer call",
			path: "guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name: "extra guest evidence import",
			path: "guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = syscallpolicy.ImportPinnedCallsiteEvidence(nil, syscallpolicy.VerifiedPolicyArtifact{}, syscallpolicy.ExpectedPinnedCallsiteEvidence{}) }
`,
		},
		{
			name: "guest issuer alias",
			path: "guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import policy "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
var reviewerMutation = policy.EmbeddedExpectedPinnedCallsiteEvidence
`,
		},
		{
			name: "guest dot import",
			path: "guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import . "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name: "second host consumer",
			path: "firecrackerhost/reviewer_mutation.go",
			source: `package firecrackerhost
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := cloneL8D4ProductionSources(sources)
			mutated[mutation.path] = mutation.source
			if err := validateL8D4ProductionHostEvidenceBoundary(mutated); err == nil {
				t.Fatal("host-evidence production guard accepted mutation")
			}
		})
	}

	t.Run("missing sole localresolver issuer", func(t *testing.T) {
		mutated := cloneL8D4ProductionSources(sources)
		const path = "assets/localresolver/l8_distribution_verifier.go"
		mutated[path] = strings.Replace(mutated[path], "expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()", "var expectedEvidence syscallpolicy.ExpectedPinnedCallsiteEvidence", 1)
		if mutated[path] == sources[path] {
			t.Fatal("mutation did not remove localresolver issuer")
		}
		if err := validateL8D4ProductionHostEvidenceBoundary(mutated); err == nil {
			t.Fatal("host-evidence production guard accepted missing sole issuer")
		}
	})

	t.Run("localresolver issuer receiver substitution", func(t *testing.T) {
		mutated := cloneL8D4ProductionSources(sources)
		const path = "assets/localresolver/l8_distribution_verifier.go"
		mutated[path] = strings.Replace(mutated[path], "syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()", "reviewerEvidence.EmbeddedExpectedPinnedCallsiteEvidence()", 1)
		if mutated[path] == sources[path] {
			t.Fatal("mutation did not substitute localresolver issuer receiver")
		}
		if err := validateL8D4ProductionHostEvidenceBoundary(mutated); err == nil {
			t.Fatal("host-evidence production guard accepted a non-syscallpolicy issuer receiver")
		}
	})
}

func readL8D4ProductionSources(t *testing.T, root string) map[string]string {
	t.Helper()
	sources := make(map[string]string)
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sources[filepath.ToSlash(relative)] = string(payload)
		return nil
	})
	if err != nil {
		t.Fatalf("read D4 production sources: %v", err)
	}
	return sources
}

func cloneL8D4ProductionSources(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source)+1)
	for path, text := range source {
		clone[path] = text
	}
	return clone
}

func validateL8D4ProductionHostEvidenceBoundary(sources map[string]string) error {
	const localResolverPath = "assets/localresolver/l8_distribution_verifier.go"
	const localResolverFunction = "VerifyL8DistributionBundle"
	definitions := map[string]string{
		"EmbeddedExpectedPinnedCallsiteEvidence": "guestagent/syscallpolicy/pinned_evidence_default.go",
		"ImportPinnedCallsiteEvidence":           "guestagent/syscallpolicy/pinned_evidence.go",
	}
	definitionCounts := make(map[string]int)
	referenceCounts := make(map[string]int)
	consumerCallCounts := make(map[string]int)

	for path, source := range sources {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return err
		}
		syscallPolicyAliases := make(map[string]bool)
		syscallPolicyDotImport := false
		for _, imported := range parsed.Imports {
			if imported.Path.Value != `"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"` {
				continue
			}
			if imported.Name == nil {
				syscallPolicyAliases["syscallpolicy"] = true
				continue
			}
			if imported.Name.Name == "." {
				syscallPolicyDotImport = true
				continue
			}
			if imported.Name.Name != "_" {
				syscallPolicyAliases[imported.Name.Name] = true
			}
		}
		declarationPositions := make(map[token.Pos]bool)
		selectorPositions := make(map[token.Pos]bool)
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if expectedPath, guarded := definitions[function.Name.Name]; guarded {
				if path != expectedPath {
					return &l8D4GuestAuthorityGuardError{"host-evidence authority declaration moved outside its frozen leaf"}
				}
				definitionCounts[function.Name.Name]++
				declarationPositions[function.Name.Pos()] = true
			}
			if path == localResolverPath && function.Name.Name == localResolverFunction && function.Body != nil {
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch callable := call.Fun.(type) {
					case *ast.SelectorExpr:
						receiver, receiverOK := callable.X.(*ast.Ident)
						if _, guarded := definitions[callable.Sel.Name]; guarded && receiverOK && syscallPolicyAliases[receiver.Name] {
							consumerCallCounts[callable.Sel.Name]++
						}
					case *ast.Ident:
						if _, guarded := definitions[callable.Name]; guarded && syscallPolicyDotImport {
							consumerCallCounts[callable.Name]++
						}
					}
					return true
				})
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok {
				selectorPositions[selector.Sel.Pos()] = true
				if _, guarded := definitions[selector.Sel.Name]; guarded {
					referenceCounts[selector.Sel.Name]++
				}
			}
			return true
		})
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || declarationPositions[identifier.Pos()] || selectorPositions[identifier.Pos()] {
				return true
			}
			if _, guarded := definitions[identifier.Name]; guarded {
				referenceCounts[identifier.Name]++
			}
			return true
		})
	}

	for name := range definitions {
		if definitionCounts[name] != 1 {
			return &l8D4GuestAuthorityGuardError{"host-evidence authority must have one frozen leaf declaration"}
		}
		if referenceCounts[name] != 1 || consumerCallCounts[name] != 1 {
			return &l8D4GuestAuthorityGuardError{"localresolver VerifyL8DistributionBundle must be the sole direct production consumer of host evidence"}
		}
	}
	return nil
}

func TestL8D4SyscallAdapterFoundationIsTruthfullyDocumented(t *testing.T) {
	document := readL8D4SyscallAdapterFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d4-syscall-adapter-foundation-verification.md"))
	normalizedDocument := strings.Join(strings.Fields(document), " ")
	for _, marker := range []string{
		"does not claim D4 live syscall enforcement",
		"policy_install_inventory_d7_gen.go",
		"hal/l8/d4-native-install-table/linux-amd64/v1",
		"NewSyscallPolicyCoreKernel",
		"adapter-callsite inventory is empty",
		"guest-side constructor never loads or imports HL8E",
		"local resolver remains the sole production consumer of the host-only expected HL8E issuer",
		"package-wide production guard",
		"every non-test Go file",
		"every guest package has zero guest references",
		"stable sanitized dependency failure",
		"l8_d4_full_syscall_adapter",
		"unstarted -> claimed -> executed -> finalized",
		"No D7 rule",
	} {
		if !strings.Contains(normalizedDocument, marker) {
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
