package cmd

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8D4HostEvidenceHasOneRepositoryWideProductionConsumer(t *testing.T) {
	sources := readL8D4RepositoryProductionSources(t, "..")
	if err := validateL8D4RepositoryHostEvidenceBoundary(sources); err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name   string
		path   string
		source string
	}{
		{
			name: "extra guest issuer call",
			path: "internal/sandboxruntime/microvm/guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name: "extra guest evidence import",
			path: "internal/sandboxruntime/microvm/guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = syscallpolicy.ImportPinnedCallsiteEvidence(nil, syscallpolicy.VerifiedPolicyArtifact{}, syscallpolicy.ExpectedPinnedCallsiteEvidence{}) }
`,
		},
		{
			name: "guest issuer alias",
			path: "internal/sandboxruntime/microvm/guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import policy "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
var reviewerMutation = policy.EmbeddedExpectedPinnedCallsiteEvidence
`,
		},
		{
			name: "guest dot import",
			path: "internal/sandboxruntime/microvm/guestagent/credentialhelper/linux/reviewer_mutation.go",
			source: `package linux
import . "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name: "second host consumer",
			path: "internal/sandboxruntime/microvm/firecrackerhost/reviewer_mutation.go",
			source: `package firecrackerhost
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerMutation() { _, _ = syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name: "outside microvm cmd consumer",
			path: "cmd/reviewer_mutation.go",
			source: `package cmd
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerOutsideMicroVM() { _, _ = syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name: "outside microvm build tagged consumer",
			path: "cmd/reviewer_mutation_variant.go",
			source: `//go:build reviewer_guard_variant

package cmd

import policy "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerBuildVariant() { _, _ = policy.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name:   "raw string syscallpolicy import",
			path:   "cmd/reviewer_raw_import.go",
			source: "package cmd\nimport policy `github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy`\nfunc reviewerRawImport() { _, _ = policy.EmbeddedExpectedPinnedCallsiteEvidence() }\n",
		},
		{
			name:   "raw dot syscallpolicy import",
			path:   "cmd/reviewer_raw_dot_import.go",
			source: "package cmd\nimport . `github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy`\nfunc reviewerRawDotImport() { _, _ = EmbeddedExpectedPinnedCallsiteEvidence() }\n",
		},
		{
			name:   "escaped syscallpolicy import",
			path:   "cmd/reviewer_escaped_import.go",
			source: "package cmd\nimport policy \"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolic\\u0079\"\nfunc reviewerEscapedImport() { _, _ = policy.EmbeddedExpectedPinnedCallsiteEvidence() }\n",
		},
		{
			name: "go linkname issuer alias",
			path: "cmd/reviewer_linkname.go",
			source: `package cmd
import _ "unsafe"
//go:linkname reviewerIssuer github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence
func reviewerIssuer() (any, error)
`,
		},
		{
			name: "unrelated same named production method",
			path: "cmd/reviewer_unrelated.go",
			source: `package cmd
type reviewerEvidence struct{}
func (reviewerEvidence) EmbeddedExpectedPinnedCallsiteEvidence() {}
func reviewerUnrelatedName() { reviewerEvidence{}.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
		{
			name: "shadowed import receiver spelling",
			path: "cmd/reviewer_shadowed_import.go",
			source: `package cmd
import policy "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
type reviewerShadowEvidence struct{}
func (reviewerShadowEvidence) EmbeddedExpectedPinnedCallsiteEvidence() {}
func reviewerShadowedImport() {
	_ = policy.VerifiedPolicyArtifact{}
	policy := reviewerShadowEvidence{}
	policy.EmbeddedExpectedPinnedCallsiteEvidence()
}
`,
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := parser.ParseFile(token.NewFileSet(), mutation.path, mutation.source, parser.ParseComments); err != nil {
				t.Fatalf("reviewer mutation must be valid Go syntax: %v", err)
			}
			mutated := cloneL8D4ProductionSources(sources)
			mutated[mutation.path] = mutation.source
			if err := validateL8D4RepositoryHostEvidenceBoundary(mutated); err == nil {
				t.Fatal("host-evidence production guard accepted mutation")
			}
		})
	}

	t.Run("missing sole localresolver issuer", func(t *testing.T) {
		mutated := cloneL8D4ProductionSources(sources)
		const path = "internal/sandboxruntime/microvm/assets/localresolver/l8_distribution_verifier.go"
		mutated[path] = strings.Replace(mutated[path], "expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()", "var expectedEvidence syscallpolicy.ExpectedPinnedCallsiteEvidence", 1)
		if mutated[path] == sources[path] {
			t.Fatal("mutation did not remove localresolver issuer")
		}
		if err := validateL8D4RepositoryHostEvidenceBoundary(mutated); err == nil {
			t.Fatal("host-evidence production guard accepted missing sole issuer")
		}
	})

	t.Run("localresolver issuer receiver substitution", func(t *testing.T) {
		mutated := cloneL8D4ProductionSources(sources)
		const path = "internal/sandboxruntime/microvm/assets/localresolver/l8_distribution_verifier.go"
		mutated[path] = strings.Replace(mutated[path], "syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()", "reviewerEvidence.EmbeddedExpectedPinnedCallsiteEvidence()", 1)
		if mutated[path] == sources[path] {
			t.Fatal("mutation did not substitute localresolver issuer receiver")
		}
		if err := validateL8D4RepositoryHostEvidenceBoundary(mutated); err == nil {
			t.Fatal("host-evidence production guard accepted a non-syscallpolicy issuer receiver")
		}
	})

	benignSources := []struct {
		name   string
		path   string
		source string
	}{
		{
			name: "test consumer excluded",
			path: "cmd/reviewer_mutation_test.go",
			source: `package cmd
import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
func reviewerTestOnly() { _, _ = syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence() }
`,
		},
	}
	for _, benign := range benignSources {
		t.Run(benign.name, func(t *testing.T) {
			mutated := cloneL8D4ProductionSources(sources)
			mutated[benign.path] = benign.source
			if err := validateL8D4RepositoryHostEvidenceBoundary(mutated); err != nil {
				t.Fatalf("host-evidence production guard rejected benign source: %v", err)
			}
		})
	}

	const generatedIssuerPath = "internal/sandboxruntime/microvm/guestagent/syscallpolicy/pinned_callsite_evidence_expected_d7_gen.go"
	const generatedIssuer = `// Code generated by tools/microvm/l8/policy/generate; DO NOT EDIT.
//go:build l8_verified_pinned_callsite_evidence

package syscallpolicy

var expectedPinnedCallsiteEvidenceSHA256 = [32]byte{1}

func EmbeddedExpectedPinnedCallsiteEvidence() (ExpectedPinnedCallsiteEvidence, error) {
	return ExpectedPinnedCallsiteEvidence{
		sha256: expectedPinnedCallsiteEvidenceSHA256,
		issuer: expectedEvidenceIssuer{issued: true},
	}, nil
}
`
	t.Run("generated positive-tag issuer is the complementary declaration", func(t *testing.T) {
		mutated := cloneL8D4ProductionSources(sources)
		mutated[generatedIssuerPath] = generatedIssuer
		if err := validateL8D4RepositoryHostEvidenceBoundary(mutated); err != nil {
			t.Fatalf("host-evidence production guard rejected frozen generated issuer: %v", err)
		}
	})

	issuerMutations := []struct {
		name   string
		path   string
		source string
	}{
		{
			name:   "wrong generated tag",
			path:   generatedIssuerPath,
			source: strings.Replace(generatedIssuer, "//go:build l8_verified_pinned_callsite_evidence", "//go:build linux || l8_verified_pinned_callsite_evidence", 1),
		},
		{
			name:   "both issuers active",
			path:   generatedIssuerPath,
			source: strings.Replace(generatedIssuer, "//go:build l8_verified_pinned_callsite_evidence", "//go:build !l8_verified_pinned_callsite_evidence", 1),
		},
		{
			name:   "generated issuer at wrong path",
			path:   "internal/sandboxruntime/microvm/guestagent/syscallpolicy/reviewer_expected_d7_gen.go",
			source: generatedIssuer,
		},
		{
			name: "duplicate generated declaration",
			path: generatedIssuerPath,
			source: generatedIssuer + `
func EmbeddedExpectedPinnedCallsiteEvidence() (ExpectedPinnedCallsiteEvidence, error) {
	return ExpectedPinnedCallsiteEvidence{}, nil
}
`,
		},
	}
	for _, mutation := range issuerMutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := cloneL8D4ProductionSources(sources)
			if mutation.path != generatedIssuerPath {
				mutated[generatedIssuerPath] = generatedIssuer
			}
			mutated[mutation.path] = mutation.source
			if err := validateL8D4RepositoryHostEvidenceBoundary(mutated); err == nil {
				t.Fatal("host-evidence production guard accepted invalid issuer composition")
			}
		})
	}
}

func readL8D4RepositoryProductionSources(t *testing.T, root string) map[string]string {
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

func validateL8D4RepositoryHostEvidenceBoundary(sources map[string]string) error {
	const syscallPolicyImportPath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
	const embeddedDeclarationPath = "internal/sandboxruntime/microvm/guestagent/syscallpolicy/pinned_evidence_default.go"
	const generatedDeclarationPath = "internal/sandboxruntime/microvm/guestagent/syscallpolicy/pinned_callsite_evidence_expected_d7_gen.go"
	const importDeclarationPath = "internal/sandboxruntime/microvm/guestagent/syscallpolicy/pinned_evidence.go"
	const localResolverPath = "internal/sandboxruntime/microvm/assets/localresolver/l8_distribution_verifier.go"
	const evidenceBuildTag = "l8_verified_pinned_callsite_evidence"
	guardedNames := []string{
		"EmbeddedExpectedPinnedCallsiteEvidence",
		"ImportPinnedCallsiteEvidence",
	}
	expectedSpellings := map[string]map[string]int{
		embeddedDeclarationPath: {
			"EmbeddedExpectedPinnedCallsiteEvidence": 1,
			"ImportPinnedCallsiteEvidence":           0,
		},
		generatedDeclarationPath: {
			"EmbeddedExpectedPinnedCallsiteEvidence": 1,
			"ImportPinnedCallsiteEvidence":           0,
		},
		importDeclarationPath: {
			"EmbeddedExpectedPinnedCallsiteEvidence": 0,
			"ImportPinnedCallsiteEvidence":           1,
		},
		localResolverPath: {
			"EmbeddedExpectedPinnedCallsiteEvidence": 1,
			"ImportPinnedCallsiteEvidence":           1,
		},
	}
	seenAllowedFiles := make(map[string]int)
	issuerConstraints := make(map[string]constraint.Expr)

	for path, source := range sources {
		path = filepath.ToSlash(filepath.Clean(path))
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		allowedCounts, allowed := expectedSpellings[path]
		for _, name := range guardedNames {
			want := 0
			if allowed {
				want = allowedCounts[name]
			}
			if strings.Count(source, name) != want {
				return &l8D4GuestAuthorityGuardError{"host-evidence authority spelling escaped its frozen production location"}
			}
		}
		if !allowed {
			continue
		}
		seenAllowedFiles[path]++
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
		if err != nil {
			return err
		}
		switch path {
		case embeddedDeclarationPath:
			buildConstraint, err := validateL8D4HostEvidenceBuildConstraint(source, evidenceBuildTag, false)
			if err != nil {
				return err
			}
			issuerConstraints[path] = buildConstraint
			if err := validateL8D4HostEvidenceDeclaration(parsed, "EmbeddedExpectedPinnedCallsiteEvidence", nil, []string{"ExpectedPinnedCallsiteEvidence", "error"}); err != nil {
				return err
			}
		case generatedDeclarationPath:
			buildConstraint, err := validateL8D4HostEvidenceBuildConstraint(source, evidenceBuildTag, true)
			if err != nil {
				return err
			}
			issuerConstraints[path] = buildConstraint
			if err := validateL8D4HostEvidenceDeclaration(parsed, "EmbeddedExpectedPinnedCallsiteEvidence", nil, []string{"ExpectedPinnedCallsiteEvidence", "error"}); err != nil {
				return err
			}
		case importDeclarationPath:
			if err := validateL8D4HostEvidenceDeclaration(parsed, "ImportPinnedCallsiteEvidence", []string{"[]byte", "VerifiedPolicyArtifact", "ExpectedPinnedCallsiteEvidence"}, []string{"PinnedCallsiteEvidenceSet", "error"}); err != nil {
				return err
			}
		case localResolverPath:
			if err := validateL8D4HostEvidenceConsumer(parsed, syscallPolicyImportPath, guardedNames); err != nil {
				return err
			}
		}
	}

	for _, path := range []string{embeddedDeclarationPath, importDeclarationPath, localResolverPath} {
		if seenAllowedFiles[path] != 1 {
			return &l8D4GuestAuthorityGuardError{"host-evidence frozen production file is missing or duplicated"}
		}
	}
	if err := validateL8D4HostEvidenceBuildContexts(issuerConstraints, embeddedDeclarationPath, generatedDeclarationPath, evidenceBuildTag); err != nil {
		return err
	}
	return nil
}

func validateL8D4HostEvidenceBuildConstraint(source, tag string, positive bool) (constraint.Expr, error) {
	var buildLines []string
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build") {
			buildLines = append(buildLines, trimmed)
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			break
		}
	}
	if len(buildLines) != 1 {
		return nil, &l8D4GuestAuthorityGuardError{"host-evidence issuer must have one exact build constraint"}
	}
	expression, err := constraint.Parse(buildLines[0])
	if err != nil {
		return nil, &l8D4GuestAuthorityGuardError{"host-evidence issuer has a malformed build constraint"}
	}
	if positive {
		tagExpression, ok := expression.(*constraint.TagExpr)
		if !ok || tagExpression.Tag != tag {
			return nil, &l8D4GuestAuthorityGuardError{"generated host-evidence issuer must use the exact positive build constraint"}
		}
		return expression, nil
	}
	negation, ok := expression.(*constraint.NotExpr)
	if !ok {
		return nil, &l8D4GuestAuthorityGuardError{"default host-evidence issuer must use the exact negative build constraint"}
	}
	tagExpression, ok := negation.X.(*constraint.TagExpr)
	if !ok || tagExpression.Tag != tag {
		return nil, &l8D4GuestAuthorityGuardError{"default host-evidence issuer must use the exact negative build constraint"}
	}
	return expression, nil
}

func validateL8D4HostEvidenceBuildContexts(constraints map[string]constraint.Expr, defaultPath, generatedPath, tag string) error {
	if constraints[defaultPath] == nil {
		return &l8D4GuestAuthorityGuardError{"default host-evidence issuer build context is missing"}
	}
	contexts := []bool{false}
	if constraints[generatedPath] != nil {
		contexts = append(contexts, true)
	}
	for _, enabled := range contexts {
		active := 0
		for _, path := range []string{defaultPath, generatedPath} {
			expression := constraints[path]
			if expression != nil && expression.Eval(func(candidate string) bool {
				return candidate == tag && enabled
			}) {
				active++
			}
		}
		if active != 1 {
			return &l8D4GuestAuthorityGuardError{"host-evidence build context must select exactly one issuer declaration"}
		}
	}
	return nil
}

func validateL8D4HostEvidenceDeclaration(file *ast.File, name string, parameterTypes, resultTypes []string) error {
	if file.Name.Name != "syscallpolicy" {
		return &l8D4GuestAuthorityGuardError{"host-evidence declaration left the syscallpolicy package"}
	}
	var matched []*ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name {
			matched = append(matched, function)
		}
	}
	if len(matched) != 1 {
		return &l8D4GuestAuthorityGuardError{"host-evidence frozen leaf must contain one exact declaration"}
	}
	function := matched[0]
	if function.Recv != nil || function.Body == nil || function.Name.Obj == nil || function.Name.Obj.Kind != ast.Fun || function.Name.Obj.Decl != function {
		return &l8D4GuestAuthorityGuardError{"host-evidence declaration is not the bound concrete function"}
	}
	if !l8D4SameTypeSpellings(l8D4FieldTypeSpellings(function.Type.Params), parameterTypes) ||
		!l8D4SameTypeSpellings(l8D4FieldTypeSpellings(function.Type.Results), resultTypes) {
		return &l8D4GuestAuthorityGuardError{"host-evidence declaration signature changed"}
	}
	return nil
}

func validateL8D4HostEvidenceConsumer(file *ast.File, importPath string, guardedNames []string) error {
	if file.Name.Name != "localresolver" {
		return &l8D4GuestAuthorityGuardError{"host-evidence consumer left the localresolver package"}
	}
	alias := ""
	importCount := 0
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return &l8D4GuestAuthorityGuardError{"localresolver has a malformed syscallpolicy import"}
		}
		if path != importPath {
			continue
		}
		importCount++
		alias = "syscallpolicy"
		if imported.Name != nil {
			alias = imported.Name.Name
		}
		if alias == "." || alias == "_" {
			return &l8D4GuestAuthorityGuardError{"localresolver syscallpolicy import must be named"}
		}
	}
	if importCount != 1 {
		return &l8D4GuestAuthorityGuardError{"localresolver must import syscallpolicy exactly once"}
	}
	var consumers []*ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "VerifyL8DistributionBundle" {
			consumers = append(consumers, function)
		}
	}
	if len(consumers) != 1 || consumers[0].Recv != nil || consumers[0].Body == nil ||
		consumers[0].Name.Obj == nil || consumers[0].Name.Obj.Kind != ast.Fun || consumers[0].Name.Obj.Decl != consumers[0] {
		return &l8D4GuestAuthorityGuardError{"localresolver must have one concrete VerifyL8DistributionBundle consumer"}
	}
	callCounts := make(map[string]int)
	ast.Inspect(consumers[0].Body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != alias || (receiver.Obj != nil && receiver.Obj.Kind != ast.Pkg) {
			return true
		}
		for _, name := range guardedNames {
			if selector.Sel.Name == name {
				callCounts[name]++
			}
		}
		return true
	})
	for _, name := range guardedNames {
		if callCounts[name] != 1 {
			return &l8D4GuestAuthorityGuardError{"localresolver must make one exact direct host-evidence call"}
		}
	}
	return nil
}

func l8D4FieldTypeSpellings(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var spellings []string
	for _, field := range fields.List {
		spelling := l8D4TypeSpelling(field.Type)
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for index := 0; index < count; index++ {
			spellings = append(spellings, spelling)
		}
	}
	return spellings
}

func l8D4TypeSpelling(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.ArrayType:
		if typed.Len == nil {
			return "[]" + l8D4TypeSpelling(typed.Elt)
		}
	}
	return ""
}

func l8D4SameTypeSpellings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
		"repository root",
		"every non-test Go file",
		"every other production file to have zero guarded spellings",
		"pinned_evidence_default.go",
		"pinned_callsite_evidence_expected_d7_gen.go",
		"!l8_verified_pinned_callsite_evidence",
		"constraints select exactly one issuer declaration in each build context",
		"go:linkname",
		"strconv.Unquote",
		"stable sanitized dependency failure",
		"l8_d4_full_syscall_adapter",
		"private one-method `syscallExecutor`",
		"linux && amd64 && l8_d4_full_syscall_adapter",
		"positive lifecycle harness is test-only",
		"NewSyscallPolicyCoreKernel` remains",
		"unstarted -> claimed -> executed -> finalized",
		"No D7 rule",
	} {
		if !strings.Contains(normalizedDocument, marker) {
			t.Errorf("D4 foundation verification omits %q", marker)
		}
	}
}

func TestL8D4SyscallAdapterFoundationFocusedSelectorListsHostEvidenceGuard(t *testing.T) {
	const selector = `^TestL8D4(SyscallAdapterFoundation.*|HostEvidenceHasOneRepositoryWideProductionConsumer)$`
	document := readL8D4SyscallAdapterFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d4-syscall-adapter-foundation-verification.md"))
	if !strings.Contains(document, "go test -count=1 ./cmd -run '"+selector+"'") {
		t.Fatalf("D4 foundation verification omits exact focused selector %q", selector)
	}
	command := exec.Command("go", "test", "-list", selector, "./cmd")
	command.Dir = ".."
	listed, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list documented D4 foundation selector: %v: %s", err, listed)
	}
	for _, testName := range []string{
		"TestL8D4HostEvidenceHasOneRepositoryWideProductionConsumer",
		"TestL8D4SyscallAdapterFoundationIsTruthfullyDocumented",
		"TestL8D4SyscallAdapterFoundationConstructorIsFailClosed",
		"TestL8D4SyscallAdapterFoundationGuestAuthorityGuardRejectsMutations",
	} {
		if !strings.Contains(string(listed), testName+"\n") {
			t.Fatalf("documented D4 foundation selector omitted %s: %s", testName, listed)
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
	for _, forbidden := range []string{"return options.Kernel", "syscall.Syscall", "unix.Syscall", "unsafe.Pointer", "os/exec", "EmbeddedExpectedPinnedCallsiteEvidence", "ImportPinnedCallsiteEvidence", "ExpectedPinnedCallsiteEvidence", "newSyscallPolicyWrapper"} {
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
