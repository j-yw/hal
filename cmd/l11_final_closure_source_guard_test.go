package cmd

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var l11SelectedPreparedTests = map[string]bool{
	"TestL10PreparedLinuxStrictCompositionE2E": true,
	l11FinalClosureSelectedTest:                true,
}

type l11SelectedFunction struct {
	declaration *ast.FuncDecl
	literal     *ast.FuncLit
	file        *l11SelectedFile
	pkg         *l11SelectedPackage
}

type l11SelectedFile struct {
	path        string
	parsed      *ast.File
	importPaths map[string]string
}

type l11SelectedPackage struct {
	dir       string
	name      string
	files     []*l11SelectedFile
	functions map[string][]*l11SelectedFunction
	methods   map[string]map[string][]*l11SelectedFunction
}

type l11SelectedCallable struct {
	function *l11SelectedFunction
	proof    bool
	skip     bool
	cloud    bool
}

func TestL11FinalClosureContractOnlyAddsNoProductionWiring(t *testing.T) {
	for _, root := range []string{".", filepath.Join("..", "internal")} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, forbidden := range []string{
				l11FinalClosureIntegrationTag,
				l11FinalClosureSelectedTest,
				"internal/l11closure",
				"SandboxL11Closure",
			} {
				if strings.Contains(string(payload), forbidden) {
					t.Errorf("production file %s contains contract-only L11 marker %q", filepath.ToSlash(path), forbidden)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan L11 production boundary %s: %v", root, err)
		}
	}
}

func TestL11FinalClosureSelectedPreparedTestsUseNoSyntheticAuthorityOrSkip(t *testing.T) {
	packages, err := l11LoadSelectedTestPackages([]string{".", filepath.Join("..", "internal")})
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range l11SelectedPreparedTestIssues(packages) {
		t.Error(issue)
	}
}

func TestL11FinalClosureTaggedSelectedSourceCannotHideSkip(t *testing.T) {
	root := t.TempDir()
	source := `//go:build l11_final_closure_integration

package fixture

import "testing"

func TestL11PreparedLinuxFinalClosure(t *testing.T) { t.Skip("missing") }
`
	if err := os.WriteFile(filepath.Join(root, "l11_tagged_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	packages, err := l11LoadSelectedTestPackages([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	issues := l11SelectedPreparedTestIssues(packages)
	if len(issues) != 1 || !strings.Contains(issues[0], "skip call") {
		t.Fatalf("issues = %v, want one tagged selected-test skip issue", issues)
	}
}

func TestL11FinalClosureSelectedPreparedSourceGuardRejectsMutations(t *testing.T) {
	clean := `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { useAcceptedAuthorities(t) }
func useAcceptedAuthorities(*testing.T) {}
`
	tests := []struct {
		name       string
		source     string
		sources    map[string]string
		wantIssue  string
		wantIssues int
	}{
		{name: "clean accepted authority seam", source: clean},
		{
			name: "direct active proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "reachable cleanup proof helper",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL10PreparedLinuxStrictCompositionE2E(*testing.T) { mintCleanup() }
func mintCleanup() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "dot imported active proof constructor",
			source: `package fixture
import (. "example.invalid/sandboxruntime"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) { _, _ = NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "called local function alias",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint := mintActive; mint() }
func mintActive() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "called package function alias",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
var mint = mintActive
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint() }
func mintActive() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "imported helper chain",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import ("testing"; "example.invalid/helper")
func TestL11PreparedLinuxFinalClosure(*testing.T) { helper.MintCleanup() }
`,
				"helper/helper.go": `package helper
import "example.invalid/sandboxruntime"
func MintCleanup() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
			},
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "reachable skip helper",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skipMissing(t) }
func skipMissing(t *testing.T) { t.Skip("missing") }
`,
			wantIssue: "skip call", wantIssues: 1,
		},
		{
			name: "testing TB skip helper",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skipMissing(t) }
func skipMissing(t testing.TB) { t.Skip("missing") }
`,
			wantIssue: "skip call", wantIssues: 1,
		},
		{
			name: "callback carried proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) { invoke(mint) }
func invoke(callback func()) { callback() }
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "method expression proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type helper struct{}
func (helper) mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint := helper.mint; mint(helper{}) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "dot imported helper chain",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import (. "example.invalid/helper"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) { MintCleanup() }
`,
				"helper/helper.go": `package helper
import "example.invalid/sandboxruntime"
func MintCleanup() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
			},
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "returned closure proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) { returnedMint()() }
func returnedMint() func() { return func() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) } }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "billed cloud marker",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = "HCLOUD_TOKEN" }
`,
			wantIssue: "cloud/provider marker", wantIssues: 1,
		},
		{
			name: "blank cloud provider import",
			source: `package fixture
import (_ "example.invalid/hetzner"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
			wantIssue: "cloud/provider marker", wantIssues: 1,
		},
		{
			name: "imported package init cloud access",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import (_ "example.invalid/helper"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
				"helper/helper.go": `package helper
func init() { _ = "HCLOUD_TOKEN" }
`,
			},
			wantIssue: "cloud/provider marker", wantIssues: 1,
		},
		{
			name: "split cloud provider literal",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { provider := "het" + "zner"; _ = provider }
`,
			wantIssue: "cloud/provider marker", wantIssues: 1,
		},
		{
			name: "negative cloud text is not provider selection",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = "Hetzner remains disabled" }
`,
		},
		{
			name: "generic Hetzner provider selection",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { provider := "hetzner"; _ = provider }
`,
			wantIssue: "cloud/provider marker", wantIssues: 1,
		},
		{
			name: "uninvoked closure is unreachable",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	unused := func() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
	_ = unused
}
var input any
`,
		},
		{
			name: "unrelated method named Skip",
			source: `package fixture
import "testing"
type helper struct{}
func (helper) Skip() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { helper{}.Skip() }
`,
		},
		{
			name: "shadowed import alias is local",
			source: `package fixture
import ("testing"; sandboxruntime "example.invalid/sandboxruntime")
type helper struct{}
func (helper) NewJobCredentialActiveProof(any) (any, error) { return nil, nil }
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	sandboxruntime := helper{}
	_, _ = sandboxruntime.NewJobCredentialActiveProof(nil)
}
`,
		},
		{
			name: "unreachable fake helper is outside selected authority",
			source: clean + `
func unitFixtureOnly() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sources := test.sources
			if sources == nil {
				sources = map[string]string{"fixture_test.go": test.source}
			}
			packages, err := l11ParseSelectedTestSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			issues := l11SelectedPreparedTestIssues(packages)
			if len(issues) != test.wantIssues {
				t.Fatalf("issues = %v, want count %d", issues, test.wantIssues)
			}
			if test.wantIssue != "" && !strings.Contains(issues[0], test.wantIssue) {
				t.Fatalf("issue = %q, want fragment %q", issues[0], test.wantIssue)
			}
		})
	}
}

func TestL11FinalClosureCallableAliasReassignmentConvergesAndFailsClosed(t *testing.T) {
	source := `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	run := safe
	run = unsafe
	run()
}
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`
	packages, err := l11ParseSelectedTestSources(map[string]string{"fixture_test.go": source})
	if err != nil {
		t.Fatal(err)
	}
	issues := l11SelectedPreparedTestIssues(packages)
	if len(issues) != 1 || !strings.Contains(issues[0], "synthetic credential proof constructor") {
		t.Fatalf("issues = %v, want one reassigned-alias proof issue", issues)
	}
}

func l11LoadSelectedTestPackages(roots []string) (map[string]*l11SelectedPackage, error) {
	sources := make(map[string]string)
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			matches, err := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
			if err != nil {
				return err
			}
			if !matches {
				return nil
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sources[path] = string(payload)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan selected prepared tests below %s: %w", root, err)
		}
	}
	return l11ParseSelectedTestSources(sources)
}

func l11ParseSelectedTestSources(sources map[string]string) (map[string]*l11SelectedPackage, error) {
	packages := make(map[string]*l11SelectedPackage)
	for path, source := range sources {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", filepath.ToSlash(path), err)
		}
		dir := filepath.Clean(filepath.Dir(path))
		key := dir + "\x00" + parsed.Name.Name
		pkg := packages[key]
		if pkg == nil {
			pkg = &l11SelectedPackage{
				dir:       dir,
				name:      parsed.Name.Name,
				functions: make(map[string][]*l11SelectedFunction),
				methods:   make(map[string]map[string][]*l11SelectedFunction),
			}
			packages[key] = pkg
		}
		file := &l11SelectedFile{path: path, parsed: parsed, importPaths: l11SelectedFileImportPaths(parsed)}
		pkg.files = append(pkg.files, file)
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			selected := &l11SelectedFunction{
				declaration: function,
				file:        file,
				pkg:         pkg,
			}
			if receiver := l11SelectedReceiverType(function); receiver != "" {
				if pkg.methods[receiver] == nil {
					pkg.methods[receiver] = make(map[string][]*l11SelectedFunction)
				}
				pkg.methods[receiver][function.Name.Name] = append(pkg.methods[receiver][function.Name.Name], selected)
				continue
			}
			pkg.functions[function.Name.Name] = append(pkg.functions[function.Name.Name], selected)
		}
	}
	return packages, nil
}

func l11SelectedFileImportPaths(file *ast.File) map[string]string {
	imports := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := pathpkg.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = importPath
	}
	return imports
}

func l11SelectedPreparedTestIssues(packages map[string]*l11SelectedPackage) []string {
	var issues []string
	for _, pkg := range packages {
		for selected := range l11SelectedPreparedTests {
			for _, root := range pkg.functions[selected] {
				issues = append(issues, l11SelectedFunctionIssues(packages, root)...)
			}
		}
	}
	sort.Strings(issues)
	return issues
}

func l11SelectedFunctionIssues(packages map[string]*l11SelectedPackage, root *l11SelectedFunction) []string {
	queue := []*l11SelectedFunction{root}
	reachable := make(map[ast.Node]bool)
	literals := make(map[*ast.FuncLit]*l11SelectedFunction)
	var issues []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		node := current.node()
		if reachable[node] {
			continue
		}
		reachable[node] = true
		aliases := l11SelectedCallableAliases(packages, current, literals)
		ast.Inspect(current.body(), func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncLit:
				return false
			case *ast.SelectorExpr:
				if l11SelectedProofSelector(current.file, value) {
					issues = append(issues, fmt.Sprintf("%s reaches synthetic credential proof constructor", root.declaration.Name.Name))
				}
				if l11SelectedCloudSelector(current.file, value) {
					issues = append(issues, fmt.Sprintf("%s reaches a cloud/provider marker", root.declaration.Name.Name))
				}
			case *ast.Ident:
				if l11SelectedDotImportedProof(current.file, value) {
					issues = append(issues, fmt.Sprintf("%s reaches synthetic credential proof constructor", root.declaration.Name.Name))
				}
				if value.Obj == nil && l11ForbiddenCloudLiteral(value.Name) {
					issues = append(issues, fmt.Sprintf("%s reaches a cloud/provider marker", root.declaration.Name.Name))
				}
			case *ast.BasicLit:
				if value.Kind == token.STRING {
					literal, err := strconv.Unquote(value.Value)
					if err == nil && l11ForbiddenCloudLiteral(literal) {
						issues = append(issues, fmt.Sprintf("%s reaches a cloud/provider marker", root.declaration.Name.Name))
					}
				}
			case *ast.CallExpr:
				for _, callable := range l11ResolveSelectedCallables(packages, current, value.Fun, aliases, literals) {
					switch {
					case callable.proof:
						issues = append(issues, fmt.Sprintf("%s reaches synthetic credential proof constructor", root.declaration.Name.Name))
					case callable.skip:
						issues = append(issues, fmt.Sprintf("%s reaches a skip call", root.declaration.Name.Name))
					case callable.cloud:
						issues = append(issues, fmt.Sprintf("%s reaches a cloud/provider marker", root.declaration.Name.Name))
					case callable.function != nil && !reachable[callable.function.node()]:
						queue = append(queue, callable.function)
					}
				}
			}
			return true
		})
	}
	return l11UniqueStrings(issues)
}

func (function *l11SelectedFunction) node() ast.Node {
	if function.declaration != nil {
		return function.declaration
	}
	return function.literal
}

func (function *l11SelectedFunction) body() *ast.BlockStmt {
	if function.declaration != nil {
		return function.declaration.Body
	}
	return function.literal.Body
}

func l11SelectedCallableAliases(packages map[string]*l11SelectedPackage, function *l11SelectedFunction, literals map[*ast.FuncLit]*l11SelectedFunction) map[*ast.Object][]l11SelectedCallable {
	aliases := make(map[*ast.Object][]l11SelectedCallable)
	for changed := true; changed; {
		changed = false
		ast.Inspect(function.body(), func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			var names []*ast.Ident
			var values []ast.Expr
			switch declaration := node.(type) {
			case *ast.AssignStmt:
				if len(declaration.Lhs) != len(declaration.Rhs) {
					return true
				}
				for _, expression := range declaration.Lhs {
					identifier, ok := expression.(*ast.Ident)
					if !ok {
						return true
					}
					names = append(names, identifier)
				}
				values = declaration.Rhs
			case *ast.ValueSpec:
				if len(declaration.Names) != len(declaration.Values) {
					return true
				}
				names, values = declaration.Names, declaration.Values
			default:
				return true
			}
			for index, name := range names {
				if name.Obj == nil {
					continue
				}
				resolved := l11ResolveSelectedCallables(packages, function, values[index], aliases, literals)
				if len(resolved) > 0 && !l11SelectedCallableSetsEqual(aliases[name.Obj], resolved) {
					aliases[name.Obj] = resolved
					changed = true
				}
			}
			return true
		})
	}
	return aliases
}

func l11ResolveSelectedCallables(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction) []l11SelectedCallable {
	return l11ResolveSelectedCallablesWithStack(packages, current, expression, aliases, literals, make(map[*ast.Object]bool))
}

func l11ResolveSelectedCallablesWithStack(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction, resolving map[*ast.Object]bool) []l11SelectedCallable {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return l11ResolveSelectedCallablesWithStack(packages, current, value.X, aliases, literals, resolving)
	case *ast.FuncLit:
		function := literals[value]
		if function == nil {
			function = &l11SelectedFunction{literal: value, file: current.file, pkg: current.pkg}
			literals[value] = function
		}
		return []l11SelectedCallable{{function: function}}
	case *ast.Ident:
		if value.Obj != nil {
			if resolved := aliases[value.Obj]; len(resolved) > 0 {
				return resolved
			}
			if declaration, ok := value.Obj.Decl.(*ast.FuncDecl); ok {
				return l11SelectedDeclaredFunction(current.pkg, declaration)
			}
			if declaration, ok := value.Obj.Decl.(*ast.ValueSpec); ok && !resolving[value.Obj] {
				if initializer := l11SelectedValueInitializer(value.Obj, declaration); initializer != nil {
					resolving[value.Obj] = true
					resolved := l11ResolveSelectedCallablesWithStack(packages, current, initializer, aliases, literals, resolving)
					delete(resolving, value.Obj)
					return resolved
				}
			}
			return nil
		}
		if l11SelectedDotImportedProof(current.file, value) {
			return []l11SelectedCallable{{proof: true}}
		}
		return l11SelectedFunctions(current.pkg.functions[value.Name])
	case *ast.SelectorExpr:
		if identifier, ok := value.X.(*ast.Ident); ok {
			if importPath, imported := current.file.importPaths[identifier.Name]; imported && identifier.Obj == nil {
				switch {
				case l11SelectedProofConstructor(value.Sel.Name) && pathpkg.Base(importPath) == "sandboxruntime":
					return []l11SelectedCallable{{proof: true}}
				case l11ForbiddenCloudImport(importPath):
					return []l11SelectedCallable{{cloud: true}}
				}
				if importedPackage := l11SelectedImportedPackage(packages, importPath); importedPackage != nil {
					return l11SelectedFunctions(importedPackage.functions[value.Sel.Name])
				}
				return nil
			}
		}
		if l11SelectedTestingSkip(current.file, value) {
			return []l11SelectedCallable{{skip: true}}
		}
		if receiver := l11SelectedExpressionType(current.file, value.X); receiver != "" {
			return l11SelectedFunctions(current.pkg.methods[receiver][value.Sel.Name])
		}
	}
	return nil
}

func l11SelectedValueInitializer(object *ast.Object, declaration *ast.ValueSpec) ast.Expr {
	for index, name := range declaration.Names {
		if name.Obj == object && index < len(declaration.Values) {
			return declaration.Values[index]
		}
	}
	return nil
}

func l11SelectedFunctions(functions []*l11SelectedFunction) []l11SelectedCallable {
	result := make([]l11SelectedCallable, 0, len(functions))
	for _, function := range functions {
		result = append(result, l11SelectedCallable{function: function})
	}
	return result
}

func l11SelectedDeclaredFunction(pkg *l11SelectedPackage, declaration *ast.FuncDecl) []l11SelectedCallable {
	for _, functions := range pkg.functions {
		for _, function := range functions {
			if function.declaration == declaration {
				return []l11SelectedCallable{{function: function}}
			}
		}
	}
	return nil
}

func l11SelectedImportedPackage(packages map[string]*l11SelectedPackage, importPath string) *l11SelectedPackage {
	const modulePath = "github.com/jywlabs/hal/"
	importSuffix := strings.TrimPrefix(importPath, modulePath)
	for _, pkg := range packages {
		if pkg.name != pathpkg.Base(importPath) {
			continue
		}
		dir := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(pkg.dir)), "../")
		if dir == "." {
			dir = pkg.name
		}
		if importSuffix == dir || strings.HasSuffix(importPath, "/"+dir) {
			return pkg
		}
	}
	base := pathpkg.Base(importPath)
	var match *l11SelectedPackage
	for _, pkg := range packages {
		if pkg.name != base && filepath.Base(pkg.dir) != base {
			continue
		}
		if match != nil && match != pkg {
			return nil
		}
		match = pkg
	}
	return match
}

func l11SelectedCallableSetsEqual(left, right []l11SelectedCallable) bool {
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

func l11SelectedReceiverType(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	return l11SelectedTypeName(nil, function.Recv.List[0].Type)
}

func l11SelectedExpressionType(file *l11SelectedFile, expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.CompositeLit:
		return l11SelectedTypeName(file, value.Type)
	case *ast.ParenExpr:
		return l11SelectedExpressionType(file, value.X)
	case *ast.UnaryExpr:
		return l11SelectedExpressionType(file, value.X)
	case *ast.Ident:
		if value.Obj == nil {
			return value.Name
		}
		switch declaration := value.Obj.Decl.(type) {
		case *ast.Field:
			return l11SelectedTypeName(file, declaration.Type)
		case *ast.ValueSpec:
			if declaration.Type != nil {
				return l11SelectedTypeName(file, declaration.Type)
			}
			for index, name := range declaration.Names {
				if name.Obj == value.Obj && index < len(declaration.Values) {
					return l11SelectedExpressionType(file, declaration.Values[index])
				}
			}
		case *ast.AssignStmt:
			for index, name := range declaration.Lhs {
				identifier, ok := name.(*ast.Ident)
				if ok && identifier.Obj == value.Obj && index < len(declaration.Rhs) {
					return l11SelectedExpressionType(file, declaration.Rhs[index])
				}
			}
		}
	}
	return ""
}

func l11SelectedTypeName(file *l11SelectedFile, expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.StarExpr:
		return l11SelectedTypeName(file, value.X)
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		if identifier, ok := value.X.(*ast.Ident); ok {
			if file != nil {
				if importPath := file.importPaths[identifier.Name]; importPath != "" {
					return pathpkg.Base(importPath) + "." + value.Sel.Name
				}
			}
			return identifier.Name + "." + value.Sel.Name
		}
	}
	return ""
}

func l11SelectedTestingSkip(file *l11SelectedFile, selector *ast.SelectorExpr) bool {
	switch selector.Sel.Name {
	case "Skip", "Skipf", "SkipNow":
		return l11SelectedExpressionType(file, selector.X) == "testing.T"
	default:
		return false
	}
}

func l11SelectedProofSelector(file *l11SelectedFile, selector *ast.SelectorExpr) bool {
	identifier, ok := selector.X.(*ast.Ident)
	if !ok || identifier.Obj != nil || !l11SelectedProofConstructor(selector.Sel.Name) {
		return false
	}
	return pathpkg.Base(file.importPaths[identifier.Name]) == "sandboxruntime"
}

func l11SelectedCloudSelector(file *l11SelectedFile, selector *ast.SelectorExpr) bool {
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Obj == nil && l11ForbiddenCloudImport(file.importPaths[identifier.Name])
}

func l11SelectedDotImportedProof(file *l11SelectedFile, identifier *ast.Ident) bool {
	return identifier.Obj == nil && pathpkg.Base(file.importPaths["."]) == "sandboxruntime" && l11SelectedProofConstructor(identifier.Name)
}

func l11SelectedProofConstructor(name string) bool {
	return name == "NewJobCredentialActiveProof" || name == "NewJobCredentialCleanupProof"
}

func l11ForbiddenCloudImport(importPath string) bool {
	lower := strings.ToLower(importPath)
	for _, marker := range []string{"hetzner", "lightsail", "aws-sdk", "digitalocean", "cloud.google.com"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func l11ForbiddenCloudLiteral(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"hcloud_token",
		"aws_access_key_id",
		"aws_secret_access_key",
		"digitalocean_access_token",
		"google_application_credentials",
		"hetzner",
		"lightsail",
		"digitalocean",
		"google_cloud",
		"google-cloud",
		"amazon_web_services",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func l11UniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
