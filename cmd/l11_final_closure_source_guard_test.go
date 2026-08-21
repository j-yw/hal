package cmd

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var l11SelectedPreparedTests = map[string]bool{
	"TestL10PreparedLinuxStrictCompositionE2E": true,
	l11FinalClosureSelectedTest:                true,
}

type l11SelectedFunction struct {
	declaration        *ast.FuncDecl
	literal            *ast.FuncLit
	file               *l11SelectedFile
	pkg                *l11SelectedPackage
	packageInitializer bool
}

type l11SelectedFile struct {
	path        string
	parsed      *ast.File
	importPaths map[string]string
	imports     []l11SelectedImport
}

type l11SelectedImport struct {
	name string
	path string
}

type l11SelectedPackage struct {
	dir       string
	name      string
	files     []*l11SelectedFile
	functions map[string][]*l11SelectedFunction
	methods   map[string]map[string][]*l11SelectedFunction
	values    []*l11SelectedPackageValue
	callables map[string][]l11SelectedCallable
	constants map[string]string
}

type l11SelectedPackageValue struct {
	file   *l11SelectedFile
	token  token.Token
	names  []*ast.Ident
	values []ast.Expr
}

type l11SelectedCallable struct {
	function *l11SelectedFunction
	proof    bool
	skip     bool
	cloud    bool
}

type l11SelectedResolutionState struct {
	objects  map[*ast.Object]bool
	returns  map[ast.Node]bool
	aliasing map[ast.Node]bool
}

func l11NewSelectedResolutionState() *l11SelectedResolutionState {
	return &l11SelectedResolutionState{
		objects:  make(map[*ast.Object]bool),
		returns:  make(map[ast.Node]bool),
		aliasing: make(map[ast.Node]bool),
	}
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
			name: "multiple dot imports cannot mask proof constructor",
			source: `package fixture
import (. "example.invalid/sandboxruntime"; . "example.invalid/helper"; "testing")
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
			name: "dot imported testing T skip",
			source: `package fixture
import . "testing"
func TestL11PreparedLinuxFinalClosure(t *T) { t.Skip("missing") }
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
			name: "forwarded callback proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) { forward(mint) }
func forward(callback func()) { invoke(callback) }
func invoke(callback func()) { callback() }
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "ignored callback remains unreachable",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) { ignore(mint) }
func ignore(func()) {}
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
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
			name: "imported method expression proof constructor",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import ("testing"; "example.invalid/helper")
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint := helper.Minter.Mint; mint(helper.Minter{}) }
`,
				"helper/helper.go": `package helper
import "example.invalid/sandboxruntime"
type Minter struct{}
func (Minter) Mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			},
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "pointer method expression proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type helper struct{}
func (*helper) mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint := (*helper).mint; mint(&helper{}) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "generic helper call proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func mint[T any]() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint[any]() }
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
			name: "multi return callable proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func choices() (func(), func()) { return safe, unsafe }
func TestL11PreparedLinuxFinalClosure(*testing.T) { _, run := choices(); run() }
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "discarded multi return proof callable remains unreachable",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func choices() (func(), func()) { return unsafe, safe }
func TestL11PreparedLinuxFinalClosure(*testing.T) { _, run := choices(); run() }
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
		},
		{
			name: "init reassigned global callable proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
var run = safe
func init() { run = unsafe }
func TestL11PreparedLinuxFinalClosure(*testing.T) { run() }
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "package scope proof initializer",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
var initialized, _ = sandboxruntime.NewJobCredentialActiveProof(input)
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = initialized }
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
			name: "sibling file blank cloud provider import",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
				"root/provider_test.go": `package fixture
import _ "example.invalid/hetzner"
`,
			},
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
			name: "selected package init cloud access",
			source: `package fixture
import "testing"
func init() { _ = "HCLOUD_TOKEN" }
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
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
			name: "package constant cloud provider composition",
			source: `package fixture
import "testing"
const providerPrefix = "het"
const providerName = providerPrefix + "zner"
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = providerName }
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
			name: "unsafe provider selection cannot hide behind negative substring",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = "Hetzner remains disabled; provider=hetzner" }
`,
			wantIssue: "cloud/provider marker", wantIssues: 1,
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
	result := make(chan []string, 1)
	go func() {
		result <- l11SelectedPreparedTestIssues(packages)
	}()
	select {
	case issues := <-result:
		if len(issues) != 1 || !strings.Contains(issues[0], "synthetic credential proof constructor") {
			t.Fatalf("issues = %v, want one reassigned-alias proof issue", issues)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reassigned callable analysis did not converge within two seconds")
	}
}

func TestL11FinalClosureReturnedCallableCycleTerminates(t *testing.T) {
	const helperEnvironment = "HAL_L11_RETURNED_CALLABLE_CYCLE_HELPER"
	if os.Getenv(helperEnvironment) == "1" {
		source := `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { first()() }
func first() func() { returned := second(); return returned }
func second() func() { returned := first(); return returned }
`
		packages, err := l11ParseSelectedTestSources(map[string]string{"fixture_test.go": source})
		if err != nil {
			t.Fatal(err)
		}
		if issues := l11SelectedPreparedTestIssues(packages); len(issues) != 0 {
			t.Fatalf("issues = %v, want a clean cyclic callable graph", issues)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestL11FinalClosureReturnedCallableCycleTerminates$")
	command.Env = append(os.Environ(), helperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("cyclic callable analysis did not terminate within two seconds: %s", output)
	}
	if err != nil {
		t.Fatalf("cyclic callable analysis failed: %v: %s", err, output)
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
				callables: make(map[string][]l11SelectedCallable),
				constants: make(map[string]string),
			}
			packages[key] = pkg
		}
		file := &l11SelectedFile{
			path:        path,
			parsed:      parsed,
			importPaths: l11SelectedFileImportPaths(parsed),
			imports:     l11SelectedFileImports(parsed),
		}
		pkg.files = append(pkg.files, file)
		for _, declaration := range parsed.Decls {
			if generated, ok := declaration.(*ast.GenDecl); ok && (generated.Tok == token.CONST || generated.Tok == token.VAR) {
				for _, spec := range generated.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if ok {
						pkg.values = append(pkg.values, &l11SelectedPackageValue{file: file, token: generated.Tok, names: value.Names, values: value.Values})
					}
				}
				continue
			}
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

func l11SelectedFileImports(file *ast.File) []l11SelectedImport {
	imports := make([]l11SelectedImport, 0, len(file.Imports))
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := pathpkg.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports = append(imports, l11SelectedImport{name: name, path: importPath})
	}
	return imports
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

func l11PrepareSelectedPackageFacts(packages map[string]*l11SelectedPackage, literals map[*ast.FuncLit]*l11SelectedFunction) {
	for _, pkg := range packages {
		pkg.callables = make(map[string][]l11SelectedCallable)
		pkg.constants = make(map[string]string)
	}
	for changed := true; changed; {
		changed = false
		for _, pkg := range packages {
			for _, declaration := range pkg.values {
				if declaration.token != token.CONST || len(declaration.names) != len(declaration.values) {
					continue
				}
				for index, name := range declaration.names {
					literal, ok := l11SelectedStringConstant(pkg, declaration.values[index])
					if ok && pkg.constants[name.Name] != literal {
						pkg.constants[name.Name] = literal
						changed = true
					}
				}
			}
		}
	}

	for changed := true; changed; {
		changed = false
		for _, pkg := range packages {
			for _, declaration := range pkg.values {
				if declaration.token != token.VAR {
					continue
				}
				context := l11SelectedPackageExpressionContext(pkg, declaration.file)
				if l11MergeSelectedPackageValueCallables(packages, pkg, context, declaration.names, declaration.values, nil, literals) {
					changed = true
				}
			}
			for _, initializer := range pkg.functions["init"] {
				aliases := l11SelectedCallableAliases(packages, initializer, literals)
				ast.Inspect(initializer.body(), func(node ast.Node) bool {
					if _, nested := node.(*ast.FuncLit); nested {
						return false
					}
					assignment, ok := node.(*ast.AssignStmt)
					if !ok {
						return true
					}
					var names []*ast.Ident
					for _, expression := range assignment.Lhs {
						name, ok := expression.(*ast.Ident)
						if !ok || (name.Name != "_" && !l11SelectedPackageAssignmentTarget(pkg, name, assignment.Tok)) {
							return true
						}
						names = append(names, name)
					}
					if l11MergeSelectedPackageValueCallables(packages, pkg, initializer, names, assignment.Rhs, aliases, literals) {
						changed = true
					}
					return true
				})
			}
		}
	}
}

func l11SelectedPackageExpressionContext(pkg *l11SelectedPackage, file *l11SelectedFile) *l11SelectedFunction {
	return &l11SelectedFunction{
		literal: &ast.FuncLit{Body: &ast.BlockStmt{}},
		file:    file,
		pkg:     pkg,
	}
}

func l11MergeSelectedPackageValueCallables(packages map[string]*l11SelectedPackage, pkg *l11SelectedPackage, current *l11SelectedFunction, names []*ast.Ident, values []ast.Expr, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction) bool {
	changed := false
	state := l11NewSelectedResolutionState()
	for index, name := range names {
		if name.Name == "_" {
			continue
		}
		var resolved []l11SelectedCallable
		if len(values) == 1 && len(names) > 1 {
			if call, ok := values[0].(*ast.CallExpr); ok {
				results := l11ResolveSelectedCallableResultsWithState(packages, current, call, aliases, literals, state)
				if index < len(results) {
					resolved = results[index]
				}
			}
		} else if index < len(values) {
			resolved = l11ResolveSelectedCallablesWithState(packages, current, values[index], aliases, literals, state)
		}
		merged := l11MergeSelectedCallables(pkg.callables[name.Name], resolved)
		if len(merged) != len(pkg.callables[name.Name]) {
			pkg.callables[name.Name] = merged
			changed = true
		}
	}
	return changed
}

func l11SelectedPackageAssignmentTarget(pkg *l11SelectedPackage, name *ast.Ident, assignment token.Token) bool {
	if name.Obj != nil {
		return l11SelectedPackageOwnsObject(pkg, name.Obj)
	}
	if assignment == token.DEFINE {
		return false
	}
	for _, declaration := range pkg.values {
		for _, declared := range declaration.names {
			if declared.Name == name.Name {
				return true
			}
		}
	}
	return false
}

func l11SelectedPackageOwnsObject(pkg *l11SelectedPackage, object *ast.Object) bool {
	for _, declaration := range pkg.values {
		for _, name := range declaration.names {
			if name.Obj == object {
				return true
			}
		}
	}
	return false
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
	literals := l11SelectedFunctionLiterals(packages)
	l11PrepareSelectedPackageFacts(packages, literals)
	packageInitializers := l11SelectedPackageInitializers(packages)
	invokedParameters := l11SelectedInvokedParameters(packages, literals)
	packagesQueued := make(map[*l11SelectedPackage]bool)
	var issues []string
	recordCallable := func(callable l11SelectedCallable) {
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
	var queuePackage func(*l11SelectedPackage)
	queuePackage = func(pkg *l11SelectedPackage) {
		if pkg == nil || packagesQueued[pkg] {
			return
		}
		packagesQueued[pkg] = true
		for _, file := range pkg.files {
			for _, imported := range file.imports {
				if l11ForbiddenCloudImport(imported.path) {
					recordCallable(l11SelectedCallable{cloud: true})
				}
				queuePackage(l11SelectedImportedPackage(packages, imported.path))
			}
		}
		for _, initializer := range pkg.functions["init"] {
			recordCallable(l11SelectedCallable{function: initializer})
		}
		for _, initializer := range packageInitializers[pkg] {
			recordCallable(l11SelectedCallable{function: initializer})
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		node := current.node()
		if reachable[node] {
			continue
		}
		reachable[node] = true
		aliases := l11SelectedCallableAliases(packages, current, literals)
		queuePackage(current.pkg)
		ast.Inspect(current.body(), func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncLit:
				return false
			case *ast.BinaryExpr:
				if !current.packageInitializer {
					literal, ok := l11SelectedStringConstant(current.pkg, value)
					if !ok {
						break
					}
					if l11ForbiddenCloudLiteral(literal) {
						recordCallable(l11SelectedCallable{cloud: true})
					}
					return false
				}
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
				if !current.packageInitializer && value.Obj == nil && l11ForbiddenCloudLiteral(value.Name) {
					issues = append(issues, fmt.Sprintf("%s reaches a cloud/provider marker", root.declaration.Name.Name))
				}
				if !current.packageInitializer {
					literal, ok := l11SelectedStringConstant(current.pkg, value)
					if ok && l11ForbiddenCloudLiteral(literal) {
						recordCallable(l11SelectedCallable{cloud: true})
					}
				}
			case *ast.BasicLit:
				if !current.packageInitializer && value.Kind == token.STRING {
					literal, err := strconv.Unquote(value.Value)
					if err == nil && l11ForbiddenCloudLiteral(literal) {
						issues = append(issues, fmt.Sprintf("%s reaches a cloud/provider marker", root.declaration.Name.Name))
					}
				}
			case *ast.CallExpr:
				callables := l11ResolveSelectedCallables(packages, current, value.Fun, aliases, literals)
				resolvedLocal := false
				for _, callable := range callables {
					recordCallable(callable)
					if callable.function == nil {
						continue
					}
					resolvedLocal = true
					for parameter := range invokedParameters[callable.function.node()] {
						if parameter >= len(value.Args) {
							continue
						}
						for _, argument := range l11ResolveSelectedCallables(packages, current, value.Args[parameter], aliases, literals) {
							recordCallable(argument)
						}
					}
				}
				if !resolvedLocal {
					for _, expression := range value.Args {
						for _, argument := range l11ResolveSelectedCallables(packages, current, expression, aliases, literals) {
							recordCallable(argument)
						}
					}
				}
			}
			return true
		})
	}
	return l11UniqueStrings(issues)
}

func l11SelectedPackageInitializers(packages map[string]*l11SelectedPackage) map[*l11SelectedPackage][]*l11SelectedFunction {
	initializers := make(map[*l11SelectedPackage][]*l11SelectedFunction)
	for _, pkg := range packages {
		for _, declaration := range pkg.values {
			if declaration.token != token.VAR {
				continue
			}
			for _, expression := range declaration.values {
				initializers[pkg] = append(initializers[pkg], &l11SelectedFunction{
					literal:            &ast.FuncLit{Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ExprStmt{X: expression}}}},
					file:               declaration.file,
					pkg:                pkg,
					packageInitializer: true,
				})
			}
		}
	}
	return initializers
}

func l11SelectedFunctionLiterals(packages map[string]*l11SelectedPackage) map[*ast.FuncLit]*l11SelectedFunction {
	literals := make(map[*ast.FuncLit]*l11SelectedFunction)
	for _, pkg := range packages {
		for _, functions := range pkg.functions {
			for _, function := range functions {
				ast.Inspect(function.body(), func(node ast.Node) bool {
					literal, ok := node.(*ast.FuncLit)
					if ok && literals[literal] == nil {
						literals[literal] = &l11SelectedFunction{literal: literal, file: function.file, pkg: pkg}
					}
					return true
				})
			}
		}
	}
	return literals
}

func l11SelectedInvokedParameters(packages map[string]*l11SelectedPackage, literals map[*ast.FuncLit]*l11SelectedFunction) map[ast.Node]map[int]bool {
	functions := make([]*l11SelectedFunction, 0)
	for _, pkg := range packages {
		for _, declarations := range pkg.functions {
			functions = append(functions, declarations...)
		}
	}
	for _, literal := range literals {
		functions = append(functions, literal)
	}

	invoked := make(map[ast.Node]map[int]bool, len(functions))
	for changed := true; changed; {
		changed = false
		for _, function := range functions {
			parameters := l11SelectedParameterObjects(function)
			if len(parameters) == 0 {
				continue
			}
			sources := l11SelectedParameterAliases(function, parameters)
			aliases := l11SelectedCallableAliases(packages, function, literals)
			ast.Inspect(function.body(), func(node ast.Node) bool {
				if _, nested := node.(*ast.FuncLit); nested {
					return false
				}
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				for parameter := range l11SelectedParameterSources(call.Fun, sources) {
					if l11AddSelectedParameter(invoked, function.node(), parameter) {
						changed = true
					}
				}
				for _, callable := range l11ResolveSelectedCallables(packages, function, call.Fun, aliases, literals) {
					if callable.function == nil {
						continue
					}
					for calleeParameter := range invoked[callable.function.node()] {
						if calleeParameter >= len(call.Args) {
							continue
						}
						for parameter := range l11SelectedParameterSources(call.Args[calleeParameter], sources) {
							if l11AddSelectedParameter(invoked, function.node(), parameter) {
								changed = true
							}
						}
					}
				}
				return true
			})
		}
	}
	return invoked
}

func l11SelectedParameterObjects(function *l11SelectedFunction) []*ast.Object {
	var fields *ast.FieldList
	if function.declaration != nil {
		fields = function.declaration.Type.Params
	} else {
		fields = function.literal.Type.Params
	}
	if fields == nil {
		return nil
	}
	var parameters []*ast.Object
	for _, field := range fields.List {
		for _, name := range field.Names {
			parameters = append(parameters, name.Obj)
		}
	}
	return parameters
}

func l11SelectedParameterAliases(function *l11SelectedFunction, parameters []*ast.Object) map[*ast.Object]map[int]bool {
	sources := make(map[*ast.Object]map[int]bool)
	for index, object := range parameters {
		if object != nil {
			sources[object] = map[int]bool{index: true}
		}
	}
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
					name, ok := expression.(*ast.Ident)
					if !ok {
						return true
					}
					names = append(names, name)
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
				for parameter := range l11SelectedParameterSources(values[index], sources) {
					if sources[name.Obj] == nil {
						sources[name.Obj] = make(map[int]bool)
					}
					if !sources[name.Obj][parameter] {
						sources[name.Obj][parameter] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return sources
}

func l11SelectedParameterSources(expression ast.Expr, sources map[*ast.Object]map[int]bool) map[int]bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return sources[value.Obj]
	case *ast.ParenExpr:
		return l11SelectedParameterSources(value.X, sources)
	case *ast.IndexExpr:
		return l11SelectedParameterSources(value.X, sources)
	case *ast.IndexListExpr:
		return l11SelectedParameterSources(value.X, sources)
	default:
		return nil
	}
}

func l11AddSelectedParameter(invoked map[ast.Node]map[int]bool, function ast.Node, parameter int) bool {
	if invoked[function] == nil {
		invoked[function] = make(map[int]bool)
	}
	if invoked[function][parameter] {
		return false
	}
	invoked[function][parameter] = true
	return true
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
	return l11SelectedCallableAliasesWithState(packages, function, literals, l11NewSelectedResolutionState())
}

func l11SelectedCallableAliasesWithState(packages map[string]*l11SelectedPackage, function *l11SelectedFunction, literals map[*ast.FuncLit]*l11SelectedFunction, state *l11SelectedResolutionState) map[*ast.Object][]l11SelectedCallable {
	aliases := make(map[*ast.Object][]l11SelectedCallable)
	if state.aliasing[function.node()] {
		return aliases
	}
	state.aliasing[function.node()] = true
	defer delete(state.aliasing, function.node())
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
				if len(declaration.Lhs) != len(declaration.Rhs) && len(declaration.Rhs) != 1 {
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
				if len(declaration.Names) != len(declaration.Values) && len(declaration.Values) != 1 {
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
				var resolved []l11SelectedCallable
				if len(values) == 1 && len(names) > 1 {
					if call, ok := values[0].(*ast.CallExpr); ok {
						results := l11ResolveSelectedCallableResultsWithState(packages, function, call, aliases, literals, state)
						if index < len(results) {
							resolved = results[index]
						}
					}
				} else if index < len(values) {
					resolved = l11ResolveSelectedCallablesWithState(packages, function, values[index], aliases, literals, state)
				}
				merged := l11MergeSelectedCallables(aliases[name.Obj], resolved)
				if len(merged) != len(aliases[name.Obj]) {
					aliases[name.Obj] = merged
					changed = true
				}
			}
			return true
		})
	}
	return aliases
}

func l11ResolveSelectedCallables(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction) []l11SelectedCallable {
	return l11ResolveSelectedCallablesWithState(packages, current, expression, aliases, literals, l11NewSelectedResolutionState())
}

func l11ResolveSelectedCallablesWithState(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction, state *l11SelectedResolutionState) []l11SelectedCallable {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return l11ResolveSelectedCallablesWithState(packages, current, value.X, aliases, literals, state)
	case *ast.IndexExpr:
		return l11ResolveSelectedCallablesWithState(packages, current, value.X, aliases, literals, state)
	case *ast.IndexListExpr:
		return l11ResolveSelectedCallablesWithState(packages, current, value.X, aliases, literals, state)
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
			if l11SelectedPackageOwnsObject(current.pkg, value.Obj) {
				if resolved := current.pkg.callables[value.Name]; len(resolved) > 0 {
					return resolved
				}
			}
			if declaration, ok := value.Obj.Decl.(*ast.FuncDecl); ok {
				return l11SelectedDeclaredFunction(current.pkg, declaration)
			}
			if declaration, ok := value.Obj.Decl.(*ast.ValueSpec); ok && !state.objects[value.Obj] {
				if initializer := l11SelectedValueInitializer(value.Obj, declaration); initializer != nil {
					state.objects[value.Obj] = true
					resolved := l11ResolveSelectedCallablesWithState(packages, current, initializer, aliases, literals, state)
					delete(state.objects, value.Obj)
					return resolved
				}
			}
			return nil
		}
		if l11SelectedDotImportedProof(current.file, value) {
			return []l11SelectedCallable{{proof: true}}
		}
		for _, imported := range current.file.imports {
			if imported.name != "." {
				continue
			}
			if importedPackage := l11SelectedImportedPackage(packages, imported.path); importedPackage != nil {
				if functions := importedPackage.functions[value.Name]; len(functions) > 0 {
					return l11SelectedFunctions(functions)
				}
			}
		}
		if resolved := current.pkg.callables[value.Name]; len(resolved) > 0 {
			return resolved
		}
		return l11SelectedFunctions(current.pkg.functions[value.Name])
	case *ast.CallExpr:
		var flattened []l11SelectedCallable
		for _, result := range l11ResolveSelectedCallableResultsWithState(packages, current, value, aliases, literals, state) {
			flattened = l11MergeSelectedCallables(flattened, result)
		}
		return flattened
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
		if typeSelector, ok := value.X.(*ast.SelectorExpr); ok {
			if packageName, ok := typeSelector.X.(*ast.Ident); ok && packageName.Obj == nil {
				if importPath := current.file.importPaths[packageName.Name]; importPath != "" {
					if importedPackage := l11SelectedImportedPackage(packages, importPath); importedPackage != nil {
						return l11SelectedFunctions(importedPackage.methods[typeSelector.Sel.Name][value.Sel.Name])
					}
				}
			}
		}
		if l11SelectedTestingSkip(current.file, value) {
			return []l11SelectedCallable{{skip: true}}
		}
		if receiver := l11SelectedExpressionType(current.file, value.X); receiver != "" {
			if packageName, typeName, imported := strings.Cut(receiver, "."); imported {
				if importPath := current.file.importPaths[packageName]; importPath != "" {
					if importedPackage := l11SelectedImportedPackage(packages, importPath); importedPackage != nil {
						return l11SelectedFunctions(importedPackage.methods[typeName][value.Sel.Name])
					}
				}
			}
			return l11SelectedFunctions(current.pkg.methods[receiver][value.Sel.Name])
		}
	}
	return nil
}

func l11ResolveSelectedCallableResultsWithState(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, call *ast.CallExpr, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction, state *l11SelectedResolutionState) [][]l11SelectedCallable {
	var results [][]l11SelectedCallable
	for _, callable := range l11ResolveSelectedCallablesWithState(packages, current, call.Fun, aliases, literals, state) {
		if callable.function == nil || state.returns[callable.function.node()] {
			continue
		}
		state.returns[callable.function.node()] = true
		returnedAliases := l11SelectedCallableAliasesWithState(packages, callable.function, literals, state)
		ast.Inspect(callable.function.body(), func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			statement, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			if len(statement.Results) == 1 {
				if nestedCall, ok := statement.Results[0].(*ast.CallExpr); ok {
					nested := l11ResolveSelectedCallableResultsWithState(packages, callable.function, nestedCall, returnedAliases, literals, state)
					results = l11MergeSelectedCallableResults(results, nested)
					return false
				}
			}
			for index, returned := range statement.Results {
				for len(results) <= index {
					results = append(results, nil)
				}
				resolved := l11ResolveSelectedCallablesWithState(packages, callable.function, returned, returnedAliases, literals, state)
				results[index] = l11MergeSelectedCallables(results[index], resolved)
			}
			return false
		})
		delete(state.returns, callable.function.node())
	}
	return results
}

func l11MergeSelectedCallableResults(left, right [][]l11SelectedCallable) [][]l11SelectedCallable {
	result := append([][]l11SelectedCallable(nil), left...)
	for len(result) < len(right) {
		result = append(result, nil)
	}
	for index := range right {
		result[index] = l11MergeSelectedCallables(result[index], right[index])
	}
	return result
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

func l11MergeSelectedCallables(left, right []l11SelectedCallable) []l11SelectedCallable {
	result := append([]l11SelectedCallable(nil), left...)
	for _, candidate := range right {
		found := false
		for _, existing := range result {
			if existing == candidate {
				found = true
				break
			}
		}
		if !found {
			result = append(result, candidate)
		}
	}
	return result
}

func l11SelectedReceiverType(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	return l11SelectedTypeName(nil, function.Recv.List[0].Type)
}

func l11SelectedExpressionType(file *l11SelectedFile, expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.StarExpr:
		return l11SelectedExpressionType(file, value.X)
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
		case *ast.TypeSpec:
			return declaration.Name.Name
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
		if value.Obj == nil && file != nil {
			for _, imported := range file.imports {
				if imported.name == "." && pathpkg.Base(imported.path) == "testing" && (value.Name == "T" || value.Name == "TB") {
					return "testing." + value.Name
				}
			}
		}
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
		receiver := l11SelectedExpressionType(file, selector.X)
		return receiver == "testing.T" || receiver == "testing.TB"
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
	if identifier.Obj != nil || !l11SelectedProofConstructor(identifier.Name) {
		return false
	}
	for _, imported := range file.imports {
		if imported.name == "." && pathpkg.Base(imported.path) == "sandboxruntime" {
			return true
		}
	}
	return false
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
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{
		"hcloud_token",
		"aws_access_key_id",
		"aws_secret_access_key",
		"digitalocean_access_token",
		"google_application_credentials",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, safeStatement := range []string{
		"hetzner remains disabled",
		"lightsail remains disabled",
		"hetzner remains unauthorized",
		"lightsail remains unauthorized",
		"hetzner remains deferred",
		"lightsail remains deferred",
	} {
		if lower == safeStatement {
			return false
		}
	}
	for _, marker := range []string{
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

func l11SelectedStringConstant(pkg *l11SelectedPackage, expression ast.Expr) (string, bool) {
	switch value := expression.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		literal, err := strconv.Unquote(value.Value)
		return literal, err == nil
	case *ast.Ident:
		literal, ok := pkg.constants[value.Name]
		return literal, ok
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return "", false
		}
		left, leftOK := l11SelectedStringConstant(pkg, value.X)
		right, rightOK := l11SelectedStringConstant(pkg, value.Y)
		return left + right, leftOK && rightOK
	case *ast.ParenExpr:
		return l11SelectedStringConstant(pkg, value.X)
	default:
		return "", false
	}
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
