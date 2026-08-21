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
	captures           map[*ast.Object][]l11SelectedCallable
	concrete           map[*ast.Object][]l11SelectedTypeRef
}

type l11SelectedFile struct {
	path        string
	parsed      *ast.File
	importPaths map[string]string
	imports     []l11SelectedImport
	pkg         *l11SelectedPackage
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
	strings   map[string]l11SelectedStringFact
	types     map[string]l11SelectedTypeAlias
	typeDefs  map[string][]l11SelectedTypeAlias
}

type l11SelectedTypeAlias struct {
	file       *l11SelectedFile
	expression ast.Expr
}

type l11SelectedStringFact struct {
	values   map[string]bool
	unknown  bool
	conflict bool
}

type l11SelectedPackageValue struct {
	file   *l11SelectedFile
	token  token.Token
	names  []*ast.Ident
	values []ast.Expr
}

type l11SelectedCallable struct {
	function   *l11SelectedFunction
	proof      bool
	skip       bool
	cloud      bool
	unresolved bool
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
	packages, err := l11LoadRepositorySelectedTestPackages("..")
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
			name: "package string variable cloud provider",
			source: `package fixture
import "testing"
var providerName = "hetzner"
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = providerName }
`,
			wantIssue: "cloud/provider marker", wantIssues: 1,
		},
		{
			name: "imported string constant cloud provider",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import ("testing"; "github.com/jywlabs/hal/tools/providerfacts")
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = providerfacts.ProviderName }
`,
				"tools/providerfacts/facts.go": `package providerfacts
const ProviderName = "hetzner"
`,
			},
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
			name: "reachable non init global callable reassignment",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
var run = safe
func selectUnsafe() { run = unsafe }
func TestL11PreparedLinuxFinalClosure(*testing.T) { selectUnsafe(); run() }
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "unreachable global callable reassignment remains unreachable",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
var run = safe
func selectUnsafe() { run = unsafe }
func TestL11PreparedLinuxFinalClosure(*testing.T) { run() }
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
		},
		{
			name: "returned callback immediately invoked",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func returnCallback(callback func()) func() { return callback }
func TestL11PreparedLinuxFinalClosure(*testing.T) { returnCallback(mint)() }
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "callback captured and invoked in IIFE",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	callback := mint
	func() { callback() }()
}
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "callback invoked by nested IIFE",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func invoke(callback func()) { func() { callback() }() }
func TestL11PreparedLinuxFinalClosure(*testing.T) { invoke(mint) }
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "concrete implementation behind interface dispatch",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type minter struct{}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { var selected runner = minter{}; selected.Run() }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "concrete interface implementation passed to helper",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type minter struct{}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func invoke(selected runner) { selected.Run() }
func TestL11PreparedLinuxFinalClosure(*testing.T) { invoke(minter{}) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "defined interface embedding testing TB skip",
			source: `package fixture
import "testing"
type testTB interface { testing.TB }
func skipMissing(t testTB) { t.Skip("missing") }
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skipMissing(t) }
`,
			wantIssue: "skip call", wantIssues: 1,
		},
		{
			name: "unresolved dot imported in module call fails closed",
			source: `package fixture
import (. "github.com/jywlabs/hal/tools/missinghelper"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) { Run() }
`,
			wantIssue: "unresolved in-module call", wantIssues: 1,
		},
		{
			name: "promoted embedded proof method",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type minter struct{}
func (minter) Mint() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
type promoted struct { minter }
func TestL11PreparedLinuxFinalClosure(*testing.T) { promoted{}.Mint() }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "uninvoked nested callback remains unreachable",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func ignore(callback func()) { _ = func() { callback() } }
func TestL11PreparedLinuxFinalClosure(*testing.T) { ignore(mint) }
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
		},
		{
			name: "safe concrete interface dispatch excludes unused implementation",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type safeRunner struct{}
type unusedMinter struct{}
func (safeRunner) Run() {}
func (unusedMinter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { var selected runner = safeRunner{}; selected.Run() }
var input any
`,
		},
		{
			name: "unrelated defined interface method named Skip",
			source: `package fixture
import "testing"
type skipper interface { Skip(...any) }
type helper struct{}
func (helper) Skip(...any) {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { var selected skipper = helper{}; selected.Skip("safe") }
`,
		},
		{
			name: "imported pointer method expression proof constructor",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import ("testing"; "github.com/jywlabs/hal/tools/proofhelper")
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint := (*proofhelper.Minter).Mint; mint(&proofhelper.Minter{}) }
`,
				"tools/proofhelper/helper.go": `package proofhelper
import "example.invalid/sandboxruntime"
type Minter struct{}
func (*Minter) Mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			},
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "bare named result callable proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func returned() (run func()) { run = mint; return }
func TestL11PreparedLinuxFinalClosure(*testing.T) { returned()() }
func mint() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "testing TB type alias skip",
			source: `package fixture
import "testing"
type testTB = testing.TB
func skipMissing(t testTB) { t.Skip("missing") }
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skipMissing(t) }
`,
			wantIssue: "skip call", wantIssues: 1,
		},
		{
			name: "testing T pointer method expression skip",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skip := (*testing.T).Skip; skip(t, "missing") }
`,
			wantIssue: "skip call", wantIssues: 1,
		},
		{
			name: "unresolved in module helper call fails closed",
			source: `package fixture
import ("testing"; "github.com/jywlabs/hal/tools/missinghelper")
func TestL11PreparedLinuxFinalClosure(*testing.T) { missinghelper.Run() }
`,
			wantIssue: "unresolved in-module call", wantIssues: 1,
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

func TestL11FinalClosureRepositoryInventoryIncludesToolsHelpers(t *testing.T) {
	root := t.TempDir()
	for path, source := range map[string]string{
		"cmd/fixture_test.go": `package cmd
import ("testing"; "github.com/jywlabs/hal/tools/l11proof")
func TestL11PreparedLinuxFinalClosure(*testing.T) { l11proof.Mint() }
`,
		"internal/placeholder/placeholder.go": `package placeholder
`,
		"tools/l11proof/proof.go": `package l11proof
import "example.invalid/sandboxruntime"
func Mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
	} {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	packages, err := l11LoadRepositorySelectedTestPackages(root)
	if err != nil {
		t.Fatal(err)
	}
	issues := l11SelectedPreparedTestIssues(packages)
	if len(issues) != 1 || !strings.Contains(issues[0], "synthetic credential proof constructor") {
		t.Fatalf("issues = %v, want tools helper proof issue", issues)
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

func TestL11FinalClosureConflictingBuildTagFactsTerminateAndFailClosed(t *testing.T) {
	const helperEnvironment = "HAL_L11_CONFLICTING_FACTS_HELPER"
	if os.Getenv(helperEnvironment) == "1" {
		sources := map[string]string{
			"fixture_test.go": `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = providerName }
`,
			"provider_linux.go": `//go:build linux
package fixture
const providerName = "disabled"
`,
			"provider_windows.go": `//go:build windows
package fixture
const providerName = "hetzner"
`,
		}
		packages, err := l11ParseSelectedTestSources(sources)
		if err != nil {
			t.Fatal(err)
		}
		issues := l11SelectedPreparedTestIssues(packages)
		if len(issues) != 1 || !strings.Contains(issues[0], "cloud/provider marker") {
			t.Fatalf("issues = %v, want conflicting cloud fact issue", issues)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestL11FinalClosureConflictingBuildTagFactsTerminateAndFailClosed$")
	command.Env = append(os.Environ(), helperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("conflicting build-tag fact analysis did not terminate within two seconds: %s", output)
	}
	if err != nil {
		t.Fatalf("conflicting build-tag fact analysis failed: %v: %s", err, output)
	}
}

func l11LoadRepositorySelectedTestPackages(repoRoot string) (map[string]*l11SelectedPackage, error) {
	return l11LoadSelectedTestPackages([]string{repoRoot})
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
				strings:   make(map[string]l11SelectedStringFact),
				types:     make(map[string]l11SelectedTypeAlias),
				typeDefs:  make(map[string][]l11SelectedTypeAlias),
			}
			packages[key] = pkg
		}
		file := &l11SelectedFile{
			path:        path,
			parsed:      parsed,
			importPaths: l11SelectedFileImportPaths(parsed),
			imports:     l11SelectedFileImports(parsed),
			pkg:         pkg,
		}
		pkg.files = append(pkg.files, file)
		for _, declaration := range parsed.Decls {
			if generated, ok := declaration.(*ast.GenDecl); ok && (generated.Tok == token.CONST || generated.Tok == token.VAR || generated.Tok == token.TYPE) {
				for _, spec := range generated.Specs {
					if value, ok := spec.(*ast.ValueSpec); ok && (generated.Tok == token.CONST || generated.Tok == token.VAR) {
						pkg.values = append(pkg.values, &l11SelectedPackageValue{file: file, token: generated.Tok, names: value.Names, values: value.Values})
					}
					if typeSpec, ok := spec.(*ast.TypeSpec); ok {
						definition := l11SelectedTypeAlias{file: file, expression: typeSpec.Type}
						pkg.typeDefs[typeSpec.Name.Name] = append(pkg.typeDefs[typeSpec.Name.Name], definition)
						if typeSpec.Assign.IsValid() {
							pkg.types[typeSpec.Name.Name] = definition
						}
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
		pkg.strings = make(map[string]l11SelectedStringFact)
	}
	for changed := true; changed; {
		changed = false
		for _, pkg := range packages {
			for _, declaration := range pkg.values {
				if len(declaration.names) != len(declaration.values) {
					for _, name := range declaration.names {
						if l11MergeSelectedStringFactInto(pkg.strings, name.Name, l11SelectedStringFact{unknown: true}) {
							changed = true
						}
					}
					continue
				}
				context := l11SelectedPackageExpressionContext(pkg, declaration.file)
				for index, name := range declaration.names {
					fact := l11ResolveSelectedStringFact(packages, context, declaration.values[index], make(map[*ast.Object]bool), 0)
					if l11MergeSelectedStringFactInto(pkg.strings, name.Name, fact) {
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
	literals := l11SelectedFunctionLiterals(packages)
	l11PrepareSelectedPackageFacts(packages, literals)
	packageInitializers := l11SelectedPackageInitializers(packages)
	invokedParameters := l11SelectedInvokedParameters(packages, literals)
	var issues []string
	for factsChanged := true; factsChanged; {
		factsChanged = false
		queue := []*l11SelectedFunction{root}
		reachable := make(map[ast.Node]bool)
		packagesQueued := make(map[*l11SelectedPackage]bool)
		var recordCallable func(l11SelectedCallable)
		recordCallable = func(callable l11SelectedCallable) {
			switch {
			case callable.proof:
				issues = append(issues, fmt.Sprintf("%s reaches synthetic credential proof constructor", root.declaration.Name.Name))
			case callable.skip:
				issues = append(issues, fmt.Sprintf("%s reaches a skip call", root.declaration.Name.Name))
			case callable.cloud:
				issues = append(issues, fmt.Sprintf("%s reaches a cloud/provider marker", root.declaration.Name.Name))
			case callable.unresolved:
				issues = append(issues, fmt.Sprintf("%s reaches an unresolved in-module call", root.declaration.Name.Name))
			case callable.function != nil && !reachable[callable.function.node()]:
				queue = append(queue, callable.function)
			}
		}
		recordStringFact := func(current *l11SelectedFunction, expression ast.Expr) {
			fact := l11ResolveSelectedStringFact(packages, current, expression, make(map[*ast.Object]bool), 0)
			for literal := range fact.values {
				if l11ForbiddenCloudLiteral(literal) {
					recordCallable(l11SelectedCallable{cloud: true})
				}
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
			if l11MergeReachablePackageCallableAssignments(packages, current, aliases, literals) {
				factsChanged = true
			}
			queuePackage(current.pkg)
			ast.Inspect(current.body(), func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.FuncLit:
					return false
				case *ast.BinaryExpr:
					recordStringFact(current, value)
					return false
				case *ast.SelectorExpr:
					if l11SelectedProofSelector(current.file, value) {
						recordCallable(l11SelectedCallable{proof: true})
					}
					if l11SelectedCloudSelector(current.file, value) {
						recordCallable(l11SelectedCallable{cloud: true})
					}
					recordStringFact(current, value)
				case *ast.Ident:
					if l11SelectedDotImportedProof(current.file, value) {
						recordCallable(l11SelectedCallable{proof: true})
					}
					if value.Obj == nil && l11ForbiddenCloudLiteral(value.Name) {
						recordCallable(l11SelectedCallable{cloud: true})
					}
					recordStringFact(current, value)
				case *ast.BasicLit:
					if value.Kind == token.STRING {
						recordStringFact(current, value)
					}
				case *ast.CallExpr:
					for _, callable := range l11ResolveSelectedCallables(packages, current, value.Fun, aliases, literals) {
						recordCallable(callable)
						if callable.function == nil {
							continue
						}
						if callable.function.concrete == nil {
							callable.function.concrete = make(map[*ast.Object][]l11SelectedTypeRef)
						}
						for parameterIndex, parameter := range l11SelectedPositionalParameterObjects(callable.function) {
							if parameter == nil || parameterIndex >= len(value.Args) {
								continue
							}
							argumentTypes := l11SelectedConcreteExpressionTypes(packages, current, value.Args[parameterIndex], make(map[*ast.Object]bool), 0)
							merged := l11MergeSelectedTypeRefs(callable.function.concrete[parameter], argumentTypes)
							if len(merged) != len(callable.function.concrete[parameter]) {
								callable.function.concrete[parameter] = merged
								factsChanged = true
							}
						}
						for parameter := range invokedParameters[callable.function.node()] {
							if parameter >= len(value.Args) {
								continue
							}
							for _, argument := range l11ResolveSelectedCallables(packages, current, value.Args[parameter], aliases, literals) {
								recordCallable(argument)
							}
						}
					}
				}
				return true
			})
		}
	}
	return l11UniqueStrings(issues)
}

func l11MergeReachablePackageCallableAssignments(packages map[string]*l11SelectedPackage, function *l11SelectedFunction, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction) bool {
	changed := false
	ast.Inspect(function.body(), func(node ast.Node) bool {
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
			if !ok || (name.Name != "_" && !l11SelectedPackageAssignmentTarget(function.pkg, name, assignment.Tok)) {
				return true
			}
			names = append(names, name)
		}
		if l11MergeSelectedPackageValueCallables(packages, function.pkg, function, names, assignment.Rhs, aliases, literals) {
			changed = true
		}
		return true
	})
	return changed
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
			if l11MergeSelectedInvokedParameters(
				packages,
				function,
				function.body(),
				sources,
				aliases,
				literals,
				invoked,
				make(map[ast.Node]bool),
			) {
				changed = true
			}
		}
	}
	return invoked
}

func l11MergeSelectedInvokedParameters(
	packages map[string]*l11SelectedPackage,
	owner *l11SelectedFunction,
	body *ast.BlockStmt,
	sources map[*ast.Object]map[int]bool,
	aliases map[*ast.Object][]l11SelectedCallable,
	literals map[*ast.FuncLit]*l11SelectedFunction,
	invoked map[ast.Node]map[int]bool,
	visiting map[ast.Node]bool,
) bool {
	if body == nil || visiting[body] {
		return false
	}
	visiting[body] = true
	defer delete(visiting, body)

	changed := false
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for parameter := range l11SelectedParameterSources(call.Fun, sources) {
			if l11AddSelectedParameter(invoked, owner.node(), parameter) {
				changed = true
			}
		}
		for _, callable := range l11ResolveSelectedCallables(packages, owner, call.Fun, aliases, literals) {
			if callable.function == nil {
				continue
			}
			for calleeParameter := range invoked[callable.function.node()] {
				if calleeParameter >= len(call.Args) {
					continue
				}
				for parameter := range l11SelectedParameterSources(call.Args[calleeParameter], sources) {
					if l11AddSelectedParameter(invoked, owner.node(), parameter) {
						changed = true
					}
				}
			}
			if callable.function.literal != nil {
				nestedAliases := l11SelectedCallableAliases(packages, callable.function, literals)
				if l11MergeSelectedInvokedParameters(
					packages,
					owner,
					callable.function.body(),
					sources,
					nestedAliases,
					literals,
					invoked,
					visiting,
				) {
					changed = true
				}
			}
		}
		return true
	})
	return changed
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
	aliases := make(map[*ast.Object][]l11SelectedCallable, len(function.captures))
	for object, captured := range function.captures {
		aliases[object] = l11MergeSelectedCallables(nil, captured)
	}
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
		if function.captures == nil {
			function.captures = make(map[*ast.Object][]l11SelectedCallable)
		}
		for object, captured := range aliases {
			function.captures[object] = l11MergeSelectedCallables(function.captures[object], captured)
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
			if l11InModuleImport(imported.path) {
				return []l11SelectedCallable{{unresolved: true}}
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
					if functions := importedPackage.functions[value.Sel.Name]; len(functions) > 0 {
						return l11SelectedFunctions(functions)
					}
					if l11InModuleImport(importPath) {
						return []l11SelectedCallable{{unresolved: true}}
					}
				}
				if l11InModuleImport(importPath) {
					return []l11SelectedCallable{{unresolved: true}}
				}
				return nil
			}
		}
		if typeSelector, ok := value.X.(*ast.SelectorExpr); ok {
			if packageName, ok := typeSelector.X.(*ast.Ident); ok && packageName.Obj == nil {
				if importPath := current.file.importPaths[packageName.Name]; importPath != "" {
					if importedPackage := l11SelectedImportedPackage(packages, importPath); importedPackage != nil {
						if methods := l11SelectedMethodsForType(packages, l11SelectedTypeRef{pkg: importedPackage, name: typeSelector.Sel.Name}, value.Sel.Name, make(map[l11SelectedTypeRef]bool)); len(methods) > 0 {
							return methods
						}
						return []l11SelectedCallable{{unresolved: true}}
					}
					if l11InModuleImport(importPath) {
						return []l11SelectedCallable{{unresolved: true}}
					}
				}
			}
		}
		if l11SelectedTestingSkip(packages, current.file, value) {
			return []l11SelectedCallable{{skip: true}}
		}
		var resolved []l11SelectedCallable
		for _, concrete := range l11SelectedConcreteExpressionTypes(packages, current, value.X, make(map[*ast.Object]bool), 0) {
			resolved = l11MergeSelectedCallables(resolved, l11SelectedMethodsForType(packages, concrete, value.Sel.Name, make(map[l11SelectedTypeRef]bool)))
		}
		if len(resolved) > 0 {
			return resolved
		}
		if receiver := l11SelectedExpressionType(current.file, value.X); receiver != "" {
			if packageName, typeName, imported := strings.Cut(receiver, "."); imported {
				if importPath := current.file.importPaths[packageName]; importPath != "" {
					if importedPackage := l11SelectedImportedPackage(packages, importPath); importedPackage != nil {
						if methods := l11SelectedMethodsForType(packages, l11SelectedTypeRef{pkg: importedPackage, name: typeName}, value.Sel.Name, make(map[l11SelectedTypeRef]bool)); len(methods) > 0 {
							return methods
						}
						return []l11SelectedCallable{{unresolved: true}}
					}
					if l11InModuleImport(importPath) {
						return []l11SelectedCallable{{unresolved: true}}
					}
				}
			}
			return l11SelectedMethodsForType(packages, l11SelectedTypeRef{pkg: current.pkg, name: receiver}, value.Sel.Name, make(map[l11SelectedTypeRef]bool))
		}
	}
	return nil
}

func l11InModuleImport(importPath string) bool {
	return strings.HasPrefix(importPath, "github.com/jywlabs/hal/")
}

func l11ResolveSelectedCallableResultsWithState(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, call *ast.CallExpr, aliases map[*ast.Object][]l11SelectedCallable, literals map[*ast.FuncLit]*l11SelectedFunction, state *l11SelectedResolutionState) [][]l11SelectedCallable {
	var results [][]l11SelectedCallable
	for _, callable := range l11ResolveSelectedCallablesWithState(packages, current, call.Fun, aliases, literals, state) {
		if callable.function == nil || state.returns[callable.function.node()] {
			continue
		}
		state.returns[callable.function.node()] = true
		returnedAliases := l11SelectedCallableAliasesWithState(packages, callable.function, literals, state)
		for index, parameter := range l11SelectedPositionalParameterObjects(callable.function) {
			if parameter == nil || index >= len(call.Args) {
				continue
			}
			resolved := l11ResolveSelectedCallablesWithState(packages, current, call.Args[index], aliases, literals, state)
			returnedAliases[parameter] = l11MergeSelectedCallables(returnedAliases[parameter], resolved)
		}
		ast.Inspect(callable.function.body(), func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			statement, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			if len(statement.Results) == 0 {
				for index, result := range l11SelectedPositionalResultObjects(callable.function) {
					for len(results) <= index {
						results = append(results, nil)
					}
					if result != nil {
						results[index] = l11MergeSelectedCallables(results[index], returnedAliases[result])
					}
				}
				return false
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

func l11SelectedPositionalParameterObjects(function *l11SelectedFunction) []*ast.Object {
	var fields *ast.FieldList
	if function.declaration != nil {
		fields = function.declaration.Type.Params
	} else {
		fields = function.literal.Type.Params
	}
	return l11SelectedPositionalFieldObjects(fields)
}

func l11SelectedPositionalResultObjects(function *l11SelectedFunction) []*ast.Object {
	var fields *ast.FieldList
	if function.declaration != nil {
		fields = function.declaration.Type.Results
	} else {
		fields = function.literal.Type.Results
	}
	return l11SelectedPositionalFieldObjects(fields)
}

func l11SelectedPositionalFieldObjects(fields *ast.FieldList) []*ast.Object {
	if fields == nil {
		return nil
	}
	var objects []*ast.Object
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			objects = append(objects, nil)
			continue
		}
		for _, name := range field.Names {
			objects = append(objects, name.Obj)
		}
	}
	return objects
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
	case *ast.SelectorExpr:
		return l11SelectedTypeName(file, value)
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
	return l11SelectedTypeNameDepth(file, expression, make(map[string]bool), 0)
}

func l11SelectedTypeNameDepth(file *l11SelectedFile, expression ast.Expr, visiting map[string]bool, depth int) string {
	if depth > 32 {
		return ""
	}
	switch value := expression.(type) {
	case *ast.StarExpr:
		return l11SelectedTypeNameDepth(file, value.X, visiting, depth+1)
	case *ast.ParenExpr:
		return l11SelectedTypeNameDepth(file, value.X, visiting, depth+1)
	case *ast.Ident:
		if value.Obj != nil {
			if typeSpec, ok := value.Obj.Decl.(*ast.TypeSpec); ok && typeSpec.Assign.IsValid() {
				return l11SelectedTypeNameDepth(file, typeSpec.Type, visiting, depth+1)
			}
		}
		if value.Obj == nil && file != nil {
			for _, imported := range file.imports {
				if imported.name == "." && pathpkg.Base(imported.path) == "testing" && (value.Name == "T" || value.Name == "TB") {
					return "testing." + value.Name
				}
			}
			if file.pkg != nil {
				alias, ok := file.pkg.types[value.Name]
				if ok && !visiting[value.Name] {
					visiting[value.Name] = true
					resolved := l11SelectedTypeNameDepth(alias.file, alias.expression, visiting, depth+1)
					delete(visiting, value.Name)
					return resolved
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

type l11SelectedTypeRef struct {
	pkg  *l11SelectedPackage
	name string
}

func l11SelectedTypeRefForExpression(packages map[string]*l11SelectedPackage, file *l11SelectedFile, expression ast.Expr) (l11SelectedTypeRef, bool) {
	switch value := expression.(type) {
	case *ast.StarExpr:
		return l11SelectedTypeRefForExpression(packages, file, value.X)
	case *ast.ParenExpr:
		return l11SelectedTypeRefForExpression(packages, file, value.X)
	case *ast.Ident:
		if value.Name == "" {
			return l11SelectedTypeRef{}, false
		}
		return l11SelectedTypeRef{pkg: file.pkg, name: value.Name}, true
	case *ast.SelectorExpr:
		identifier, ok := value.X.(*ast.Ident)
		if !ok || identifier.Obj != nil {
			return l11SelectedTypeRef{}, false
		}
		importPath := file.importPaths[identifier.Name]
		if importPath == "" {
			return l11SelectedTypeRef{}, false
		}
		if imported := l11SelectedImportedPackage(packages, importPath); imported != nil {
			return l11SelectedTypeRef{pkg: imported, name: value.Sel.Name}, true
		}
		return l11SelectedTypeRef{name: pathpkg.Base(importPath) + "." + value.Sel.Name}, true
	default:
		return l11SelectedTypeRef{}, false
	}
}

func l11SelectedMethodsForType(packages map[string]*l11SelectedPackage, ref l11SelectedTypeRef, method string, visiting map[l11SelectedTypeRef]bool) []l11SelectedCallable {
	if ref.pkg == nil || ref.name == "" || visiting[ref] {
		return nil
	}
	visiting[ref] = true
	defer delete(visiting, ref)

	resolved := l11SelectedFunctions(ref.pkg.methods[ref.name][method])
	definitions := ref.pkg.typeDefs[ref.name]
	if len(definitions) == 0 {
		return resolved
	}
	for _, definition := range definitions {
		switch expression := definition.expression.(type) {
		case *ast.StructType:
			for _, field := range expression.Fields.List {
				if len(field.Names) != 0 {
					continue
				}
				if embedded, ok := l11SelectedTypeRefForExpression(packages, definition.file, field.Type); ok {
					resolved = l11MergeSelectedCallables(resolved, l11SelectedMethodsForType(packages, embedded, method, visiting))
				}
			}
		default:
			if underlying, ok := l11SelectedTypeRefForExpression(packages, definition.file, expression); ok && underlying != ref {
				resolved = l11MergeSelectedCallables(resolved, l11SelectedMethodsForType(packages, underlying, method, visiting))
			}
		}
	}
	return resolved
}

func l11SelectedConcreteExpressionTypes(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr, visiting map[*ast.Object]bool, depth int) []l11SelectedTypeRef {
	if expression == nil || depth > 32 {
		return nil
	}
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return l11SelectedConcreteExpressionTypes(packages, current, value.X, visiting, depth+1)
	case *ast.UnaryExpr:
		return l11SelectedConcreteExpressionTypes(packages, current, value.X, visiting, depth+1)
	case *ast.CompositeLit:
		if ref, ok := l11SelectedTypeRefForExpression(packages, current.file, value.Type); ok && !l11SelectedTypeIsInterface(ref, make(map[l11SelectedTypeRef]bool)) {
			return []l11SelectedTypeRef{ref}
		}
	case *ast.Ident:
		if value.Obj == nil || visiting[value.Obj] {
			return nil
		}
		visiting[value.Obj] = true
		defer delete(visiting, value.Obj)
		resolved := l11MergeSelectedTypeRefs(nil, current.concrete[value.Obj])
		switch declaration := value.Obj.Decl.(type) {
		case *ast.ValueSpec:
			if initializer := l11SelectedValueInitializer(value.Obj, declaration); initializer != nil {
				resolved = l11MergeSelectedTypeRefs(resolved, l11SelectedConcreteExpressionTypes(packages, current, initializer, visiting, depth+1))
			}
			if declaration.Type != nil {
				if ref, ok := l11SelectedTypeRefForExpression(packages, current.file, declaration.Type); ok && !l11SelectedTypeIsInterface(ref, make(map[l11SelectedTypeRef]bool)) {
					resolved = l11MergeSelectedTypeRefs(resolved, []l11SelectedTypeRef{ref})
				}
			}
		case *ast.AssignStmt:
			for index, target := range declaration.Lhs {
				identifier, ok := target.(*ast.Ident)
				if !ok || identifier.Obj != value.Obj || index >= len(declaration.Rhs) {
					continue
				}
				resolved = l11MergeSelectedTypeRefs(resolved, l11SelectedConcreteExpressionTypes(packages, current, declaration.Rhs[index], visiting, depth+1))
			}
		}
		ast.Inspect(current.body(), func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != len(assignment.Rhs) {
				return true
			}
			for index, target := range assignment.Lhs {
				identifier, ok := target.(*ast.Ident)
				if ok && identifier.Obj == value.Obj {
					resolved = l11MergeSelectedTypeRefs(resolved, l11SelectedConcreteExpressionTypes(packages, current, assignment.Rhs[index], visiting, depth+1))
				}
			}
			return true
		})
		return resolved
	}
	return nil
}

func l11SelectedTypeIsInterface(ref l11SelectedTypeRef, visiting map[l11SelectedTypeRef]bool) bool {
	if ref.pkg == nil || visiting[ref] {
		return false
	}
	visiting[ref] = true
	defer delete(visiting, ref)
	definitions := ref.pkg.typeDefs[ref.name]
	if len(definitions) == 0 {
		return false
	}
	for _, definition := range definitions {
		if _, ok := definition.expression.(*ast.InterfaceType); ok {
			return true
		}
		underlying, ok := l11SelectedTypeRefForExpression(nil, definition.file, definition.expression)
		if ok && underlying != ref && l11SelectedTypeIsInterface(underlying, visiting) {
			return true
		}
	}
	return false
}

func l11MergeSelectedTypeRefs(left, right []l11SelectedTypeRef) []l11SelectedTypeRef {
	result := append([]l11SelectedTypeRef(nil), left...)
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

func l11SelectedTestingSkip(packages map[string]*l11SelectedPackage, file *l11SelectedFile, selector *ast.SelectorExpr) bool {
	switch selector.Sel.Name {
	case "Skip", "Skipf", "SkipNow":
		receiver := l11SelectedExpressionType(file, selector.X)
		if receiver == "testing.T" || receiver == "testing.TB" {
			return true
		}
		ref, ok := l11SelectedTypeRefForExpression(packages, file, &ast.Ident{Name: receiver})
		return ok && l11SelectedTypeEmbedsTestingTB(packages, ref, make(map[l11SelectedTypeRef]bool))
	default:
		return false
	}
}

func l11SelectedTypeEmbedsTestingTB(packages map[string]*l11SelectedPackage, ref l11SelectedTypeRef, visiting map[l11SelectedTypeRef]bool) bool {
	if ref.name == "testing.T" || ref.name == "testing.TB" {
		return true
	}
	if ref.pkg == nil || visiting[ref] {
		return false
	}
	visiting[ref] = true
	defer delete(visiting, ref)
	definitions := ref.pkg.typeDefs[ref.name]
	if len(definitions) == 0 {
		return false
	}
	for _, definition := range definitions {
		if embedded, ok := l11SelectedTypeRefForExpression(packages, definition.file, definition.expression); ok && embedded != ref && l11SelectedTypeEmbedsTestingTB(packages, embedded, visiting) {
			return true
		}
		interfaceType, ok := definition.expression.(*ast.InterfaceType)
		if !ok {
			continue
		}
		for _, field := range interfaceType.Methods.List {
			if len(field.Names) != 0 {
				continue
			}
			embedded, ok := l11SelectedTypeRefForExpression(packages, definition.file, field.Type)
			if ok && l11SelectedTypeEmbedsTestingTB(packages, embedded, visiting) {
				return true
			}
		}
	}
	return false
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

const (
	l11SelectedMaxStringFacts = 64
	l11SelectedMaxStringBytes = 4096
)

func l11ResolveSelectedStringFact(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr, visiting map[*ast.Object]bool, depth int) l11SelectedStringFact {
	if expression == nil || current == nil || current.pkg == nil || depth > 64 {
		return l11SelectedStringFact{unknown: true}
	}
	switch value := expression.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return l11SelectedStringFact{}
		}
		literal, err := strconv.Unquote(value.Value)
		if err != nil || len(literal) > l11SelectedMaxStringBytes {
			return l11SelectedStringFact{unknown: true}
		}
		return l11SelectedStringFact{values: map[string]bool{literal: true}}
	case *ast.Ident:
		if value.Obj != nil {
			if visiting[value.Obj] {
				return l11SelectedStringFact{unknown: true}
			}
			if declaration, ok := value.Obj.Decl.(*ast.ValueSpec); ok {
				if initializer := l11SelectedValueInitializer(value.Obj, declaration); initializer != nil {
					visiting[value.Obj] = true
					fact := l11ResolveSelectedStringFact(packages, current, initializer, visiting, depth+1)
					delete(visiting, value.Obj)
					return fact
				}
			}
		}
		if fact, ok := current.pkg.strings[value.Name]; ok {
			return l11CloneSelectedStringFact(fact)
		}
		return l11SelectedStringFact{}
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return l11SelectedStringFact{}
		}
		left := l11ResolveSelectedStringFact(packages, current, value.X, visiting, depth+1)
		right := l11ResolveSelectedStringFact(packages, current, value.Y, visiting, depth+1)
		result := l11SelectedStringFact{unknown: left.unknown || right.unknown || len(left.values) == 0 || len(right.values) == 0}
		for leftValue := range left.values {
			for rightValue := range right.values {
				combined := leftValue + rightValue
				if len(combined) > l11SelectedMaxStringBytes || !l11AddSelectedStringValue(&result, combined) {
					result.unknown = true
				}
			}
		}
		return result
	case *ast.ParenExpr:
		return l11ResolveSelectedStringFact(packages, current, value.X, visiting, depth+1)
	case *ast.SelectorExpr:
		identifier, ok := value.X.(*ast.Ident)
		if !ok || identifier.Obj != nil {
			return l11SelectedStringFact{}
		}
		importPath := current.file.importPaths[identifier.Name]
		importedPackage := l11SelectedImportedPackage(packages, importPath)
		if importedPackage == nil {
			return l11SelectedStringFact{}
		}
		return l11CloneSelectedStringFact(importedPackage.strings[value.Sel.Name])
	default:
		return l11SelectedStringFact{}
	}
}

func l11MergeSelectedStringFactInto(facts map[string]l11SelectedStringFact, name string, incoming l11SelectedStringFact) bool {
	current := l11CloneSelectedStringFact(facts[name])
	changed := false
	if incoming.unknown && !current.unknown {
		current.unknown = true
		changed = true
	}
	if incoming.conflict && !current.conflict {
		current.conflict = true
		changed = true
	}
	for value := range incoming.values {
		before := len(current.values)
		if !l11AddSelectedStringValue(&current, value) {
			if !current.unknown {
				current.unknown = true
				changed = true
			}
			continue
		}
		if len(current.values) != before {
			changed = true
		}
	}
	if len(current.values) > 1 && !current.conflict {
		current.conflict = true
		changed = true
	}
	if changed {
		facts[name] = current
	}
	return changed
}

func l11AddSelectedStringValue(fact *l11SelectedStringFact, value string) bool {
	if fact == nil || len(value) > l11SelectedMaxStringBytes {
		return false
	}
	if fact.values == nil {
		fact.values = make(map[string]bool)
	}
	if fact.values[value] {
		return true
	}
	if len(fact.values) >= l11SelectedMaxStringFacts {
		return false
	}
	fact.values[value] = true
	if len(fact.values) > 1 {
		fact.conflict = true
	}
	return true
}

func l11CloneSelectedStringFact(source l11SelectedStringFact) l11SelectedStringFact {
	cloned := l11SelectedStringFact{unknown: source.unknown, conflict: source.conflict}
	if len(source.values) > 0 {
		cloned.values = make(map[string]bool, len(source.values))
		for value := range source.values {
			cloned.values[value] = true
		}
	}
	return cloned
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
