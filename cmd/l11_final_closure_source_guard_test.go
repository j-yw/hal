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
	declaration *ast.FuncDecl
	file        *l11SelectedFile
	pkg         *l11SelectedPackage
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
	values    []*l11SelectedPackageValue
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
	names  []*ast.Ident
	values []ast.Expr
}

type l11SelectedCallable struct {
	function *l11SelectedFunction
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
			name: "exact selected subtest callback is allowed",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { t.Run("rootless_advisory_success", runRootlessAdvisorySuccess) }
func runRootlessAdvisorySuccess(*testing.T) {}
`,
		},
		{
			name: "exact selected subtest callback permits testing import alias",
			source: `package fixture
import stdtesting "testing"
func TestL11PreparedLinuxFinalClosure(t *stdtesting.T) { t.Run("rootless_advisory_success", runRootlessAdvisorySuccess) }
func runRootlessAdvisorySuccess(*stdtesting.T) {}
`,
		},
		{
			name: "exact selected subtest callback permits testing T type alias",
			source: `package fixture
import stdtesting "testing"
type selectedT = stdtesting.T
func TestL11PreparedLinuxFinalClosure(t *selectedT) { t.Run("rootless_advisory_success", runRootlessAdvisorySuccess) }
func runRootlessAdvisorySuccess(*selectedT) {}
`,
		},
		{
			name: "exact selected subtest callback permits dereferenced testing T receiver",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { (*t).Run("rootless_advisory_success", runRootlessAdvisorySuccess) }
func runRootlessAdvisorySuccess(*testing.T) {}
`,
		},
		{
			name: "exact selected subtest callback permits sibling testing T type alias",
			sources: map[string]string{
				"root/alias_test.go": `package fixture
import stdtesting "testing"
type selectedT = stdtesting.T
`,
				"root/fixture_test.go": `package fixture
func TestL11PreparedLinuxFinalClosure(t *selectedT) { t.Run("rootless_advisory_success", runRootlessAdvisorySuccess) }
func runRootlessAdvisorySuccess(*selectedT) {}
`,
			},
		},
		{
			name: "exact selected subtest callback permits testing T pointer type alias",
			source: `package fixture
import "testing"
type selectedPointerT = *testing.T
func TestL11PreparedLinuxFinalClosure(t selectedPointerT) { t.Run("rootless_advisory_success", runRootlessAdvisorySuccess) }
func runRootlessAdvisorySuccess(selectedPointerT) {}
`,
		},
		{
			name: "local testing field cannot impersonate testing T Run",
			source: `package fixture
import (stdtesting "testing"; "example.invalid/sandboxruntime")
type fakeT struct{}
func (fakeT) Run(string, func(*stdtesting.T)) bool { _, _ = sandboxruntime.NewJobCredentialActiveProof(input); return true }
func TestL11PreparedLinuxFinalClosure(*stdtesting.T) {
	testing := struct{ T fakeT }{}
	testing.T.Run("rootless_advisory_success", runRootlessAdvisorySuccess)
}
func runRootlessAdvisorySuccess(*stdtesting.T) {}
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "shadowed testing import cannot impersonate testing T Run",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type fakeT struct{}
func (fakeT) Run(string, func(*testing.T)) bool { _, _ = sandboxruntime.NewJobCredentialActiveProof(input); return true }
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	testing := struct{ T fakeT }{}
	testing.T.Run("rootless_advisory_success", runRootlessAdvisorySuccess)
}
func runRootlessAdvisorySuccess(*testing.T) {}
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "fake Run method is not a selected subtest seam",
			source: `package fixture
import stdtesting "testing"
type fakeT struct{}
func (fakeT) Run(string, func(*stdtesting.T)) bool { return true }
func TestL11PreparedLinuxFinalClosure(*stdtesting.T) { fakeT{}.Run("rootless_advisory_success", runRootlessAdvisorySuccess) }
func runRootlessAdvisorySuccess(*stdtesting.T) {}
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "exact selected subtest callback is traversed",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(t *testing.T) { t.Run("strict_firecracker_success", runStrictFirecrackerSuccess) }
func runStrictFirecrackerSuccess(*testing.T) { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "unknown selected subtest name is forbidden",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { t.Run("not_in_the_matrix", runUnknown) }
func runUnknown(*testing.T) {}
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "selected subtest closure is forbidden",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { t.Run("rootless_advisory_success", func(*testing.T) {}) }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "matrix shaped non subtest callback is forbidden",
			source: `package fixture
import "testing"
func invoke(string, any) {}
func callback() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { invoke("rootless_advisory_success", callback) }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "selected subtest production callback is forbidden",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { t.Run("rootless_advisory_success", productionScenario) }
`,
				"root/scenario.go": `package fixture
import "testing"
func productionScenario(*testing.T) {}
`,
			},
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "ignored callback shape is forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) { ignore(mint) }
func ignore(func()) {}
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "generic helper call proof constructor",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func mint[T any]() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { mint[any]() }
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "discarded multi return callable shape is forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func choices() (func(), func()) { return unsafe, safe }
func TestL11PreparedLinuxFinalClosure(*testing.T) { _, run := choices(); run() }
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			name: "blank cloud provider import is forbidden",
			source: `package fixture
import (_ "example.invalid/hetzner"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
			wantIssue: "blank import", wantIssues: 1,
		},
		{
			name: "sibling file blank cloud provider import is forbidden",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
				"root/provider_test.go": `package fixture
import _ "example.invalid/hetzner"
`,
			},
			wantIssue: "blank import", wantIssues: 1,
		},
		{
			name: "resolved external blank import is forbidden",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import (_ "example.invalid/helper"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
				"helper/helper.go": `package helper
func init() { _ = "HCLOUD_TOKEN" }
`,
			},
			wantIssue: "blank import", wantIssues: 1,
		},
		{
			name: "unresolved external blank import is forbidden",
			source: `package fixture
import (_ "example.invalid/unresolved"; "testing")
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
			wantIssue: "blank import", wantIssues: 1,
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
			name: "uninvoked closure shape is forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	unused := func() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
	_ = unused
}
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "global callable variable shape is forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
var run = safe
func selectUnsafe() { run = unsafe }
func TestL11PreparedLinuxFinalClosure(*testing.T) { run() }
func safe() {}
func unsafe() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "concrete interface implementation returned by helper",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type minter struct{}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func choose() runner { return minter{} }
func TestL11PreparedLinuxFinalClosure(*testing.T) { selected := choose(); selected.Run() }
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "explicit interface conversion preserves concrete implementation",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type minter struct{}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { selected := runner(minter{}); selected.Run() }
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "predeclared any conversion is forbidden",
			source: `package fixture
import "testing"
type minter struct{}
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = any(minter{}) }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "implicitly instantiated generic direct helper is forbidden",
			source: `package fixture
import "testing"
func generic[T ~int](T) {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { generic(1) }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "imported package function value is forbidden",
			sources: map[string]string{
				"root/fixture_test.go": `package fixture
import ("testing"; "example.invalid/helper")
func invoke(func()) {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { invoke(helper.Run) }
`,
				"helper/helper.go": `package helper
func Run() {}
`,
			},
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "test package global function value is forbidden",
			source: `package fixture
import "testing"
var callback = safe
func safe() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "ordinary indexed data remains allowed",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) { values := []string{"safe"}; _ = values[0] }
`,
		},
		{
			name: "ordinary struct field read remains allowed",
			source: `package fixture
import "testing"
type payload struct { Name string }
func TestL11PreparedLinuxFinalClosure(*testing.T) { value := payload{Name: "safe"}; _ = value.Name }
`,
		},
		{
			name: "function typed struct field is forbidden",
			source: `package fixture
import "testing"
type payload struct { Callback func() }
func safe() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { value := payload{Callback: safe}; _ = value.Callback }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "function identifier in composite element is forbidden",
			source: `package fixture
import "testing"
func helper() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = []any{helper} }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "function identifier in package composite is forbidden",
			source: `package fixture
import "testing"
func helper() {}
var escaped = []any{helper}
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = escaped }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "function identifier in return is forbidden",
			source: `package fixture
import "testing"
func helper() {}
func escape() any { return helper }
func TestL11PreparedLinuxFinalClosure(*testing.T) { _ = escape() }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "function identifier in send is forbidden",
			source: `package fixture
import "testing"
func helper() {}
func escape(ch chan any) { ch <- helper }
func TestL11PreparedLinuxFinalClosure(*testing.T) { escape(make(chan any, 1)) }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "deferred direct helper is forbidden",
			source: `package fixture
import "testing"
func helper() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { defer helper() }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "goroutine direct helper is forbidden",
			source: `package fixture
import "testing"
func helper() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { go helper() }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "parenthesized direct helper remains allowed",
			source: `package fixture
import "testing"
func helper() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) { (helper)() }
`,
		},
		{
			name: "parenthesized direct helper is traversed",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func helper() { _, _ = sandboxruntime.NewJobCredentialCleanupProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { (((helper)))() }
var input any
`,
			wantIssue: "synthetic credential proof constructor", wantIssues: 1,
		},
		{
			name: "unreachable production package dynamics remain outside selected graph",
			sources: map[string]string{
				"cmd/fixture_test.go": `package cmd
import "testing"
func TestL11PreparedLinuxFinalClosure(*testing.T) {}
`,
				"internal/unused/unused.go": `package unused
func Invoke(callback func()) { callback() }
`,
			},
		},
		{
			name: "interface dispatch after nested branch assignment is forbidden",
			source: `package fixture
import "testing"
type runner interface { Run() }
type safeRunner struct{}
func (safeRunner) Run() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	var selected runner
	if condition { selected = safeRunner{} } else { selected = safeRunner{} }
	selected.Run()
}
var condition bool
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "interface dispatch after loop assignment is forbidden",
			source: `package fixture
import "testing"
type runner interface { Run() }
type safeRunner struct{}
func (safeRunner) Run() {}
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	var selected runner
	for index := 0; index < 1; index++ { selected = safeRunner{} }
	selected.Run()
}
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "interface implementation from named return is forbidden",
			source: `package fixture
import "testing"
type runner interface { Run() }
type safeRunner struct{}
func (safeRunner) Run() {}
func choose() (selected runner) { selected = safeRunner{}; return }
func TestL11PreparedLinuxFinalClosure(*testing.T) { selected := choose(); selected.Run() }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "defined interface embedding testing TB skip",
			source: `package fixture
import "testing"
type testTB interface { testing.TB }
func skipMissing(t testTB) { t.Skip("missing") }
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skipMissing(t) }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "uninvoked nested callback shape is forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
func ignore(callback func()) { _ = func() { callback() } }
func TestL11PreparedLinuxFinalClosure(*testing.T) { ignore(mint) }
func mint() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "outer concrete reassignment captured by invoked IIFE",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type safeRunner struct{}
type minter struct{}
func (safeRunner) Run() {}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	var selected runner = safeRunner{}
	selected = minter{}
	func() { selected.Run() }()
}
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "definite interface overwrite remains forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type safeRunner struct{}
type minter struct{}
func (safeRunner) Run() {}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	var selected runner = minter{}
	selected = safeRunner{}
	selected.Run()
}
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "conditional interface overwrite remains forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type safeRunner struct{}
type minter struct{}
func (safeRunner) Run() {}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	var selected runner = minter{}
	if condition { selected = safeRunner{} }
	selected.Run()
}
var condition bool
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "captured IIFE after definite overwrite remains forbidden",
			source: `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type safeRunner struct{}
type minter struct{}
func (safeRunner) Run() {}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func TestL11PreparedLinuxFinalClosure(*testing.T) {
	var selected runner = minter{}
	selected = safeRunner{}
	func() { selected.Run() }()
}
var input any
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "concrete interface dispatch remains forbidden",
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "testing TB type alias skip",
			source: `package fixture
import "testing"
type testTB = testing.TB
func skipMissing(t testTB) { t.Skip("missing") }
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skipMissing(t) }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
		},
		{
			name: "testing T pointer method expression skip",
			source: `package fixture
import "testing"
func TestL11PreparedLinuxFinalClosure(t *testing.T) { skip := (*testing.T).Skip; skip(t, "missing") }
`,
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
			wantIssue: "forbidden dynamic selected helper graph", wantIssues: 1,
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
		if len(issues) != 1 || !strings.Contains(issues[0], "forbidden dynamic selected helper graph") {
			t.Fatalf("issues = %v, want one forbidden dynamic-graph issue", issues)
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
		issues := l11SelectedPreparedTestIssues(packages)
		if len(issues) != 1 || !strings.Contains(issues[0], "forbidden dynamic selected helper graph") {
			t.Fatalf("issues = %v, want one forbidden dynamic-graph issue", issues)
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

func TestL11FinalClosureConcreteReturnCycleTerminatesAndFailsClosed(t *testing.T) {
	const helperEnvironment = "HAL_L11_CONCRETE_RETURN_CYCLE_HELPER"
	if os.Getenv(helperEnvironment) == "1" {
		source := `package fixture
import ("testing"; "example.invalid/sandboxruntime")
type runner interface { Run() }
type minter struct{}
func (minter) Run() { _, _ = sandboxruntime.NewJobCredentialActiveProof(input) }
func first(condition bool) runner { if condition { return minter{} }; return second(condition) }
func second(condition bool) runner { return first(condition) }
func TestL11PreparedLinuxFinalClosure(*testing.T) { selected := first(true); selected.Run() }
var input any
`
		packages, err := l11ParseSelectedTestSources(map[string]string{"fixture_test.go": source})
		if err != nil {
			t.Fatal(err)
		}
		issues := l11SelectedPreparedTestIssues(packages)
		if len(issues) != 1 || !strings.Contains(issues[0], "forbidden dynamic selected helper graph") {
			t.Fatalf("issues = %v, want one forbidden dynamic-graph issue", issues)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestL11FinalClosureConcreteReturnCycleTerminatesAndFailsClosed$")
	command.Env = append(os.Environ(), helperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("concrete return-cycle analysis did not terminate within two seconds: %s", output)
	}
	if err != nil {
		t.Fatalf("concrete return-cycle analysis failed: %v: %s", err, output)
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
						pkg.values = append(pkg.values, &l11SelectedPackageValue{file: file, names: value.Names, values: value.Values})
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
			if function.Recv != nil {
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

func l11SelectedPackageExpressionContext(pkg *l11SelectedPackage, file *l11SelectedFile) *l11SelectedFunction {
	return &l11SelectedFunction{
		file: file,
		pkg:  pkg,
	}
}

func (function *l11SelectedFunction) node() ast.Node {
	if function == nil {
		return nil
	}
	return function.declaration
}

func (function *l11SelectedFunction) body() *ast.BlockStmt {
	if function == nil || function.declaration == nil {
		return nil
	}
	return function.declaration.Body
}

func l11SelectedValueInitializer(object *ast.Object, declaration *ast.ValueSpec) ast.Expr {
	for index, name := range declaration.Names {
		if name.Obj == object && index < len(declaration.Values) {
			return declaration.Values[index]
		}
	}
	return nil
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
	l11PrepareSelectedStringFacts(packages)
	var issues []string
	queue := []*l11SelectedFunction{root}
	reachable := make(map[ast.Node]bool)
	packagesChecked := make(map[*l11SelectedPackage]bool)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nil || reachable[current.node()] {
			continue
		}
		reachable[current.node()] = true
		issues = append(issues, l11SelectedClosedPackageIssues(packages, root, current.pkg, packagesChecked, &queue)...)
		issues = append(issues, l11SelectedClosedFunctionIssues(packages, root, current, &queue)...)
	}
	return l11UniqueStrings(issues)
}

var l11SelectedAllowedDirectProductionFunctions = map[string]bool{}

var l11SelectedAllowedDirectProductionMethods = map[string]bool{}

var l11SelectedAllowedTestingTMethods = map[string]bool{
	"Error": true, "Errorf": true, "Fail": true, "FailNow": true,
	"Failed": true, "Fatal": true, "Fatalf": true, "Helper": true,
	"Log": true, "Logf": true, "Name": true, "TempDir": true,
}

func l11SelectedClosedPackageIssues(packages map[string]*l11SelectedPackage, root *l11SelectedFunction, pkg *l11SelectedPackage, checked map[*l11SelectedPackage]bool, queue *[]*l11SelectedFunction) []string {
	if pkg == nil || checked[pkg] {
		return nil
	}
	checked[pkg] = true
	var issues []string
	for _, file := range pkg.files {
		if !l11SelectedClosedFileOwned(root, pkg, file) {
			continue
		}
		for _, imported := range file.imports {
			if imported.name == "_" {
				issues = append(issues, l11SelectedClosedIssue(root, "blank import"))
				continue
			}
			if l11ForbiddenCloudImport(imported.path) {
				issues = append(issues, l11SelectedClosedIssue(root, "cloud/provider marker"))
			}
		}
	}
	for _, declaration := range pkg.values {
		if !l11SelectedClosedFileOwned(root, pkg, declaration.file) {
			continue
		}
		current := l11SelectedPackageExpressionContext(pkg, declaration.file)
		for _, expression := range declaration.values {
			directCallExpressions := make(map[ast.Expr]bool)
			ast.Inspect(expression, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.FuncLit, *ast.FuncType:
					issues = append(issues, l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph"))
					return false
				case *ast.CallExpr:
					l11SelectedMarkDirectCallExpressions(directCallExpressions, value.Fun)
					if l11SelectedClosedProofCall(current.file, l11SelectedUnwrapCallFunction(value.Fun)) {
						issues = append(issues, l11SelectedClosedIssue(root, "synthetic credential proof constructor"))
					}
				case ast.Expr:
					if !directCallExpressions[value] && l11SelectedCallableValueExpression(packages, current, value, make(map[*ast.Object]bool)) {
						issues = append(issues, l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph"))
					}
					if l11SelectedClosedCloudExpression(packages, current, value) {
						issues = append(issues, l11SelectedClosedIssue(root, "cloud/provider marker"))
					}
				}
				return true
			})
		}
	}
	for _, initializer := range pkg.functions["init"] {
		if pkg != root.pkg || l11SelectedTestOwnedFunction(initializer) || l11SelectedToolHelperFunction(initializer) {
			*queue = append(*queue, initializer)
		}
	}
	return l11UniqueStrings(issues)
}

func l11SelectedClosedFileOwned(root *l11SelectedFunction, pkg *l11SelectedPackage, file *l11SelectedFile) bool {
	if root == nil || pkg != root.pkg {
		return true
	}
	return file != nil && (strings.HasSuffix(file.path, "_test.go") || l11SelectedToolHelperPath(file.path))
}

func l11SelectedClosedFunctionIssues(packages map[string]*l11SelectedPackage, root, current *l11SelectedFunction, queue *[]*l11SelectedFunction) []string {
	var issues []string
	if l11SelectedFunctionHasCallableSignature(current) {
		issues = append(issues, l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph"))
	}
	directCallExpressions := make(map[ast.Expr]bool)
	subtestCallbacks := make(map[ast.Expr]bool)
	ast.Inspect(current.body(), func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.DeferStmt, *ast.GoStmt:
			issues = append(issues, l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph"))
			return false
		case *ast.FuncLit:
			issues = append(issues, l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph"))
			return false
		case *ast.FuncType:
			issues = append(issues, l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph"))
			return false
		case *ast.CallExpr:
			l11SelectedMarkDirectCallExpressions(directCallExpressions, value.Fun)
			if _, ok := l11SelectedExactSubtestCallback(current, value); ok {
				subtestCallbacks[value.Args[1]] = true
			}
			issues = append(issues, l11SelectedClosedCallIssues(packages, root, current, value, queue)...)
		case ast.Expr:
			if !directCallExpressions[value] && !subtestCallbacks[value] && l11SelectedCallableValueExpression(packages, current, value, make(map[*ast.Object]bool)) {
				issues = append(issues, l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph"))
			}
			if l11SelectedClosedCloudExpression(packages, current, value) {
				issues = append(issues, l11SelectedClosedIssue(root, "cloud/provider marker"))
			}
		}
		return true
	})
	return l11UniqueStrings(issues)
}

func l11SelectedMarkDirectCallExpressions(marked map[ast.Expr]bool, expression ast.Expr) {
	marked[expression] = true
	if parenthesized, ok := expression.(*ast.ParenExpr); ok {
		l11SelectedMarkDirectCallExpressions(marked, parenthesized.X)
	}
}

func l11SelectedClosedCallIssues(packages map[string]*l11SelectedPackage, root, current *l11SelectedFunction, call *ast.CallExpr, queue *[]*l11SelectedFunction) []string {
	switch function := l11SelectedUnwrapCallFunction(call.Fun).(type) {
	case *ast.IndexExpr, *ast.IndexListExpr, *ast.CallExpr, *ast.FuncLit:
		return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
	case *ast.Ident:
		if l11SelectedProofConstructor(function.Name) && l11SelectedDotImportedProof(current.file, function) {
			return []string{l11SelectedClosedIssue(root, "synthetic credential proof constructor")}
		}
		if function.Obj != nil {
			switch declaration := function.Obj.Decl.(type) {
			case *ast.FuncDecl:
				targets := l11SelectedDeclaredFunction(current.pkg, declaration)
				return l11SelectedClosedDirectTargets(root, current, targets, current.pkg.name+"."+function.Name, queue)
			case *ast.TypeSpec:
				return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
			default:
				return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
			}
		}
		if function.Name == "any" || function.Name == "error" || function.Name == "comparable" {
			return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
		}
		if l11SelectedAllowedBuiltin(function.Name) {
			return nil
		}
		var targets []*l11SelectedFunction
		key := ""
		for _, imported := range current.file.imports {
			if imported.name != "." {
				continue
			}
			if importedPackage := l11SelectedImportedPackage(packages, imported.path); importedPackage != nil {
				matches := importedPackage.functions[function.Name]
				if len(matches) > 0 {
					targets = append(targets, matches...)
					key = imported.path + "." + function.Name
				}
			}
		}
		if len(targets) == 1 {
			return l11SelectedClosedDirectTargets(root, current, l11SelectedFunctions(targets), key, queue)
		}
		return []string{l11SelectedClosedIssue(root, "unresolved in-module call")}
	case *ast.SelectorExpr:
		if l11SelectedProofSelector(current.file, function) {
			return []string{l11SelectedClosedIssue(root, "synthetic credential proof constructor")}
		}
		if l11SelectedCloudSelector(current.file, function) {
			return []string{l11SelectedClosedIssue(root, "cloud/provider marker")}
		}
		if identifier, ok := function.X.(*ast.Ident); ok && identifier.Obj == nil {
			if importPath := current.file.importPaths[identifier.Name]; importPath != "" {
				if importedPackage := l11SelectedImportedPackage(packages, importPath); importedPackage != nil {
					if len(importedPackage.typeDefs[function.Sel.Name]) > 0 {
						return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
					}
					targets := importedPackage.functions[function.Sel.Name]
					if len(targets) == 1 {
						return l11SelectedClosedDirectTargets(root, current, l11SelectedFunctions(targets), importPath+"."+function.Sel.Name, queue)
					}
				}
				if l11SelectedAllowedDirectProductionFunctions[importPath+"."+function.Sel.Name] {
					return nil
				}
				return []string{l11SelectedClosedIssue(root, "unresolved in-module call")}
			}
		}
		receiver := l11SelectedExpressionType(current.file, function.X)
		if l11SelectedExpressionHasExactTestingTType(current.file, function.X, l11SelectedNewTestingTResolution(), 0) {
			if function.Sel.Name == "Run" {
				callback, ok := l11SelectedExactSubtestCallback(current, call)
				if !ok {
					return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
				}
				*queue = append(*queue, callback)
				return nil
			}
			switch function.Sel.Name {
			case "Skip", "Skipf", "SkipNow":
				return []string{l11SelectedClosedIssue(root, "skip call")}
			}
			if l11SelectedAllowedTestingTMethods[function.Sel.Name] {
				return nil
			}
		}
		if l11SelectedAllowedDirectProductionMethods[receiver+"."+function.Sel.Name] {
			return nil
		}
		return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
	default:
		return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
	}
}

func l11SelectedUnwrapCallFunction(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

func l11SelectedExactSubtestCallback(current *l11SelectedFunction, call *ast.CallExpr) (*l11SelectedFunction, bool) {
	if current == nil || current.file == nil || len(call.Args) != 2 {
		return nil, false
	}
	selector, ok := l11SelectedUnwrapCallFunction(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Run" || !l11SelectedExpressionHasExactTestingTType(current.file, selector.X, l11SelectedNewTestingTResolution(), 0) {
		return nil, false
	}
	scenario, ok := call.Args[0].(*ast.BasicLit)
	if !ok || scenario.Kind != token.STRING {
		return nil, false
	}
	name, err := strconv.Unquote(scenario.Value)
	if err != nil || !l11SelectedFinalScenario(name) {
		return nil, false
	}
	callbackName, ok := call.Args[1].(*ast.Ident)
	if !ok || callbackName.Obj == nil {
		return nil, false
	}
	declaration, ok := callbackName.Obj.Decl.(*ast.FuncDecl)
	if !ok {
		return nil, false
	}
	targets := l11SelectedDeclaredFunction(current.pkg, declaration)
	if len(targets) != 1 || targets[0].function == nil || !l11SelectedTestOwnedFunction(targets[0].function) || !l11SelectedTestingTCallback(targets[0].function) {
		return nil, false
	}
	return targets[0].function, true
}

func l11SelectedFinalScenario(name string) bool {
	for _, row := range l11ExpectedFinalClosureMatrix() {
		if row.id == name {
			return true
		}
	}
	return false
}

func l11SelectedTestingTCallback(function *l11SelectedFunction) bool {
	if function == nil || function.declaration == nil || function.declaration.Type.TypeParams != nil || function.declaration.Type.Results != nil {
		return false
	}
	parameters := function.declaration.Type.Params
	if parameters == nil || len(parameters.List) != 1 || len(parameters.List[0].Names) > 1 {
		return false
	}
	pointers, exact := l11SelectedTestingTPointerDepth(function.file, parameters.List[0].Type, l11SelectedNewTestingTResolution(), 0)
	return exact && pointers == 1
}

type l11SelectedTestingTAliasKey struct {
	pkg  *l11SelectedPackage
	name string
}

type l11SelectedTestingTResolution struct {
	objects map[*ast.Object]bool
	aliases map[l11SelectedTestingTAliasKey]bool
}

func l11SelectedNewTestingTResolution() *l11SelectedTestingTResolution {
	return &l11SelectedTestingTResolution{
		objects: make(map[*ast.Object]bool),
		aliases: make(map[l11SelectedTestingTAliasKey]bool),
	}
}

func l11SelectedExpressionHasExactTestingTType(file *l11SelectedFile, expression ast.Expr, resolution *l11SelectedTestingTResolution, depth int) bool {
	if expression == nil || depth > 32 {
		return false
	}
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return l11SelectedExpressionHasExactTestingTType(file, value.X, resolution, depth+1)
	case *ast.StarExpr:
		return l11SelectedExpressionHasExactTestingTType(file, value.X, resolution, depth+1)
	case *ast.UnaryExpr:
		return l11SelectedExpressionHasExactTestingTType(file, value.X, resolution, depth+1)
	case *ast.Ident:
		if value.Obj == nil || resolution.objects[value.Obj] {
			return false
		}
		resolution.objects[value.Obj] = true
		defer delete(resolution.objects, value.Obj)
		switch declaration := value.Obj.Decl.(type) {
		case *ast.Field:
			return l11SelectedHasExactTestingTType(file, declaration.Type, resolution, depth+1)
		case *ast.ValueSpec:
			if declaration.Type != nil {
				return l11SelectedHasExactTestingTType(file, declaration.Type, resolution, depth+1)
			}
			for index, name := range declaration.Names {
				if name.Obj == value.Obj && index < len(declaration.Values) {
					return l11SelectedExpressionHasExactTestingTType(file, declaration.Values[index], resolution, depth+1)
				}
			}
		case *ast.AssignStmt:
			for index, name := range declaration.Lhs {
				identifier, ok := name.(*ast.Ident)
				if ok && identifier.Obj == value.Obj && index < len(declaration.Rhs) {
					return l11SelectedExpressionHasExactTestingTType(file, declaration.Rhs[index], resolution, depth+1)
				}
			}
		}
	}
	return false
}

func l11SelectedHasExactTestingTType(file *l11SelectedFile, expression ast.Expr, resolution *l11SelectedTestingTResolution, depth int) bool {
	_, exact := l11SelectedTestingTPointerDepth(file, expression, resolution, depth)
	return exact
}

func l11SelectedTestingTPointerDepth(file *l11SelectedFile, expression ast.Expr, resolution *l11SelectedTestingTResolution, depth int) (int, bool) {
	if file == nil || expression == nil || depth > 32 {
		return 0, false
	}
	switch value := expression.(type) {
	case *ast.StarExpr:
		pointers, exact := l11SelectedTestingTPointerDepth(file, value.X, resolution, depth+1)
		return pointers + 1, exact
	case *ast.ParenExpr:
		return l11SelectedTestingTPointerDepth(file, value.X, resolution, depth+1)
	case *ast.Ident:
		if value.Obj != nil {
			if resolution.objects[value.Obj] {
				return 0, false
			}
			typeSpec, ok := value.Obj.Decl.(*ast.TypeSpec)
			if !ok || !typeSpec.Assign.IsValid() {
				return 0, false
			}
			resolution.objects[value.Obj] = true
			defer delete(resolution.objects, value.Obj)
			return l11SelectedTestingTPointerDepth(file, typeSpec.Type, resolution, depth+1)
		}
		if file.pkg != nil && len(file.pkg.typeDefs[value.Name]) > 0 {
			alias, ok := file.pkg.types[value.Name]
			if !ok || len(file.pkg.typeDefs[value.Name]) != 1 {
				return 0, false
			}
			key := l11SelectedTestingTAliasKey{pkg: file.pkg, name: value.Name}
			if resolution.aliases[key] {
				return 0, false
			}
			resolution.aliases[key] = true
			defer delete(resolution.aliases, key)
			return l11SelectedTestingTPointerDepth(alias.file, alias.expression, resolution, depth+1)
		}
		if value.Name != "T" {
			return 0, false
		}
		for _, imported := range file.imports {
			if imported.name == "." && imported.path == "testing" {
				return 0, true
			}
		}
	case *ast.SelectorExpr:
		identifier, ok := value.X.(*ast.Ident)
		return 0, ok && identifier.Obj == nil && value.Sel.Name == "T" && file.importPaths[identifier.Name] == "testing"
	}
	return 0, false
}

func l11SelectedClosedDirectTargets(root, current *l11SelectedFunction, targets []l11SelectedCallable, key string, queue *[]*l11SelectedFunction) []string {
	if len(targets) != 1 || targets[0].function == nil {
		if l11SelectedAllowedDirectProductionFunctions[key] {
			return nil
		}
		return []string{l11SelectedClosedIssue(root, "unresolved in-module call")}
	}
	target := targets[0].function
	if target.declaration != nil && target.declaration.Type.TypeParams != nil && len(target.declaration.Type.TypeParams.List) > 0 {
		return []string{l11SelectedClosedIssue(root, "forbidden dynamic selected helper graph")}
	}
	if l11SelectedTestOwnedFunction(target) || l11SelectedToolHelperFunction(target) || (target.pkg != current.pkg && !strings.HasPrefix(key, "github.com/jywlabs/hal/")) {
		*queue = append(*queue, target)
		return nil
	}
	if l11SelectedAllowedDirectProductionFunctions[key] {
		return nil
	}
	return []string{l11SelectedClosedIssue(root, "unresolved in-module call")}
}

func l11SelectedTestOwnedFunction(function *l11SelectedFunction) bool {
	return function != nil && function.file != nil && strings.HasSuffix(function.file.path, "_test.go")
}

func l11SelectedToolHelperFunction(function *l11SelectedFunction) bool {
	if function == nil || function.file == nil {
		return false
	}
	return l11SelectedToolHelperPath(function.file.path)
}

func l11SelectedToolHelperPath(filePath string) bool {
	path := filepath.ToSlash(filePath)
	return strings.Contains(path, "/tools/l11") || strings.HasPrefix(path, "tools/l11")
}

func l11SelectedFunctionHasCallableSignature(function *l11SelectedFunction) bool {
	if function == nil || function.declaration == nil {
		return false
	}
	found := false
	for _, fields := range []*ast.FieldList{function.declaration.Type.Params, function.declaration.Type.Results} {
		if fields == nil {
			continue
		}
		for _, field := range fields.List {
			ast.Inspect(field.Type, func(node ast.Node) bool {
				if _, ok := node.(*ast.FuncType); ok {
					found = true
					return false
				}
				return true
			})
		}
	}
	return found
}

func l11SelectedCallableValueExpression(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr, visiting map[*ast.Object]bool) bool {
	if expression == nil || current == nil || current.file == nil {
		return false
	}
	switch value := expression.(type) {
	case *ast.FuncLit:
		return true
	case *ast.ParenExpr:
		return l11SelectedCallableValueExpression(packages, current, value.X, visiting)
	case *ast.IndexExpr:
		return l11SelectedCallableValueExpression(packages, current, value.X, visiting)
	case *ast.IndexListExpr:
		return l11SelectedCallableValueExpression(packages, current, value.X, visiting)
	case *ast.Ident:
		if value.Obj == nil || visiting[value.Obj] {
			return false
		}
		switch declaration := value.Obj.Decl.(type) {
		case *ast.FuncDecl:
			return true
		case *ast.Field:
			found := false
			ast.Inspect(declaration.Type, func(node ast.Node) bool {
				if _, ok := node.(*ast.FuncType); ok {
					found = true
					return false
				}
				return true
			})
			return found
		case *ast.ValueSpec:
			visiting[value.Obj] = true
			defer delete(visiting, value.Obj)
			return l11SelectedCallableValueExpression(packages, current, l11SelectedValueInitializer(value.Obj, declaration), visiting)
		case *ast.AssignStmt:
			visiting[value.Obj] = true
			defer delete(visiting, value.Obj)
			for index, target := range declaration.Lhs {
				identifier, ok := target.(*ast.Ident)
				if ok && identifier.Obj == value.Obj && index < len(declaration.Rhs) {
					return l11SelectedCallableValueExpression(packages, current, declaration.Rhs[index], visiting)
				}
			}
		}
		return false
	case *ast.SelectorExpr:
		if identifier, ok := value.X.(*ast.Ident); ok && identifier.Obj == nil {
			if importPath := current.file.importPaths[identifier.Name]; importPath != "" {
				importedPackage := l11SelectedImportedPackage(packages, importPath)
				return importedPackage != nil && len(importedPackage.functions[value.Sel.Name]) > 0
			}
		}
		if found, callable := l11SelectedStructFieldKind(packages, current, value.X, value.Sel.Name); found {
			return callable
		}
		return l11SelectedExpressionType(current.file, value.X) != ""
	default:
		return false
	}
}

func l11SelectedStructFieldKind(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, receiver ast.Expr, fieldName string) (bool, bool) {
	if current == nil || current.pkg == nil || current.file == nil {
		return false, false
	}
	typeName := l11SelectedExpressionType(current.file, receiver)
	pkg := current.pkg
	if separator := strings.LastIndex(typeName, "."); separator >= 0 {
		pkg = l11SelectedImportedPackage(packages, typeName[:separator])
		typeName = typeName[separator+1:]
	}
	return l11SelectedNamedFieldKind(pkg, typeName, fieldName, make(map[string]bool))
}

func l11SelectedNamedFieldKind(pkg *l11SelectedPackage, typeName, fieldName string, visiting map[string]bool) (bool, bool) {
	if pkg == nil || typeName == "" || visiting[typeName] {
		return false, false
	}
	visiting[typeName] = true
	defer delete(visiting, typeName)
	for _, definition := range pkg.typeDefs[typeName] {
		switch expression := definition.expression.(type) {
		case *ast.StructType:
			for _, field := range expression.Fields.List {
				for _, name := range field.Names {
					if name.Name == fieldName {
						return true, l11SelectedCallableType(field.Type, make(map[*ast.Object]bool))
					}
				}
			}
		case *ast.InterfaceType:
			for _, field := range expression.Methods.List {
				for _, name := range field.Names {
					if name.Name == fieldName {
						return true, true
					}
				}
			}
		case *ast.Ident:
			if found, callable := l11SelectedNamedFieldKind(pkg, expression.Name, fieldName, visiting); found {
				return true, callable
			}
		}
	}
	return false, false
}

func l11SelectedCallableType(expression ast.Expr, visiting map[*ast.Object]bool) bool {
	if expression == nil {
		return false
	}
	switch value := expression.(type) {
	case *ast.FuncType:
		return true
	case *ast.ParenExpr:
		return l11SelectedCallableType(value.X, visiting)
	case *ast.Ident:
		if value.Obj == nil || visiting[value.Obj] {
			return false
		}
		typeSpec, ok := value.Obj.Decl.(*ast.TypeSpec)
		if !ok {
			return false
		}
		visiting[value.Obj] = true
		defer delete(visiting, value.Obj)
		return l11SelectedCallableType(typeSpec.Type, visiting)
	default:
		return false
	}
}

func l11SelectedAllowedBuiltin(name string) bool {
	switch name {
	case "append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover":
		return true
	case "bool", "byte", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr":
		return true
	default:
		return false
	}
}

func l11SelectedClosedProofCall(file *l11SelectedFile, expression ast.Expr) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return l11SelectedDotImportedProof(file, value)
	case *ast.SelectorExpr:
		return l11SelectedProofSelector(file, value)
	default:
		return false
	}
}

func l11SelectedClosedCloudExpression(packages map[string]*l11SelectedPackage, current *l11SelectedFunction, expression ast.Expr) bool {
	fact := l11ResolveSelectedStringFact(packages, current, expression, make(map[*ast.Object]bool), 0)
	for literal := range fact.values {
		if l11ForbiddenCloudLiteral(literal) {
			return true
		}
	}
	return false
}

func l11SelectedClosedIssue(root *l11SelectedFunction, detail string) string {
	name := "selected test"
	if root != nil && root.declaration != nil {
		name = root.declaration.Name.Name
	}
	switch detail {
	case "skip call":
		return fmt.Sprintf("%s reaches a skip call", name)
	case "cloud/provider marker":
		return fmt.Sprintf("%s reaches a cloud/provider marker", name)
	case "unresolved in-module call":
		return fmt.Sprintf("%s reaches an unresolved in-module call", name)
	case "blank import":
		return fmt.Sprintf("%s reaches a forbidden blank import", name)
	case "synthetic credential proof constructor":
		return fmt.Sprintf("%s reaches synthetic credential proof constructor", name)
	default:
		return fmt.Sprintf("%s reaches a forbidden dynamic selected helper graph", name)
	}
}

func l11PrepareSelectedStringFacts(packages map[string]*l11SelectedPackage) {
	for _, pkg := range packages {
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
				current := l11SelectedPackageExpressionContext(pkg, declaration.file)
				for index, name := range declaration.names {
					fact := l11ResolveSelectedStringFact(packages, current, declaration.values[index], make(map[*ast.Object]bool), 0)
					if l11MergeSelectedStringFactInto(pkg.strings, name.Name, fact) {
						changed = true
					}
				}
			}
		}
	}
}

func l11InModuleImport(importPath string) bool {
	return strings.HasPrefix(importPath, "github.com/jywlabs/hal/")
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
					return importPath + "." + value.Sel.Name
				}
			}
			return identifier.Name + "." + value.Sel.Name
		}
	}
	return ""
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
