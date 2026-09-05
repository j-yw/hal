package credentialsource

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestL8CredentialSourceImportAndIngressBoundaries(t *testing.T) {
	productionFiles, err := l8CredentialSourceProductionFiles(".")
	if err != nil {
		t.Fatal(err)
	}
	foundCredentialMemory := false
	foundDirectKeyctl := false
	productionSource := strings.Builder{}
	typedProductionAnalysis, err := l8CredentialSourceAnalyzeTypedProduction(productionFiles)
	if err != nil {
		t.Fatalf("type-check production credential source: %v", err)
	}
	for _, issue := range typedProductionAnalysis.issues {
		t.Errorf("production credential source %s", issue)
	}
	denialMethods := map[string]map[string]bool{
		"Registry":                   {},
		"RegistryConfig":             {},
		"SourceRegistration":         {},
		"AdmissionGrantRegistration": {},
		"KeyIdentity":                {},
		"KeyDescriptor":              {},
		"registryAuthorization":      {},
		"keyringLiveSecretSource":    {},
	}
	formatLiterals := l8CredentialSourceFormatLiterals()
	for _, productionPath := range productionFiles {
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, productionPath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", productionPath, err)
		}
		rootPackage := filepath.Clean(filepath.Dir(productionPath)) == "." && file.Name.Name == "credentialsource"
		fmtAliases, fmtDotImport := l8CredentialSourceImportAliases(file, "fmt")
		if fmtDotImport {
			t.Errorf("production credential source %s uses forbidden dot import of fmt", productionPath)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", productionPath, err)
			}
			forbidden := importPath == "os" || importPath == "os/exec" || importPath == "io/ioutil" || importPath == "io/fs" || importPath == "path/filepath" ||
				importPath == "bytes" || importPath == "bufio" ||
				importPath == "net" || strings.HasPrefix(importPath, "net/") || importPath == "syscall" || importPath == "unsafe" ||
				importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "log" || importPath == "log/slog" ||
				strings.Contains(importPath, "/cmd") || strings.Contains(importPath, "/internal/sandboxworker") ||
				(strings.Contains(importPath, "/internal/sandboxruntime/") && importPath != "github.com/jywlabs/hal/internal/sandboxruntime") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
				strings.Contains(importPath, "credentialdelivery") || strings.Contains(importPath, "provider") ||
				strings.Contains(importPath, "process") || strings.Contains(importPath, "workspace") || strings.Contains(importPath, "sandboxexecution")
			if forbidden {
				t.Errorf("production credential source %s imports forbidden ingress %q", productionPath, importPath)
			}
			if importPath == "github.com/jywlabs/hal/internal/credentialmemory" {
				foundCredentialMemory = true
			}
			if importPath == "golang.org/x/sys/unix" {
				foundDirectKeyctl = true
			}
		}
		for _, issue := range l8CredentialSourceForbiddenSelectorIssues(file) {
			t.Errorf("production credential source %s %s", productionPath, issue)
		}
		for _, issue := range l8CredentialSourceFmtFileIssues(file, fmtAliases, rootPackage, formatLiterals) {
			t.Errorf("production credential source %s %s", productionPath, issue)
		}
		source, err := os.ReadFile(filepath.Clean(productionPath))
		if err != nil {
			t.Fatal(err)
		}
		productionSource.Write(source)
		productionSource.WriteByte('\n')
		for _, marker := range []string{
			"os.Getenv(", "os.LookupEnv(", "os.ReadFile(", "exec.Command(", "exec.CommandContext(",
			"io.ReadAll(", "bytes.Buffer", "strings.Builder", "ResolvedRunSecret", "SecretBroker", "Value string", "json.Marshal(", "errors.Join(",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production credential source %s contains forbidden ingress/marshal marker %q", productionPath, marker)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.TypeSpec:
				structure, ok := typed.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range structure.Fields.List {
					if len(field.Names) > 0 && field.Names[0].IsExported() {
						t.Errorf("production credential source %s type %s exposes live/config field %s", productionPath, typed.Name.Name, field.Names[0].Name)
					}
				}
			case *ast.FuncDecl:
				receiver := ""
				if typed.Recv != nil {
					receiver = l8CredentialSourceReceiverName(typed.Recv.List[0].Type)
				}
				if typed.Recv == nil {
					return true
				}
				switch typed.Name.Name {
				case "Unwrap", "MarshalBinary", "GobEncode", "Bytes", "Value":
					t.Errorf("production credential source %s defines forbidden live/raw method %s on %s", productionPath, typed.Name.Name, receiver)
				case "String", "GoString", "MarshalJSON", "MarshalText", "Format":
					allowed, ok := denialMethods[receiver]
					if !ok || !rootPackage {
						t.Errorf("production credential source %s defines formatting/codec method %s on unexpected receiver %s", productionPath, typed.Name.Name, receiver)
						return true
					}
					allowed[typed.Name.Name] = true
				}
			}
			return true
		})
	}
	if len(productionFiles) == 0 {
		t.Fatal("L8 credential source production package does not exist")
	}
	if !foundCredentialMemory {
		t.Fatal("L8 credential source does not use the owned credentialmemory boundary")
	}
	if !foundDirectKeyctl {
		t.Fatal("L8 credential source does not use direct Linux keyctl syscalls")
	}
	for receiver, found := range denialMethods {
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText", "Format"} {
			if !found[required] {
				t.Errorf("production credential source %s omits safe/denial method %s", receiver, required)
			}
		}
	}
	for _, required := range []string{"unix.KeyctlBuffer(", "unix.KEYCTL_DESCRIBE", "unix.KEYCTL_READ"} {
		if !strings.Contains(productionSource.String(), required) {
			t.Errorf("L8 credential source omits direct keyctl read marker %q", required)
		}
	}
}

func TestL8CredentialSourceRecursiveProductionDiscoveryAndAliasGuards(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{
		"root.go":                    "package credentialsource\ntype rootMarker struct{}\n",
		"nested/live.go":             "package nested\nimport u \"golang.org/x/sys/unix\"\nvar _ = u.Socket\n",
		"nested/deeper/live.go":      "package deeper\ntype marker struct{}\n",
		"nested/deeper/live_test.go": "package deeper\nimport u \"golang.org/x/sys/unix\"\nvar _ = u.Socket\n",
	}
	for relativePath, source := range fixtures {
		fullPath := filepath.Join(root, filepath.FromSlash(relativePath))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	productionFiles, err := l8CredentialSourceProductionFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	var relative []string
	for _, productionPath := range productionFiles {
		value, err := filepath.Rel(root, productionPath)
		if err != nil {
			t.Fatal(err)
		}
		relative = append(relative, filepath.ToSlash(value))
	}
	want := []string{"nested/deeper/live.go", "nested/live.go", "root.go"}
	if !reflect.DeepEqual(relative, want) {
		t.Fatalf("recursive production files = %v, want %v", relative, want)
	}
	nested, err := parser.ParseFile(token.NewFileSet(), productionFiles[1], nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if issues := l8CredentialSourceForbiddenSelectorIssues(nested); len(issues) != 1 {
		t.Fatalf("nested production selector issues = %v, want one unix denial", issues)
	}

	for _, tt := range []struct {
		name       string
		source     string
		wantIssues int
	}{
		{name: "unix alias denied", source: "package fixture\nimport privateunix \"golang.org/x/sys/unix\"\nvar _ = privateunix.Socket\n", wantIssues: 1},
		{name: "unix dot denied", source: "package fixture\nimport . \"golang.org/x/sys/unix\"\nvar _ = Socket\n", wantIssues: 1},
		{name: "allowed unix alias", source: "package fixture\nimport privateunix \"golang.org/x/sys/unix\"\nvar _ = privateunix.KeyctlBuffer\n"},
		{name: "errors alias denied", source: "package fixture\nimport privateerrors \"errors\"\nvar _ = privateerrors.Join\n", wantIssues: 1},
		{name: "errors dot denied", source: "package fixture\nimport . \"errors\"\nvar _ = Join\n", wantIssues: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if issues := l8CredentialSourceForbiddenSelectorIssues(file); len(issues) != tt.wantIssues {
				t.Fatalf("issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func TestL8CredentialSourceAllLiveHoldersRejectRawAliasAndNestedState(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		wantIssues int
	}{
		{name: "registry raw alias", source: `package fixture
type credentialBytes []byte
type Registry struct{ retained credentialBytes }
`, wantIssues: 1},
		{name: "differently named nested holder", source: `package fixture
type rawAlias string
type nestedState struct{ raw rawAlias }
type Vault struct{ state nestedState }
`, wantIssues: 2},
		{name: "differently named byte holder", source: `package fixture
type Cache struct{ payload []byte }
`, wantIssues: 1},
		{name: "nested package cannot spoof safe metadata name", source: `package fixture
type RegistryConfig struct{ payload []byte }
`, wantIssues: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			analysis := l8CredentialSourceFixtureAnalysis(t, map[string]string{"fixture.go": tt.source})
			if len(analysis.issues) != tt.wantIssues {
				t.Fatalf("typed holder issues = %v, want %d", analysis.issues, tt.wantIssues)
			}
		})
	}
}

func TestL8CredentialSourceSafeMetadataSchemasAreExactAndOrderIndependent(t *testing.T) {
	exact := l8CredentialSourceSafeMetadataFixture()
	validated, issues := l8CredentialSourceFixtureSafeMetadata(t, exact)
	if len(issues) != 0 || len(validated) != len(l8CredentialSourceSafeMetadataSchemas()) {
		t.Fatalf("exact semantic safe metadata = %v, issues = %v", validated, issues)
	}

	aliasSpelling := strings.Replace(exact, "import sandboxruntime ", "import runtimecontract ", 1)
	aliasSpelling = strings.ReplaceAll(aliasSpelling, "sandboxruntime.", "runtimecontract.")
	validated, issues = l8CredentialSourceFixtureSafeMetadata(t, aliasSpelling)
	if len(issues) != 0 || len(validated) != len(l8CredentialSourceSafeMetadataSchemas()) {
		t.Fatalf("exact imported contracts under alternate alias rejected: %v, %v", validated, issues)
	}

	for _, tt := range []struct {
		name   string
		source string
	}{
		{name: "shadowed predeclared string", source: strings.Replace(exact, "type KeyPermission uint32", "type string struct{ retained []byte }\ntype KeyPermission uint32", 1)},
		{name: "aliased key permission", source: strings.Replace(exact, "type KeyPermission uint32", "type KeyPermission = uint32", 1)},
		{name: "lookalike key permission", source: strings.Replace(exact, "type KeyPermission uint32", "type KeyPermission string", 1)},
		{name: "aliased builtin field", source: strings.Replace(exact, "type KeyPermission uint32", "type safeString = string\ntype KeyPermission uint32", 1)},
		{name: "aliased local field", source: strings.Replace(exact, "type KeyPermission uint32", "type identityAlias = KeyIdentity\ntype KeyPermission uint32", 1)},
		{name: "aliased imported field", source: strings.Replace(exact, "type KeyPermission uint32", "type requestAlias = sandboxruntime.JobCredentialAdmissionRequest\ntype KeyPermission uint32", 1)},
		{name: "fake sandboxruntime package", source: strings.Replace(exact, l8CredentialSourceSandboxruntimeImportPath, "example.com/fake/sandboxruntime", 1)},
		{name: "unresolved external field", source: strings.Replace(exact, "sandboxruntime.JobCredentialAdmissionRequest", "sandboxruntime.DoesNotExist", 1)},
		{name: "mutated field", source: strings.Replace(exact, "serial int32", "serial uint32", 1)},
		{name: "extra field", source: strings.Replace(exact, "serial int32", "serial int32\n\tretained []byte", 1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := tt.source
			switch tt.name {
			case "aliased builtin field":
				source = strings.Replace(source, "keyType string", "keyType safeString", 1)
			case "aliased local field":
				source = strings.Replace(source, "identity KeyIdentity", "identity identityAlias", 1)
			case "aliased imported field":
				source = strings.Replace(source, "request sandboxruntime.JobCredentialAdmissionRequest", "request requestAlias", 1)
			}
			validated, issues := l8CredentialSourceFixtureSafeMetadata(t, source)
			if len(issues) == 0 || len(validated) != 0 {
				t.Fatalf("semantic spoof retained exemption %v with issues %v", validated, issues)
			}
		})
	}
}

func TestL8CredentialSourceRejectsPackageMutableRawStateOnly(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		wantIssues int
	}{
		{name: "package string", source: "package fixture\nvar retained string\n", wantIssues: 1},
		{name: "package inferred string", source: "package fixture\nvar retained = \"secret\"\n", wantIssues: 1},
		{name: "package inferred constant string", source: "package fixture\nconst seed = \"secret\"\nvar retained = seed\n", wantIssues: 1},
		{name: "package inferred binary string", source: "package fixture\nconst seed = \"secret\"\nvar retained = seed + \"-tail\"\n", wantIssues: 1},
		{name: "package inferred string call", source: "package fixture\nfunc build() string { return \"secret\" }\nvar retained = build()\n", wantIssues: 1},
		{name: "package explicit interface string", source: "package fixture\nvar retained any = \"secret\"\n", wantIssues: 1},
		{name: "package explicit interface string call", source: "package fixture\nfunc build() string { return \"secret\" }\nvar retained interface{} = build()\n", wantIssues: 1},
		{name: "package bytes", source: "package fixture\nvar retained []byte\n", wantIssues: 1},
		{name: "package inferred converted bytes", source: "package fixture\nconst seed = \"secret\"\nvar retained = []byte(seed)\n", wantIssues: 1},
		{name: "package inferred appended bytes", source: "package fixture\nconst seed = \"secret\"\nvar retained = append([]byte(nil), []byte(seed)...)\n", wantIssues: 1},
		{name: "package inferred copied bytes", source: `package fixture
const seed = "secret"
func clone(value []byte) []byte {
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}
var retained = clone([]byte(seed))
`, wantIssues: 1},
		{name: "package raw alias", source: "package fixture\ntype rawAlias string\nvar retained rawAlias\n", wantIssues: 1},
		{name: "package nested raw", source: "package fixture\ntype nestedRaw struct{ value string }\nvar retained nestedRaw\n", wantIssues: 2},
		{name: "package external byte buffer", source: "package fixture\nimport \"bytes\"\nvar retained bytes.Buffer\n", wantIssues: 1},
		{name: "package external string builder", source: "package fixture\nimport \"strings\"\nvar retained *strings.Builder\n", wantIssues: 1},
		{name: "unresolved module global fails closed", source: "package fixture\nimport sandboxruntime \"github.com/jywlabs/hal/internal/sandboxruntime\"\nvar retained sandboxruntime.JobCredentialState\n", wantIssues: 1},
		{name: "uninitialized error", source: "package fixture\nvar retained error\n", wantIssues: 1},
		{name: "error alias", source: "package fixture\ntype errorAlias = error\nvar retained errorAlias\n", wantIssues: 1},
		{name: "uninitialized interface", source: "package fixture\nvar retained any\n", wantIssues: 1},
		{name: "uninitialized function", source: "package fixture\nvar retained func()\n", wantIssues: 1},
		{name: "function alias", source: "package fixture\ntype callback = func(uint64) bool\nvar retained callback\n", wantIssues: 1},
		{name: "closure initializer", source: "package fixture\nvar retained = func() {}\n", wantIssues: 1},
		{name: "safe constant", source: "package fixture\nconst safeCode = \"credential_source_denied\"\n"},
		{name: "safe explicit sentinel error", source: "package fixture\nimport \"errors\"\nvar errValue error = errors.New(\"credential source unavailable\")\n"},
		{name: "safe inferred sentinel error", source: "package fixture\nimport stableerrors \"errors\"\nvar errValue = stableerrors.New(\"credential source unavailable\")\n"},
		{name: "sentinel through error alias", source: "package fixture\nimport \"errors\"\ntype errorAlias = error\nvar errValue errorAlias = errors.New(\"credential source unavailable\")\n", wantIssues: 1},
		{name: "dynamic sentinel error string", source: "package fixture\nimport \"errors\"\nfunc build() string { return \"secret\" }\nvar errValue error = errors.New(build())\n", wantIssues: 1},
		{name: "safe nonraw globals", source: `package fixture
import (
	"errors"
	"sync"
)
type counters struct{ admitted uint64; ready bool }
var count uint64
var enabled = true
var state counters
var sentinel = errors.New("credential source unavailable")
var gate sync.Mutex
var once sync.Once
`},
		{name: "ordinary function declaration", source: "package fixture\nfunc callback(uint64) bool { return true }\n"},
		{name: "function local transient", source: "package fixture\nfunc transient(){ text := \"secret\"; value := make([]byte, 32); _, _ = text, value }\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixturePath := filepath.Join(t.TempDir(), "fixture.go")
			if err := os.WriteFile(fixturePath, []byte(tt.source), 0o600); err != nil {
				t.Fatal(err)
			}
			typedAnalysis, err := l8CredentialSourceAnalyzeTypedProduction([]string{fixturePath})
			if err != nil {
				t.Fatal(err)
			}
			if len(typedAnalysis.issues) != tt.wantIssues {
				t.Fatalf("raw holder issues = %v, want %d", typedAnalysis.issues, tt.wantIssues)
			}
		})
	}
}

func TestL8CredentialSourceBuildContextsSeparatePlatformDeclarationsAndCoverEveryFile(t *testing.T) {
	analysis := l8CredentialSourceFixtureAnalysis(t, map[string]string{
		"common.go": `package fixture
type safeCounter struct{ count uint64 }
`,
		"platform_linux.go": `//go:build linux

package fixture

type platformHolder struct{ retained []byte }
var platformValue = "linux-secret"
`,
		"platform_other.go": `//go:build !linux

package fixture

type platformHolder struct{ retained string }
var platformValue = []byte("nonlinux-secret")
`,
	})
	for _, contextName := range []string{"linux", "nonlinux"} {
		if len(analysis.contextIssues[contextName]) == 0 {
			t.Fatalf("%s build context did not enforce raw-state guards", contextName)
		}
	}
	linuxPath := l8CredentialSourceCoveredFixturePath(t, analysis, "platform_linux.go")
	nonLinuxPath := l8CredentialSourceCoveredFixturePath(t, analysis, "platform_other.go")
	commonPath := l8CredentialSourceCoveredFixturePath(t, analysis, "common.go")
	if !analysis.covered[linuxPath]["linux"] || analysis.covered[linuxPath]["nonlinux"] {
		t.Fatalf("linux fixture coverage = %v, want linux only", analysis.covered[linuxPath])
	}
	if !analysis.covered[nonLinuxPath]["nonlinux"] || analysis.covered[nonLinuxPath]["linux"] {
		t.Fatalf("non-linux fixture coverage = %v, want nonlinux only", analysis.covered[nonLinuxPath])
	}
	if !analysis.covered[commonPath]["linux"] || !analysis.covered[commonPath]["nonlinux"] {
		t.Fatalf("common fixture coverage = %v, want both contexts", analysis.covered[commonPath])
	}
	if !strings.Contains(strings.Join(analysis.contextIssues["linux"], "\n"), "platform_linux.go") {
		t.Fatal("linux context did not report its platform raw holder")
	}
	if !strings.Contains(strings.Join(analysis.contextIssues["nonlinux"], "\n"), "platform_other.go") {
		t.Fatal("non-linux context did not report its platform raw holder")
	}

	uncovered := l8CredentialSourceFixtureAnalysis(t, map[string]string{
		"platform_windows.go": "//go:build windows\n\npackage fixture\ntype windowsOnly struct{ count uint64 }\n",
	})
	if len(uncovered.issues) != 1 || !strings.Contains(uncovered.issues[0], "not covered by the selected linux/non-linux build contexts") {
		t.Fatalf("uncovered production file issues = %v, want exact coverage blocker", uncovered.issues)
	}
}

func TestL8CredentialSourceTypedLiveHolderFieldsFailClosedExceptExactOperationalSeams(t *testing.T) {
	exactOperational := `package fixture
import (
	"context"
	sandboxruntime "github.com/jywlabs/hal/internal/sandboxruntime"
)
type keyctlReader interface {
	DescribeSize(context.Context, int32) (int, error)
	DescribeInto(context.Context, int32, []byte) (int, error)
	ReadSize(context.Context, int32) (int, error)
	ReadInto(context.Context, int32, []byte) (int, error)
}
type lockedSecretBorrowedView interface {
	WriteTo(context.Context, sandboxruntime.JobCredentialSecretSink) error
}
type lockedSecretMapping interface {
	Load(context.Context, func([]byte) (int, error)) error
	Borrow(context.Context, func(lockedSecretBorrowedView) error) error
	Destroy() error
}
type registryDeps struct {
	keyctl keyctlReader
	newLockedMapping func(int) (lockedSecretMapping, error)
}
type Registry struct{ deps registryDeps }
`
	if analysis := l8CredentialSourceFixtureAnalysis(t, map[string]string{"exact.go": exactOperational}); len(analysis.issues) != 0 {
		t.Fatalf("exact operational seams rejected: %v", analysis.issues)
	}
	alternateAlias := strings.Replace(exactOperational, "sandboxruntime \"", "runtimecontract \"", 1)
	alternateAlias = strings.ReplaceAll(alternateAlias, "sandboxruntime.", "runtimecontract.")
	if analysis := l8CredentialSourceFixtureAnalysis(t, map[string]string{"exact.go": alternateAlias}); len(analysis.issues) != 0 {
		t.Fatalf("semantic operational seam rejected exact imported type under alternate alias: %v", analysis.issues)
	}

	if analysis := l8CredentialSourceFixtureAnalysis(t, map[string]string{"safe.go": `package fixture
import "sync"
type safeHolder struct {
	count uint64
	ready bool
	gate sync.Mutex
}
`}); len(analysis.issues) != 0 {
		t.Fatalf("safe scalar/synchronization fields rejected: %v", analysis.issues)
	}

	for _, tt := range []struct {
		name   string
		source string
		want   []string
	}{
		{
			name: "raw interface error function builder and nested alias",
			source: `package fixture
import "strings"
type builderAlias = strings.Builder
type nestedRawAlias string
type nestedState struct{ raw nestedRawAlias }
type unsafeHolder struct {
	anyValue any
	errValue error
	callback func()
	builder builderAlias
	nested nestedState
}
`,
			want: []string{"unsafeHolder.anyValue", "unsafeHolder.errValue", "unsafeHolder.callback", "unsafeHolder.builder", "unsafeHolder.nested"},
		},
		{
			name: "unresolved external field",
			source: `package fixture
import sandboxruntime "github.com/jywlabs/hal/internal/sandboxruntime"
type unsafeHolder struct{ unresolved sandboxruntime.DoesNotExist }
`,
			want: []string{"unsafeHolder.unresolved"},
		},
		{
			name:   "mutated keyctl interface",
			source: strings.Replace(exactOperational, "ReadInto(context.Context, int32, []byte) (int, error)", "ReadInto(context.Context, int32, []byte) (int, error)\n\tRaw() []byte", 1),
			want:   []string{"keyctlReader contains unexpected method Raw"},
		},
		{
			name:   "mutated locked mapping callback",
			source: strings.Replace(exactOperational, "newLockedMapping func(int) (lockedSecretMapping, error)", "newLockedMapping func(int, func([]byte)) (lockedSecretMapping, error)", 1),
			want:   []string{"registryDeps field newLockedMapping"},
		},
		{
			name:   "aliased keyctl interface",
			source: strings.Replace(exactOperational, "type keyctlReader interface {", "type keyctlReader = keyctlReaderAlias\ntype keyctlReaderAlias interface {", 1),
			want:   []string{"keyctlReader is missing or aliases another type"},
		},
		{
			name:   "fake context package",
			source: strings.Replace(exactOperational, "\"context\"", "context \"example.com/fake/context\"", 1),
			want:   []string{"keyctlReader method DescribeSize"},
		},
		{
			name:   "fake sandboxruntime package",
			source: strings.Replace(exactOperational, l8CredentialSourceSandboxruntimeImportPath, "example.com/fake/sandboxruntime", 1),
			want:   []string{"lockedSecretBorrowedView method WriteTo"},
		},
		{
			name: "aliased sandboxruntime sink",
			source: strings.Replace(
				strings.Replace(exactOperational, "type keyctlReader interface {", "type sinkAlias = sandboxruntime.JobCredentialSecretSink\ntype keyctlReader interface {", 1),
				"WriteTo(context.Context, sandboxruntime.JobCredentialSecretSink)", "WriteTo(context.Context, sinkAlias)", 1,
			),
			want: []string{"lockedSecretBorrowedView method WriteTo"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			analysis := l8CredentialSourceFixtureAnalysis(t, map[string]string{"fixture.go": tt.source})
			joined := strings.Join(analysis.issues, "\n")
			for _, expected := range tt.want {
				if !strings.Contains(joined, expected) {
					t.Errorf("typed field issues omit %q: %v", expected, analysis.issues)
				}
			}
		})
	}
}

func l8CredentialSourceFixtureAnalysis(t *testing.T, fixtures map[string]string) l8CredentialSourceTypedAnalysis {
	t.Helper()
	root := t.TempDir()
	for relativePath, source := range fixtures {
		productionPath := filepath.Join(root, filepath.FromSlash(relativePath))
		if err := os.MkdirAll(filepath.Dir(productionPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(productionPath, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	productionFiles, err := l8CredentialSourceProductionFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := l8CredentialSourceAnalyzeTypedProduction(productionFiles)
	if err != nil {
		t.Fatal(err)
	}
	return analysis
}

func l8CredentialSourceCoveredFixturePath(t *testing.T, analysis l8CredentialSourceTypedAnalysis, base string) string {
	t.Helper()
	for productionPath := range analysis.covered {
		if filepath.Base(productionPath) == base {
			return productionPath
		}
	}
	t.Fatalf("fixture %s was not covered", base)
	return ""
}

func l8CredentialSourceProductionFiles(root string) ([]string, error) {
	var productionFiles []string
	err := filepath.WalkDir(root, func(productionPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if productionPath != root && (entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			productionFiles = append(productionFiles, productionPath)
		}
		return nil
	})
	return productionFiles, err
}

type l8CredentialSourceBuildTarget struct {
	name    string
	context build.Context
}

type l8CredentialSourceTypedAnalysis struct {
	issues        []string
	contextIssues map[string][]string
	covered       map[string]map[string]bool
	issueSet      map[string]bool
}

func l8CredentialSourceAnalyzeTypedProduction(productionFiles []string) (l8CredentialSourceTypedAnalysis, error) {
	type packageFiles struct {
		name  string
		paths []string
	}
	analysis := l8CredentialSourceTypedAnalysis{
		contextIssues: map[string][]string{},
		covered:       map[string]map[string]bool{},
		issueSet:      map[string]bool{},
	}
	productionFiles = append([]string(nil), productionFiles...)
	sort.Strings(productionFiles)

	workingDir, err := os.Getwd()
	if err != nil {
		return analysis, fmt.Errorf("resolve credential source package: %w", err)
	}
	workingDir, err = filepath.Abs(workingDir)
	if err != nil {
		return analysis, fmt.Errorf("resolve credential source package: %w", err)
	}

	for _, target := range l8CredentialSourceBuildTargets() {
		groups := map[string]*packageFiles{}
		var groupKeys []string
		for _, productionPath := range productionFiles {
			matched, err := target.context.MatchFile(filepath.Dir(productionPath), filepath.Base(productionPath))
			if err != nil {
				return analysis, fmt.Errorf("match %s build context: %w", target.name, err)
			}
			if !matched {
				continue
			}
			if analysis.covered[productionPath] == nil {
				analysis.covered[productionPath] = map[string]bool{}
			}
			analysis.covered[productionPath][target.name] = true
			file, err := parser.ParseFile(token.NewFileSet(), productionPath, nil, parser.PackageClauseOnly)
			if err != nil {
				return analysis, fmt.Errorf("parse %s package declaration: %w", target.name, err)
			}
			key := filepath.Clean(filepath.Dir(productionPath)) + "\x00" + file.Name.Name
			if groups[key] == nil {
				groups[key] = &packageFiles{name: file.Name.Name}
				groupKeys = append(groupKeys, key)
			}
			groups[key].paths = append(groups[key].paths, productionPath)
		}
		sort.Strings(groupKeys)
		for groupIndex, key := range groupKeys {
			if err := l8CredentialSourceAnalyzeTypedPackage(target.name, groupIndex, groups[key].name, groups[key].paths, workingDir, &analysis); err != nil {
				return analysis, err
			}
		}
	}
	for _, productionPath := range productionFiles {
		if len(analysis.covered[productionPath]) == 0 {
			analysis.addIssue("coverage", filepath.ToSlash(productionPath)+" is not covered by the selected linux/non-linux build contexts")
		}
	}
	sort.Strings(analysis.issues)
	for contextName := range analysis.contextIssues {
		sort.Strings(analysis.contextIssues[contextName])
	}
	return analysis, nil
}

func l8CredentialSourceBuildTargets() []l8CredentialSourceBuildTarget {
	linux := build.Default
	linux.GOOS = "linux"
	linux.GOARCH = "amd64"
	linux.CgoEnabled = false
	nonLinux := build.Default
	nonLinux.GOOS = "darwin"
	nonLinux.GOARCH = "amd64"
	nonLinux.CgoEnabled = false
	return []l8CredentialSourceBuildTarget{
		{name: "linux", context: linux},
		{name: "nonlinux", context: nonLinux},
	}
}

func (analysis *l8CredentialSourceTypedAnalysis) addIssue(contextName, issue string) {
	if !analysis.issueSet[issue] {
		analysis.issueSet[issue] = true
		analysis.issues = append(analysis.issues, issue)
	}
	for _, existing := range analysis.contextIssues[contextName] {
		if existing == issue {
			return
		}
	}
	analysis.contextIssues[contextName] = append(analysis.contextIssues[contextName], issue)
}

func l8CredentialSourceAnalyzeTypedPackage(contextName string, groupIndex int, packageName string, productionPaths []string, workingDir string, analysis *l8CredentialSourceTypedAnalysis) error {
	set := token.NewFileSet()
	var files []*ast.File
	filePaths := map[*ast.File]string{}
	for _, productionPath := range productionPaths {
		file, err := parser.ParseFile(set, productionPath, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s production package: %w", contextName, err)
		}
		files = append(files, file)
		filePaths[file] = productionPath
	}

	packagePath := fmt.Sprintf("l8-credential-source-guard/%s/%d", contextName, groupIndex)
	info := &types.Info{
		Defs:  map[*ast.Ident]types.Object{},
		Types: map[ast.Expr]types.TypeAndValue{},
	}
	fallbackImporter := &l8CredentialSourceFallbackImporter{
		primary:    importer.Default(),
		unresolved: map[string]bool{},
	}
	var typeErrors []error
	config := &types.Config{
		Importer:                 fallbackImporter,
		IgnoreFuncBodies:         true,
		DisableUnusedImportCheck: true,
		Error:                    func(err error) { typeErrors = append(typeErrors, err) },
	}
	typedPackage, _ := config.Check(packagePath, set, files, info)
	if typedPackage == nil {
		return fmt.Errorf("type-check %s package declarations: package unavailable", contextName)
	}
	for _, typeErr := range typeErrors {
		if !l8CredentialSourceExpectedUnresolvedTypeError(typeErr, files, fallbackImporter.unresolved) {
			return fmt.Errorf("type-check %s package declarations: %w", contextName, typeErr)
		}
	}

	safeMetadataTypes := map[string]bool{}
	packageDir, err := filepath.Abs(filepath.Dir(productionPaths[0]))
	if err != nil {
		return fmt.Errorf("resolve production package: %w", err)
	}
	rootCredentialSource := filepath.Clean(packageDir) == filepath.Clean(workingDir) && packageName == "credentialsource"
	if rootCredentialSource {
		var safeMetadataIssues []string
		safeMetadataTypes, safeMetadataIssues = l8CredentialSourceSemanticSafeMetadata(typedPackage)
		for _, issue := range safeMetadataIssues {
			analysis.addIssue(contextName, "safe metadata schema "+issue)
		}
	}
	operationalSafeFields, operationalSafeTypes, operationalIssues := l8CredentialSourceExactOperationalSeams(typedPackage)
	for _, issue := range operationalIssues {
		analysis.addIssue(contextName, filepath.ToSlash(filepath.Dir(productionPaths[0]))+" operational seam "+issue)
	}
	for _, file := range files {
		productionPath := filePaths[file]
		for _, declaration := range file.Decls {
			generic, ok := declaration.(*ast.GenDecl)
			if !ok {
				continue
			}
			switch generic.Tok {
			case token.VAR:
				for _, spec := range generic.Specs {
					valueSpec := spec.(*ast.ValueSpec)
					for _, name := range valueSpec.Names {
						if name.Name == "_" {
							continue
						}
						object, ok := info.Defs[name].(*types.Var)
						if !ok || object.Type() == nil {
							analysis.addIssue(contextName, filepath.ToSlash(productionPath)+" package variable "+name.Name+" could not be analyzed")
							continue
						}
						safeSentinel := object.Type() == types.Universe.Lookup("error").Type() &&
							l8CredentialSourceSafeSentinelErrorInitializer(file, valueSpec, name)
						raw := l8CredentialSourceTypedRawType(object.Type(), packagePath, safeMetadataTypes, nil, map[types.Type]bool{})
						if initializerType, present, analyzed := l8CredentialSourceTypedInitializerType(info, valueSpec, name); present {
							if !analyzed {
								analysis.addIssue(contextName, filepath.ToSlash(productionPath)+" package variable "+name.Name+" initializer could not be analyzed")
								continue
							}
							raw = raw || l8CredentialSourceTypedRawType(initializerType, packagePath, safeMetadataTypes, nil, map[types.Type]bool{})
						}
						if safeSentinel {
							raw = false
						}
						if raw {
							analysis.addIssue(contextName, filepath.ToSlash(productionPath)+" package variable "+name.Name+" retains mutable raw state")
						}
					}
				}
			case token.TYPE:
				for _, spec := range generic.Specs {
					typeSpec := spec.(*ast.TypeSpec)
					if safeMetadataTypes[typeSpec.Name.Name] {
						continue
					}
					object, ok := info.Defs[typeSpec.Name].(*types.TypeName)
					if !ok || object.Type() == nil {
						analysis.addIssue(contextName, filepath.ToSlash(productionPath)+" live holder "+typeSpec.Name.Name+" could not be analyzed")
						continue
					}
					structure, ok := types.Unalias(object.Type()).Underlying().(*types.Struct)
					if !ok {
						continue
					}
					for fieldIndex := 0; fieldIndex < structure.NumFields(); fieldIndex++ {
						field := structure.Field(fieldIndex)
						fieldKey := typeSpec.Name.Name + "." + field.Name()
						if operationalSafeFields[fieldKey] {
							continue
						}
						if l8CredentialSourceTypedRawFieldType(field.Type(), packagePath, safeMetadataTypes, operationalSafeTypes, map[types.Type]bool{}) {
							analysis.addIssue(contextName, filepath.ToSlash(productionPath)+" live holder "+fieldKey+" retains raw/interface/function state")
						}
					}
				}
			}
		}
	}
	return nil
}

func l8CredentialSourceExactOperationalSeams(typedPackage *types.Package) (map[string]bool, map[string]bool, []string) {
	safeFields := map[string]bool{}
	safeTypes := map[string]bool{}
	requiredNames := []string{"keyctlReader", "lockedSecretBorrowedView", "lockedSecretMapping", "registryDeps"}
	present := false
	for _, name := range requiredNames {
		present = present || typedPackage.Scope().Lookup(name) != nil
	}
	if !present {
		return safeFields, safeTypes, nil
	}

	var issues []string
	issues = append(issues, l8CredentialSourceSemanticInterfaceSchemaIssues(typedPackage, "keyctlReader", map[string]string{
		"DescribeSize": "func(context.Context,int32)(int,error)",
		"DescribeInto": "func(context.Context,int32,[]byte)(int,error)",
		"ReadSize":     "func(context.Context,int32)(int,error)",
		"ReadInto":     "func(context.Context,int32,[]byte)(int,error)",
	})...)
	issues = append(issues, l8CredentialSourceSemanticInterfaceSchemaIssues(typedPackage, "lockedSecretBorrowedView", map[string]string{
		"WriteTo": "func(context.Context," + l8CredentialSourceSandboxruntimeImportPath + ".JobCredentialSecretSink)(error)",
	})...)
	issues = append(issues, l8CredentialSourceSemanticInterfaceSchemaIssues(typedPackage, "lockedSecretMapping", map[string]string{
		"Load":    "func(context.Context,func([]byte)(int,error))(error)",
		"Borrow":  "func(context.Context,func(local:lockedSecretBorrowedView)(error))(error)",
		"Destroy": "func()(error)",
	})...)
	issues = append(issues, l8CredentialSourceSemanticStructSchemaIssues(typedPackage, map[string]map[string]string{
		"registryDeps": {
			"keyctl":           "local:keyctlReader",
			"newLockedMapping": "func(int)(local:lockedSecretMapping,error)",
		},
	})...)
	registry, ok := l8CredentialSourceLocalNamedType(typedPackage, "Registry")
	if !ok {
		issues = append(issues, "Registry is not an exact struct holder for registryDeps")
	} else {
		structure, structureOK := registry.Underlying().(*types.Struct)
		matchedDeps := false
		if structureOK {
			for fieldIndex := 0; fieldIndex < structure.NumFields(); fieldIndex++ {
				field := structure.Field(fieldIndex)
				if !field.Anonymous() && field.Name() == "deps" && l8CredentialSourceSemanticTypeString(field.Type(), typedPackage.Path()) == "local:registryDeps" {
					matchedDeps = true
				}
			}
		}
		if !structureOK {
			issues = append(issues, "Registry is not an exact struct holder for registryDeps")
		} else if !matchedDeps {
			issues = append(issues, "Registry is missing exact deps registryDeps field")
		}
	}
	if len(issues) == 0 {
		safeFields["registryDeps.keyctl"] = true
		safeFields["registryDeps.newLockedMapping"] = true
		safeFields["Registry.deps"] = true
		safeTypes["Registry"] = true
	}
	return safeFields, safeTypes, issues
}

func l8CredentialSourceSemanticInterfaceSchemaIssues(typedPackage *types.Package, typeName string, expected map[string]string) []string {
	named, ok := l8CredentialSourceLocalNamedType(typedPackage, typeName)
	if !ok {
		return []string{typeName + " is missing or aliases another type"}
	}
	contract, ok := named.Underlying().(*types.Interface)
	if !ok {
		return []string{typeName + " is not an exact interface schema"}
	}
	contract.Complete()
	actual := map[string]string{}
	var issues []string
	if contract.NumEmbeddeds() != 0 {
		issues = append(issues, typeName+" contains embedded interfaces")
	}
	for methodIndex := 0; methodIndex < contract.NumExplicitMethods(); methodIndex++ {
		method := contract.ExplicitMethod(methodIndex)
		actual[method.Name()] = l8CredentialSourceSemanticTypeString(method.Type(), typedPackage.Path())
	}
	for methodName, expectedSignature := range expected {
		actualSignature, exists := actual[methodName]
		if !exists {
			issues = append(issues, typeName+" is missing method "+methodName)
			continue
		}
		if actualSignature != expectedSignature {
			issues = append(issues, typeName+" method "+methodName+" has signature "+actualSignature+", want "+expectedSignature)
		}
	}
	for methodName := range actual {
		if _, expectedMethod := expected[methodName]; !expectedMethod {
			issues = append(issues, typeName+" contains unexpected method "+methodName)
		}
	}
	if len(actual) != len(expected) {
		issues = append(issues, typeName+" method count differs from exact schema")
	}
	return issues
}

func l8CredentialSourceSemanticTypeString(valueType types.Type, localPackagePath string) string {
	switch typed := valueType.(type) {
	case *types.Alias:
		return "<alias:" + typed.Obj().Name() + ">"
	case *types.Basic:
		return typed.Name()
	case *types.Named:
		object := typed.Obj()
		if object == nil {
			return "<unnamed>"
		}
		if object.Pkg() == nil {
			return object.Name()
		}
		if object.Pkg().Path() == localPackagePath {
			return "local:" + object.Name()
		}
		return object.Pkg().Path() + "." + object.Name()
	case *types.Pointer:
		return "*" + l8CredentialSourceSemanticTypeString(typed.Elem(), localPackagePath)
	case *types.Slice:
		return "[]" + l8CredentialSourceSemanticTypeString(typed.Elem(), localPackagePath)
	case *types.Array:
		return fmt.Sprintf("[%d]%s", typed.Len(), l8CredentialSourceSemanticTypeString(typed.Elem(), localPackagePath))
	case *types.Map:
		return "map[" + l8CredentialSourceSemanticTypeString(typed.Key(), localPackagePath) + "]" + l8CredentialSourceSemanticTypeString(typed.Elem(), localPackagePath)
	case *types.Chan:
		return "chan " + l8CredentialSourceSemanticTypeString(typed.Elem(), localPackagePath)
	case *types.Signature:
		if typed.TypeParams() != nil && typed.TypeParams().Len() != 0 {
			return "func[generic]"
		}
		prefix := "func("
		if typed.Variadic() {
			prefix = "func[variadic]("
		}
		return prefix + l8CredentialSourceSemanticTupleString(typed.Params(), localPackagePath) + ")(" +
			l8CredentialSourceSemanticTupleString(typed.Results(), localPackagePath) + ")"
	case *types.Interface:
		return "<interface>"
	case *types.Struct:
		return "<struct>"
	case *types.Tuple:
		return l8CredentialSourceSemanticTupleString(typed, localPackagePath)
	default:
		return "<invalid>"
	}
}

func l8CredentialSourceSemanticTupleString(tuple *types.Tuple, localPackagePath string) string {
	if tuple == nil {
		return ""
	}
	values := make([]string, 0, tuple.Len())
	for index := 0; index < tuple.Len(); index++ {
		values = append(values, l8CredentialSourceSemanticTypeString(tuple.At(index).Type(), localPackagePath))
	}
	return strings.Join(values, ",")
}

func l8CredentialSourceLocalNamedType(typedPackage *types.Package, name string) (*types.Named, bool) {
	object, ok := typedPackage.Scope().Lookup(name).(*types.TypeName)
	if !ok || object.IsAlias() {
		return nil, false
	}
	named, ok := object.Type().(*types.Named)
	return named, ok && named.Obj() == object && object.Pkg() == typedPackage
}

type l8CredentialSourceFallbackImporter struct {
	primary        types.Importer
	unresolved     map[string]bool
	sandboxruntime *types.Package
}

func (fallback *l8CredentialSourceFallbackImporter) Import(importPath string) (*types.Package, error) {
	if importPath == l8CredentialSourceSandboxruntimeImportPath {
		fallback.unresolved[importPath] = true
		if fallback.sandboxruntime == nil {
			fallback.sandboxruntime = l8CredentialSourceSandboxruntimeContractPackage()
		}
		return fallback.sandboxruntime, nil
	}
	imported, err := fallback.primary.Import(importPath)
	if err == nil {
		return imported, nil
	}
	fallback.unresolved[importPath] = true
	placeholder := types.NewPackage(importPath, path.Base(importPath))
	placeholder.MarkComplete()
	return placeholder, nil
}

const l8CredentialSourceSandboxruntimeImportPath = "github.com/jywlabs/hal/internal/sandboxruntime"

func l8CredentialSourceSandboxruntimeContractPackage() *types.Package {
	contract := types.NewPackage(l8CredentialSourceSandboxruntimeImportPath, "sandboxruntime")
	interfaceNames := map[string]bool{
		"AuthenticatedWorkerPrincipal":       true,
		"AuthorizedCredentialSourceRegistry": true,
		"CredentialAdmissionAuthorization":   true,
		"CredentialAdmissionAuthorizer":      true,
		"JobCredentialSecretSink":            true,
	}
	for _, name := range []string{
		"AuthenticatedWorkerPrincipal",
		"AuthenticatedWorkerPrincipalAuthority",
		"AuthorizedCredentialSourceRegistry",
		"CredentialAdmissionAuthorization",
		"CredentialAdmissionAuthorizer",
		"JobCredentialAdmissionIdentity",
		"JobCredentialAdmissionRequest",
		"JobCredentialBindingRequest",
		"JobCredentialSecretSink",
	} {
		object := types.NewTypeName(token.NoPos, contract, name, nil)
		underlying := types.Type(types.NewStruct(nil, nil))
		if interfaceNames[name] {
			underlying = types.NewInterfaceType(nil, nil).Complete()
		}
		types.NewNamed(object, underlying, nil)
		contract.Scope().Insert(object)
	}
	contract.MarkComplete()
	return contract
}

func l8CredentialSourceExpectedUnresolvedTypeError(typeErr error, files []*ast.File, unresolved map[string]bool) bool {
	message := typeErr.Error()
	for _, file := range files {
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil || !unresolved[importPath] {
				continue
			}
			alias := path.Base(importPath)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			marker := "undefined: " + alias
			markerIndex := strings.Index(message, marker)
			if markerIndex < 0 {
				continue
			}
			remainder := message[markerIndex+len(marker):]
			if remainder == "" || strings.HasPrefix(remainder, ".") || strings.HasPrefix(remainder, " ") {
				return true
			}
		}
	}
	return false
}

func l8CredentialSourceTypedInitializerType(info *types.Info, valueSpec *ast.ValueSpec, name *ast.Ident) (types.Type, bool, bool) {
	if len(valueSpec.Values) == 0 {
		return nil, false, true
	}
	nameIndex := -1
	for index, candidate := range valueSpec.Names {
		if candidate == name {
			nameIndex = index
			break
		}
	}
	if nameIndex < 0 {
		return nil, true, false
	}
	if len(valueSpec.Values) == len(valueSpec.Names) {
		value, ok := info.Types[valueSpec.Values[nameIndex]]
		return value.Type, true, ok && value.Type != nil
	}
	if len(valueSpec.Values) != 1 {
		return nil, true, false
	}
	value, ok := info.Types[valueSpec.Values[0]]
	if !ok || value.Type == nil {
		return nil, true, false
	}
	tuple, ok := types.Unalias(value.Type).(*types.Tuple)
	if !ok || nameIndex >= tuple.Len() {
		return nil, true, false
	}
	return tuple.At(nameIndex).Type(), true, true
}

func l8CredentialSourceSafeSentinelErrorInitializer(file *ast.File, valueSpec *ast.ValueSpec, name *ast.Ident) bool {
	if len(valueSpec.Values) != len(valueSpec.Names) {
		return false
	}
	nameIndex := -1
	for index, candidate := range valueSpec.Names {
		if candidate == name {
			nameIndex = index
			break
		}
	}
	if nameIndex < 0 {
		return false
	}
	call, ok := valueSpec.Values[nameIndex].(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "New" {
		return false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	errorsAlias := ""
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != "errors" {
			continue
		}
		errorsAlias = "errors"
		if spec.Name != nil {
			errorsAlias = spec.Name.Name
		}
	}
	if errorsAlias == "" || qualifier.Name != errorsAlias {
		return false
	}
	literal, ok := call.Args[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	message, err := strconv.Unquote(literal.Value)
	return err == nil && strings.TrimSpace(message) == message && message != ""
}

func l8CredentialSourceTypedRawType(valueType types.Type, packagePath string, safeMetadataTypes, safeOperationalTypes map[string]bool, seen map[types.Type]bool) bool {
	if _, aliased := valueType.(*types.Alias); aliased {
		return true
	}
	valueType = types.Unalias(valueType)
	if seen[valueType] {
		return false
	}
	seen[valueType] = true

	switch typed := valueType.(type) {
	case *types.Basic:
		switch typed.Kind() {
		case types.Invalid, types.String, types.UntypedString, types.UnsafePointer:
			return true
		default:
			return false
		}
	case *types.Array:
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Slice:
		if basic, ok := types.Unalias(typed.Elem()).Underlying().(*types.Basic); ok && basic.Kind() == types.Uint8 {
			return true
		}
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Map:
		return l8CredentialSourceTypedRawType(typed.Key(), packagePath, safeMetadataTypes, safeOperationalTypes, seen) ||
			l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Pointer:
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Chan:
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Struct:
		for fieldIndex := 0; fieldIndex < typed.NumFields(); fieldIndex++ {
			if l8CredentialSourceTypedRawType(typed.Field(fieldIndex).Type(), packagePath, safeMetadataTypes, safeOperationalTypes, seen) {
				return true
			}
		}
		return false
	case *types.Tuple:
		for valueIndex := 0; valueIndex < typed.Len(); valueIndex++ {
			if l8CredentialSourceTypedRawType(typed.At(valueIndex).Type(), packagePath, safeMetadataTypes, safeOperationalTypes, seen) {
				return true
			}
		}
		return false
	case *types.Interface:
		return true
	case *types.Signature:
		return true
	case *types.Named:
		object := typed.Obj()
		if object != nil && object.Pkg() != nil && object.Pkg().Path() == packagePath && (safeMetadataTypes[object.Name()] || safeOperationalTypes[object.Name()]) {
			return false
		}
		return l8CredentialSourceTypedRawType(types.Unalias(typed.Underlying()), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	default:
		return true
	}
}

func l8CredentialSourceTypedRawFieldType(valueType types.Type, packagePath string, safeMetadataTypes, safeOperationalTypes map[string]bool, seen map[types.Type]bool) bool {
	if _, aliased := valueType.(*types.Alias); aliased {
		return true
	}
	valueType = types.Unalias(valueType)
	if seen[valueType] {
		return false
	}
	seen[valueType] = true

	switch typed := valueType.(type) {
	case *types.Interface, *types.Signature:
		return true
	case *types.Basic:
		switch typed.Kind() {
		case types.Invalid, types.String, types.UntypedString, types.UnsafePointer:
			return true
		default:
			return false
		}
	case *types.Array:
		return l8CredentialSourceTypedRawFieldType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Slice:
		if basic, ok := types.Unalias(typed.Elem()).Underlying().(*types.Basic); ok && basic.Kind() == types.Uint8 {
			return true
		}
		return l8CredentialSourceTypedRawFieldType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Map:
		return l8CredentialSourceTypedRawFieldType(typed.Key(), packagePath, safeMetadataTypes, safeOperationalTypes, seen) ||
			l8CredentialSourceTypedRawFieldType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Pointer:
		return l8CredentialSourceTypedRawFieldType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Chan:
		return l8CredentialSourceTypedRawFieldType(typed.Elem(), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	case *types.Struct:
		for fieldIndex := 0; fieldIndex < typed.NumFields(); fieldIndex++ {
			if l8CredentialSourceTypedRawFieldType(typed.Field(fieldIndex).Type(), packagePath, safeMetadataTypes, safeOperationalTypes, seen) {
				return true
			}
		}
		return false
	case *types.Tuple:
		for valueIndex := 0; valueIndex < typed.Len(); valueIndex++ {
			if l8CredentialSourceTypedRawFieldType(typed.At(valueIndex).Type(), packagePath, safeMetadataTypes, safeOperationalTypes, seen) {
				return true
			}
		}
		return false
	case *types.Named:
		object := typed.Obj()
		if object != nil && object.Pkg() != nil && object.Pkg().Path() == packagePath && (safeMetadataTypes[object.Name()] || safeOperationalTypes[object.Name()]) {
			return false
		}
		return l8CredentialSourceTypedRawFieldType(types.Unalias(typed.Underlying()), packagePath, safeMetadataTypes, safeOperationalTypes, seen)
	default:
		return true
	}
}

func l8CredentialSourceForbiddenSelectorIssues(file *ast.File) []string {
	aliases := map[string]string{}
	var issues []string
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		localName := path.Base(importPath)
		if spec.Name != nil {
			localName = spec.Name.Name
		}
		if localName == "." && (importPath == "errors" || importPath == "golang.org/x/sys/unix") {
			issues = append(issues, "uses forbidden dot import of "+importPath)
			continue
		}
		aliases[localName] = importPath
	}
	allowedUnix := map[string]bool{
		"KeyctlBuffer": true, "KEYCTL_DESCRIBE": true, "KEYCTL_READ": true,
		"ENOKEY": true, "EKEYEXPIRED": true, "EKEYREVOKED": true,
		"EACCES": true, "EPERM": true, "EINVAL": true,
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch aliases[identifier.Name] {
		case "errors":
			if selector.Sel.Name == "Join" {
				issues = append(issues, "uses forbidden raw-error composition errors.Join")
			}
		case "golang.org/x/sys/unix":
			if !allowedUnix[selector.Sel.Name] {
				issues = append(issues, "uses unapproved unix selector "+selector.Sel.Name)
			}
		}
		return true
	})
	return issues
}

func TestL8CredentialSourceFmtUsageIsRestrictedToExactFormatMethods(t *testing.T) {
	for receiver, requiredFormat := range l8CredentialSourceFormatLiterals() {
		t.Run("exact "+receiver, func(t *testing.T) {
			source := "package fixture\nimport safeformat \"fmt\"\ntype " + receiver + " struct{}\nfunc (" + receiver + ") Format(state safeformat.State, verb rune) { safeformat.Fprint(state, " + strconv.Quote(requiredFormat) + ") }\n"
			l8CredentialSourceAssertFmtFixture(t, source, requiredFormat, false, false)
		})
	}

	for _, tt := range []struct {
		name           string
		source         string
		requiredFormat string
		wantDotImport  bool
	}{
		{name: "generic formatting in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprintf(state, \"%v\", verb) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "sprint in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { _ = safeformat.Sprint(verb) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "formatting outside formatter", source: "package fixture\nimport safeformat \"fmt\"\nfunc render(value any) string { return safeformat.Sprint(value) }\n"},
		{name: "wrong fixed literal", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.RegistryConfig>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "package payload", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, safeformat.Stringer(nil)) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "captured payload", source: "package fixture\nimport safeformat \"fmt\"\nvar captured = \"raw\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, captured) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "raw identifier payload", source: "package fixture\nimport safeformat \"fmt\"\nvar rawIdentifier any\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, rawIdentifier) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "helper payload", source: "package fixture\nimport safeformat \"fmt\"\nfunc fixed() string { return \"fixed\" }\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, fixed()) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "receiver payload", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (registry Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, registry) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "wrong destination", source: "package fixture\nimport safeformat \"fmt\"\nvar other safeformat.State\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(other, \"<credentialsource.Registry>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "extra argument", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\", verb) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "variadic argument", source: "package fixture\nimport safeformat \"fmt\"\nvar parts []any\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, parts...) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "concatenated payload", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.\" + \"Registry>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "multiple calls", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\"); safeformat.Fprint(state, \"<credentialsource.Registry>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "import alias shadowed by receiver", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (safeformat Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "state shadowed in closure", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { func(state safeformat.State) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }(state) }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "package capture beside exact format", source: "package fixture\nimport safeformat \"fmt\"\nvar write = safeformat.Fprint\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "indirect package capture use beside exact format", source: "package fixture\nimport safeformat \"fmt\"\nvar write = safeformat.Fprint\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }\nfunc helper(state safeformat.State) { write(state, \"helper\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "grouped package captures beside exact format", source: "package fixture\nimport safeformat \"fmt\"\nvar (\nwrite = safeformat.Fprint\nrender = safeformat.Sprint\n)\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "cross function fmt use beside exact format", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }\nfunc helper(state safeformat.State) { safeformat.Fprint(state, \"helper\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "function local capture beside exact format", source: "package fixture\nimport safeformat \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }\nfunc helper() { write := safeformat.Fprint; _ = write }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "function alias type beside exact format", source: "package fixture\nimport safeformat \"fmt\"\ntype formatter func(safeformat.State, ...any) (int, error)\ntype Registry struct{}\nfunc (Registry) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialsource.Registry>\") }\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "blank import", source: "package fixture\nimport _ \"fmt\"\ntype Registry struct{}\n", requiredFormat: "<credentialsource.Registry>"},
		{name: "dot import", source: "package fixture\nimport . \"fmt\"\ntype Registry struct{}\nfunc (Registry) Format(state State, verb rune) { Fprint(state, \"<credentialsource.Registry>\") }\n", requiredFormat: "<credentialsource.Registry>", wantDotImport: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l8CredentialSourceAssertFmtFixture(t, tt.source, tt.requiredFormat, tt.wantDotImport, true)
		})
	}
}

func l8CredentialSourceAssertFmtFixture(t *testing.T, source, requiredFormat string, wantDotImport, wantIssue bool) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliases, dotImport := l8CredentialSourceImportAliases(file, "fmt")
	if dotImport != wantDotImport {
		t.Fatalf("fmt dot import = %t, want %t", dotImport, wantDotImport)
	}
	formatLiterals := map[string]string{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "Format" && function.Recv != nil {
			formatLiterals[l8CredentialSourceReceiverName(function.Recv.List[0].Type)] = requiredFormat
		}
	}
	issues := l8CredentialSourceFmtFileIssues(file, aliases, true, formatLiterals)
	if wantIssue == (len(issues) == 0 && !dotImport) {
		t.Fatalf("fmt issues = %v, dot import = %t, want issue %t", issues, dotImport, wantIssue)
	}
}

func l8CredentialSourceFormatLiterals() map[string]string {
	return map[string]string{
		"Registry":                   "<credentialsource.Registry>",
		"RegistryConfig":             "<credentialsource.RegistryConfig>",
		"SourceRegistration":         "<credentialsource.SourceRegistration>",
		"AdmissionGrantRegistration": "<credentialsource.AdmissionGrantRegistration>",
		"KeyIdentity":                "<credentialsource.KeyIdentity>",
		"KeyDescriptor":              "<credentialsource.KeyDescriptor>",
		"registryAuthorization":      "<credentialsource.registryAuthorization>",
		"keyringLiveSecretSource":    "<credentialsource.keyringLiveSecretSource>",
	}
}

func l8CredentialSourceImportAliases(file *ast.File, wantedPath string) (map[string]bool, bool) {
	aliases := map[string]bool{}
	dotImport := false
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != wantedPath {
			continue
		}
		alias := path.Base(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		switch alias {
		case ".":
			dotImport = true
		default:
			aliases[alias] = true
		}
	}
	return aliases, dotImport
}

func l8CredentialSourceFmtFileIssues(file *ast.File, fmtAliases map[string]bool, rootPackage bool, formatLiterals map[string]string) []string {
	var issues []string
	allowedSelectors := map[*ast.SelectorExpr]bool{}
	approvedAliases := map[string]bool{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Format" || function.Recv == nil || !rootPackage {
			continue
		}
		receiver := l8CredentialSourceReceiverName(function.Recv.List[0].Type)
		requiredFormat := formatLiterals[receiver]
		if requiredFormat == "" {
			continue
		}
		if !l8CredentialSourceExactFormatMethod(function, fmtAliases, requiredFormat) {
			issues = append(issues, "Format method on "+receiver+" is not the exact single fixed-literal fmt.Fprint boundary")
			continue
		}
		stateSelector := function.Type.Params.List[0].Type.(*ast.SelectorExpr)
		call := function.Body.List[0].(*ast.ExprStmt).X.(*ast.CallExpr)
		allowedSelectors[stateSelector] = true
		allowedSelectors[call.Fun.(*ast.SelectorExpr)] = true
		approvedAliases[stateSelector.X.(*ast.Ident).Name] = true
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok || !fmtAliases[identifier.Name] {
			return true
		}
		if !allowedSelectors[selector] {
			issues = append(issues, "uses fmt."+selector.Sel.Name+" outside an exact approved Format signature/body")
		}
		return true
	})
	for alias := range fmtAliases {
		if !approvedAliases[alias] {
			issues = append(issues, "imports fmt outside an exact approved Format method")
		}
	}
	return issues
}

func l8CredentialSourceExactFormatMethod(function *ast.FuncDecl, fmtAliases map[string]bool, requiredFormat string) bool {
	if function.Type.Results != nil && len(function.Type.Results.List) != 0 || function.Type.Params == nil || len(function.Type.Params.List) != 2 {
		return false
	}
	stateField, verbField := function.Type.Params.List[0], function.Type.Params.List[1]
	if len(stateField.Names) != 1 || len(verbField.Names) != 1 {
		return false
	}
	stateType, ok := stateField.Type.(*ast.SelectorExpr)
	if !ok || stateType.Sel.Name != "State" {
		return false
	}
	fmtIdentifier, ok := stateType.X.(*ast.Ident)
	if !ok || !fmtAliases[fmtIdentifier.Name] || fmtIdentifier.Obj != nil {
		return false
	}
	verbType, ok := verbField.Type.(*ast.Ident)
	if !ok || verbType.Name != "rune" {
		return false
	}
	for _, name := range []string{stateField.Names[0].Name, verbField.Names[0].Name, l8CredentialSourceReceiverIdentifier(function)} {
		if name != "" && fmtAliases[name] {
			return false
		}
	}
	if len(function.Body.List) != 1 {
		return false
	}
	expression, ok := function.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 2 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Fprint" {
		return false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok || !fmtAliases[qualifier.Name] || qualifier.Name != fmtIdentifier.Name || qualifier.Obj != nil {
		return false
	}
	destination, ok := call.Args[0].(*ast.Ident)
	if !ok || destination.Name != stateField.Names[0].Name || destination.Obj != stateField.Names[0].Obj {
		return false
	}
	payload, ok := call.Args[1].(*ast.BasicLit)
	if !ok || payload.Kind != token.STRING {
		return false
	}
	literal, err := strconv.Unquote(payload.Value)
	return err == nil && literal == requiredFormat
}

func l8CredentialSourceReceiverIdentifier(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
}

func l8CredentialSourceReceiverName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return l8CredentialSourceReceiverName(typed.X)
	default:
		return ""
	}
}

func l8CredentialSourceSafeMetadataSchemas() map[string]map[string]string {
	return map[string]map[string]string{
		"KeyIdentity": {
			"serial": "int32", "keyType": "string", "ownerUID": "uint32", "ownerGID": "uint32",
			"permissions": "local:KeyPermission", "description": "string",
		},
		"KeyDescriptor": {
			"keyType": "string", "ownerUID": "uint32", "ownerGID": "uint32",
			"permissions": "local:KeyPermission", "description": "string",
		},
		"SourceRegistration": {
			"referenceID": "string", "identity": "local:KeyIdentity",
		},
		"AdmissionGrantRegistration": {
			"authority":          "*" + l8CredentialSourceSandboxruntimeImportPath + ".AuthenticatedWorkerPrincipalAuthority",
			"principal":          l8CredentialSourceSandboxruntimeImportPath + ".AuthenticatedWorkerPrincipal",
			"request":            l8CredentialSourceSandboxruntimeImportPath + ".JobCredentialAdmissionRequest",
			"sourceReferenceIDs": "[]string",
		},
		"RegistryConfig": {
			"authority": "*" + l8CredentialSourceSandboxruntimeImportPath + ".AuthenticatedWorkerPrincipalAuthority",
			"ownerUID":  "uint32",
			"ownerGID":  "uint32",
			"sources":   "[]local:SourceRegistration",
			"grants":    "[]local:AdmissionGrantRegistration",
		},
	}
}

func l8CredentialSourceSemanticSafeMetadata(typedPackage *types.Package) (map[string]bool, []string) {
	validated := map[string]bool{}
	var issues []string
	permission, ok := l8CredentialSourceLocalNamedType(typedPackage, "KeyPermission")
	if !ok || permission.NumMethods() != 0 || !types.Identical(permission.Underlying(), types.Typ[types.Uint32]) {
		issues = append(issues, "KeyPermission is not the exact local uint32 metadata type")
	}
	issues = append(issues, l8CredentialSourceSemanticStructSchemaIssues(typedPackage, l8CredentialSourceSafeMetadataSchemas())...)
	if len(issues) == 0 {
		for typeName := range l8CredentialSourceSafeMetadataSchemas() {
			validated[typeName] = true
		}
	}
	sort.Strings(issues)
	return validated, issues
}

func l8CredentialSourceSemanticStructSchemaIssues(typedPackage *types.Package, schemas map[string]map[string]string) []string {
	var issues []string
	for typeName, schema := range schemas {
		named, ok := l8CredentialSourceLocalNamedType(typedPackage, typeName)
		if !ok {
			issues = append(issues, typeName+" is missing or aliases another type")
			continue
		}
		structure, ok := named.Underlying().(*types.Struct)
		if !ok {
			issues = append(issues, typeName+" is not an exact struct schema")
			continue
		}
		actual := map[string]string{}
		for fieldIndex := 0; fieldIndex < structure.NumFields(); fieldIndex++ {
			field := structure.Field(fieldIndex)
			if field.Anonymous() {
				issues = append(issues, typeName+" contains embedded field "+field.Name())
				continue
			}
			actual[field.Name()] = l8CredentialSourceSemanticTypeString(field.Type(), typedPackage.Path())
		}
		for fieldName, expectedType := range schema {
			actualType, exists := actual[fieldName]
			if !exists {
				issues = append(issues, typeName+" is missing field "+fieldName)
				continue
			}
			if actualType != expectedType {
				issues = append(issues, typeName+" field "+fieldName+" has type "+actualType+", want "+expectedType)
			}
		}
		for fieldName := range actual {
			if _, expected := schema[fieldName]; !expected {
				issues = append(issues, typeName+" contains unexpected field "+fieldName)
			}
		}
		if len(actual) != len(schema) {
			issues = append(issues, typeName+" field count differs from exact schema")
		}
	}
	sort.Strings(issues)
	return issues
}

func l8CredentialSourceSafeMetadataFixture() string {
	return `package credentialsource
import sandboxruntime "github.com/jywlabs/hal/internal/sandboxruntime"
type KeyPermission uint32
type KeyIdentity struct {
	description string
	permissions KeyPermission
	ownerGID uint32
	serial int32
	ownerUID uint32
	keyType string
}
type KeyDescriptor struct {
	description string
	ownerGID uint32
	permissions KeyPermission
	keyType string
	ownerUID uint32
}
type SourceRegistration struct { identity KeyIdentity; referenceID string }
type AdmissionGrantRegistration struct {
	sourceReferenceIDs []string
	request sandboxruntime.JobCredentialAdmissionRequest
	authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	principal sandboxruntime.AuthenticatedWorkerPrincipal
}
type RegistryConfig struct {
	grants []AdmissionGrantRegistration
	ownerGID uint32
	sources []SourceRegistration
	authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	ownerUID uint32
}
`
}

func l8CredentialSourceFixtureSafeMetadata(t *testing.T, source string) (map[string]bool, []string) {
	t.Helper()
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "safe_metadata.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	fallback := &l8CredentialSourceFallbackImporter{primary: importer.Default(), unresolved: map[string]bool{}}
	var typeErrors []error
	typedPackage, _ := (&types.Config{
		Importer:                 fallback,
		IgnoreFuncBodies:         true,
		DisableUnusedImportCheck: true,
		Error:                    func(err error) { typeErrors = append(typeErrors, err) },
	}).Check("l8-safe-metadata-self-test", set, []*ast.File{file}, nil)
	for _, typeErr := range typeErrors {
		if !l8CredentialSourceExpectedUnresolvedTypeError(typeErr, []*ast.File{file}, fallback.unresolved) {
			t.Fatalf("type-check semantic metadata fixture: %v", typeErr)
		}
	}
	if typedPackage == nil {
		t.Fatal("semantic metadata fixture package unavailable")
	}
	return l8CredentialSourceSemanticSafeMetadata(typedPackage)
}
