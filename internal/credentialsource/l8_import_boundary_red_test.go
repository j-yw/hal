package credentialsource

import (
	"fmt"
	"go/ast"
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
	packageTypeExpressions := map[string]map[string]ast.Expr{}
	for _, productionPath := range productionFiles {
		file, err := parser.ParseFile(token.NewFileSet(), productionPath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", productionPath, err)
		}
		packageKey := l8CredentialSourcePackageKey(productionPath, file)
		if packageTypeExpressions[packageKey] == nil {
			packageTypeExpressions[packageKey] = map[string]ast.Expr{}
		}
		for name, expression := range l8CredentialSourceTypeExpressions(file) {
			packageTypeExpressions[packageKey][name] = expression
		}
	}
	typedRawGlobalIssues, err := l8CredentialSourceTypedRawGlobalIssues(productionFiles)
	if err != nil {
		t.Fatalf("type-check production credential source globals: %v", err)
	}
	for _, issue := range typedRawGlobalIssues {
		t.Errorf("production credential source %s", issue)
	}
	rootPackageKey := filepath.Clean(".") + "\x00credentialsource"
	rootTypeExpressions := packageTypeExpressions[rootPackageKey]
	validatedSafeMetadataTypes := map[string]bool{}
	if len(rootTypeExpressions) > 0 {
		for _, issue := range l8CredentialSourceSafeMetadataSchemaIssues(rootTypeExpressions, l8CredentialSourceSafeMetadataSchemas()) {
			t.Errorf("production credential source safe metadata schema %s", issue)
		}
		validatedSafeMetadataTypes = l8CredentialSourceValidatedSafeMetadataTypes(rootTypeExpressions, l8CredentialSourceSafeMetadataSchemas())
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
	for _, productionPath := range productionFiles {
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, productionPath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", productionPath, err)
		}
		typeExpressions := packageTypeExpressions[l8CredentialSourcePackageKey(productionPath, file)]
		rootPackage := filepath.Clean(filepath.Dir(productionPath)) == "." && file.Name.Name == "credentialsource"
		safeMetadataTypes := map[string]bool{}
		if rootPackage {
			safeMetadataTypes = validatedSafeMetadataTypes
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
				importPath == "fmt" || importPath == "log" || importPath == "log/slog" ||
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
		for _, issue := range l8CredentialSourceRawHolderIssues(file, typeExpressions, safeMetadataTypes) {
			t.Errorf("production credential source %s %s", productionPath, issue)
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
				if typed.Recv == nil {
					return true
				}
				receiver := l8CredentialSourceReceiverName(typed.Recv.List[0].Type)
				switch typed.Name.Name {
				case "Unwrap", "MarshalBinary", "GobEncode", "Bytes", "Value":
					t.Errorf("production credential source %s defines forbidden live/raw method %s on %s", productionPath, typed.Name.Name, receiver)
				case "String", "GoString", "MarshalJSON", "MarshalText":
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
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText"} {
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
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			typeExpressions := l8CredentialSourceTypeExpressions(file)
			if issues := l8CredentialSourceRawHolderIssues(file, typeExpressions, nil); len(issues) != tt.wantIssues {
				t.Fatalf("raw holder issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func TestL8CredentialSourceSafeMetadataSchemasAreExactAndOrderIndependent(t *testing.T) {
	file := l8ParseCredentialSourceSafeMetadataFixture(t)
	typeExpressions := l8CredentialSourceTypeExpressions(file)
	schemas := l8CredentialSourceSafeMetadataSchemas()
	if issues := l8CredentialSourceSafeMetadataSchemaIssues(typeExpressions, schemas); len(issues) != 0 {
		t.Fatalf("valid safe metadata schema issues = %v", issues)
	}
	validated := l8CredentialSourceValidatedSafeMetadataTypes(typeExpressions, schemas)
	if len(validated) != len(schemas) {
		t.Fatalf("validated safe metadata types = %v, want every exact schema", validated)
	}
	if issues := l8CredentialSourceRawHolderIssues(file, typeExpressions, validated); len(issues) != 0 {
		t.Fatalf("valid safe metadata raw holder issues = %v", issues)
	}
	packagePath := "l8-safe-metadata-self-test"
	localPackage := types.NewPackage(packagePath, "credentialsource")
	rawStructure := types.NewStruct([]*types.Var{types.NewVar(token.NoPos, localPackage, "retained", types.Typ[types.String])}, nil)
	localSafeType := types.NewNamed(types.NewTypeName(token.NoPos, localPackage, "RegistryConfig", nil), rawStructure, nil)
	if l8CredentialSourceTypedRawType(localSafeType, packagePath, validated, map[types.Type]bool{}) {
		t.Fatal("exact validated local safe metadata did not receive typed global exemption")
	}
	if !l8CredentialSourceTypedRawType(localSafeType, packagePath, nil, map[types.Type]bool{}) {
		t.Fatal("unvalidated local safe metadata name bypassed typed global guard")
	}
	externalPackage := types.NewPackage("external-safe-metadata-self-test", "credentialsource")
	externalLookalike := types.NewNamed(types.NewTypeName(token.NoPos, externalPackage, "RegistryConfig", nil), rawStructure, nil)
	if !l8CredentialSourceTypedRawType(externalLookalike, packagePath, validated, map[types.Type]bool{}) {
		t.Fatal("external safe metadata lookalike bypassed typed global guard")
	}

	for typeName := range schemas {
		for _, mutation := range []struct {
			name   string
			mutate func(*ast.StructType)
		}{
			{name: "missing field", mutate: func(structure *ast.StructType) {
				structure.Fields.List = structure.Fields.List[1:]
			}},
			{name: "extra field", mutate: func(structure *ast.StructType) {
				structure.Fields.List = append(structure.Fields.List, l8CredentialSourceFixtureField("unexpected", ast.NewIdent("bool")))
			}},
			{name: "duplicate field", mutate: func(structure *ast.StructType) {
				first := structure.Fields.List[0]
				structure.Fields.List = append(structure.Fields.List, l8CredentialSourceFixtureField(first.Names[0].Name, first.Type))
			}},
			{name: "unexpected string", mutate: func(structure *ast.StructType) {
				structure.Fields.List = append(structure.Fields.List, l8CredentialSourceFixtureField("retained", ast.NewIdent("string")))
			}},
			{name: "unexpected bytes", mutate: func(structure *ast.StructType) {
				structure.Fields.List = append(structure.Fields.List, l8CredentialSourceFixtureField("retained", &ast.ArrayType{Elt: ast.NewIdent("byte")}))
			}},
			{name: "unexpected raw alias", mutate: func(structure *ast.StructType) {
				structure.Fields.List = append(structure.Fields.List, l8CredentialSourceFixtureField("retained", ast.NewIdent("rawAlias")))
			}},
			{name: "unexpected nested raw state", mutate: func(structure *ast.StructType) {
				structure.Fields.List = append(structure.Fields.List, l8CredentialSourceFixtureField("retained", ast.NewIdent("nestedRaw")))
			}},
			{name: "expected field type alias", mutate: func(structure *ast.StructType) {
				structure.Fields.List[0].Type = ast.NewIdent("safeAlias")
			}},
		} {
			t.Run(typeName+"/"+mutation.name, func(t *testing.T) {
				mutatedFile := l8ParseCredentialSourceSafeMetadataFixture(t)
				typeSpec := l8CredentialSourceFixtureTypeSpec(t, mutatedFile, typeName)
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					t.Fatalf("%s is not a struct", typeName)
				}
				mutation.mutate(structure)
				mutatedTypes := l8CredentialSourceTypeExpressions(mutatedFile)
				issues := l8CredentialSourceSafeMetadataSchemaIssues(mutatedTypes, schemas)
				if len(issues) == 0 {
					t.Fatalf("exact schema accepted %s mutation of %s", mutation.name, typeName)
				}
				if l8CredentialSourceValidatedSafeMetadataTypes(mutatedTypes, schemas)[typeName] {
					t.Fatalf("mutated %s retained safe-metadata exemption", typeName)
				}
			})
		}
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
		{name: "safe constant", source: "package fixture\nconst safeCode = \"credential_source_denied\"\n"},
		{name: "safe explicit sentinel error", source: "package fixture\nimport \"errors\"\nvar errValue error = errors.New(\"credential source unavailable\")\n"},
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
var callback func(uint64) bool
`},
		{name: "function local transient", source: "package fixture\nfunc transient(){ text := \"secret\"; value := make([]byte, 32); _, _ = text, value }\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixturePath := filepath.Join(t.TempDir(), "fixture.go")
			if err := os.WriteFile(fixturePath, []byte(tt.source), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), fixturePath, tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			typeExpressions := l8CredentialSourceTypeExpressions(file)
			issues := l8CredentialSourceRawHolderIssues(file, typeExpressions, nil)
			typedIssues, err := l8CredentialSourceTypedRawGlobalIssues([]string{fixturePath})
			if err != nil {
				t.Fatal(err)
			}
			issues = append(issues, typedIssues...)
			if len(issues) != tt.wantIssues {
				t.Fatalf("raw holder issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
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

func l8CredentialSourceTypeExpressions(file *ast.File) map[string]ast.Expr {
	typeExpressions := map[string]ast.Expr{}
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, spec := range generic.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			typeExpressions[typeSpec.Name.Name] = typeSpec.Type
		}
	}
	return typeExpressions
}

func l8CredentialSourcePackageKey(productionPath string, file *ast.File) string {
	return filepath.Clean(filepath.Dir(productionPath)) + "\x00" + file.Name.Name
}

func l8CredentialSourceRawHolderIssues(file *ast.File, typeExpressions map[string]ast.Expr, safeMetadataTypes map[string]bool) []string {
	var issues []string
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		switch generic.Tok {
		case token.TYPE:
			for _, spec := range generic.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				if safeMetadataTypes[typeSpec.Name.Name] {
					continue
				}
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structure.Fields.List {
					if l8CredentialSourceRawType(field.Type, typeExpressions, safeMetadataTypes, map[string]bool{}) {
						issues = append(issues, "live holder "+typeSpec.Name.Name+" retains raw state")
					}
				}
			}
		}
	}
	return issues
}

func l8CredentialSourceTypedRawGlobalIssues(productionFiles []string) ([]string, error) {
	type packageFiles struct {
		name  string
		paths []string
	}
	groups := map[string]*packageFiles{}
	var groupKeys []string
	for _, productionPath := range productionFiles {
		file, err := parser.ParseFile(token.NewFileSet(), productionPath, nil, parser.PackageClauseOnly)
		if err != nil {
			return nil, fmt.Errorf("parse package declaration: %w", err)
		}
		key := filepath.Clean(filepath.Dir(productionPath)) + "\x00" + file.Name.Name
		if groups[key] == nil {
			groups[key] = &packageFiles{name: file.Name.Name}
			groupKeys = append(groupKeys, key)
		}
		groups[key].paths = append(groups[key].paths, productionPath)
	}
	sort.Strings(groupKeys)

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve credential source package: %w", err)
	}
	workingDir, err = filepath.Abs(workingDir)
	if err != nil {
		return nil, fmt.Errorf("resolve credential source package: %w", err)
	}

	var issues []string
	for groupIndex, key := range groupKeys {
		group := groups[key]
		set := token.NewFileSet()
		var files []*ast.File
		typeExpressions := map[string]ast.Expr{}
		for _, productionPath := range group.paths {
			file, err := parser.ParseFile(set, productionPath, nil, 0)
			if err != nil {
				return nil, fmt.Errorf("parse production package: %w", err)
			}
			files = append(files, file)
			for name, expression := range l8CredentialSourceTypeExpressions(file) {
				typeExpressions[name] = expression
			}
		}

		packagePath := fmt.Sprintf("l8-credential-source-guard/%d", groupIndex)
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
		_, _ = config.Check(packagePath, set, files, info)
		for _, typeErr := range typeErrors {
			if !l8CredentialSourceExpectedUnresolvedTypeError(typeErr, files, fallbackImporter.unresolved) {
				return nil, fmt.Errorf("type-check package declarations: %w", typeErr)
			}
		}

		safeMetadataTypes := map[string]bool{}
		packageDir, err := filepath.Abs(filepath.Dir(group.paths[0]))
		if err != nil {
			return nil, fmt.Errorf("resolve production package: %w", err)
		}
		if filepath.Clean(packageDir) == filepath.Clean(workingDir) && group.name == "credentialsource" {
			safeMetadataTypes = l8CredentialSourceValidatedSafeMetadataTypes(typeExpressions, l8CredentialSourceSafeMetadataSchemas())
		}
		for _, file := range files {
			for _, declaration := range file.Decls {
				generic, ok := declaration.(*ast.GenDecl)
				if !ok || generic.Tok != token.VAR {
					continue
				}
				for _, spec := range generic.Specs {
					valueSpec := spec.(*ast.ValueSpec)
					for _, name := range valueSpec.Names {
						if name.Name == "_" {
							continue
						}
						object, ok := info.Defs[name].(*types.Var)
						if !ok || object.Type() == nil {
							issues = append(issues, "package variable "+name.Name+" could not be analyzed")
							continue
						}
						raw := l8CredentialSourceTypedRawType(object.Type(), packagePath, safeMetadataTypes, map[types.Type]bool{})
						if initializerType, present, analyzed := l8CredentialSourceTypedInitializerType(info, valueSpec, name); present {
							if !analyzed {
								issues = append(issues, "package variable "+name.Name+" initializer could not be analyzed")
								continue
							}
							raw = raw || l8CredentialSourceTypedRawType(initializerType, packagePath, safeMetadataTypes, map[types.Type]bool{})
							if types.Identical(object.Type(), types.Universe.Lookup("error").Type()) &&
								!l8CredentialSourceSafeSentinelErrorInitializer(file, valueSpec, name) {
								raw = true
							}
						}
						if raw {
							issues = append(issues, "package variable "+name.Name+" retains mutable raw state")
						}
					}
				}
			}
		}
	}
	return issues, nil
}

type l8CredentialSourceFallbackImporter struct {
	primary    types.Importer
	unresolved map[string]bool
}

func (fallback *l8CredentialSourceFallbackImporter) Import(importPath string) (*types.Package, error) {
	imported, err := fallback.primary.Import(importPath)
	if err == nil {
		return imported, nil
	}
	fallback.unresolved[importPath] = true
	placeholder := types.NewPackage(importPath, path.Base(importPath))
	placeholder.MarkComplete()
	return placeholder, nil
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
			if strings.Contains(message, "undefined: "+alias) {
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

func l8CredentialSourceTypedRawType(valueType types.Type, packagePath string, safeMetadataTypes map[string]bool, seen map[types.Type]bool) bool {
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
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, seen)
	case *types.Slice:
		if basic, ok := types.Unalias(typed.Elem()).Underlying().(*types.Basic); ok && basic.Kind() == types.Uint8 {
			return true
		}
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, seen)
	case *types.Map:
		return l8CredentialSourceTypedRawType(typed.Key(), packagePath, safeMetadataTypes, seen) ||
			l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, seen)
	case *types.Pointer:
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, seen)
	case *types.Chan:
		return l8CredentialSourceTypedRawType(typed.Elem(), packagePath, safeMetadataTypes, seen)
	case *types.Struct:
		for fieldIndex := 0; fieldIndex < typed.NumFields(); fieldIndex++ {
			if l8CredentialSourceTypedRawType(typed.Field(fieldIndex).Type(), packagePath, safeMetadataTypes, seen) {
				return true
			}
		}
		return false
	case *types.Tuple:
		for valueIndex := 0; valueIndex < typed.Len(); valueIndex++ {
			if l8CredentialSourceTypedRawType(typed.At(valueIndex).Type(), packagePath, safeMetadataTypes, seen) {
				return true
			}
		}
		return false
	case *types.Interface:
		return !types.Identical(typed, types.Universe.Lookup("error").Type().Underlying())
	case *types.Signature:
		return l8CredentialSourceTypedRawType(typed.Params(), packagePath, safeMetadataTypes, seen) ||
			l8CredentialSourceTypedRawType(typed.Results(), packagePath, safeMetadataTypes, seen)
	case *types.Named:
		object := typed.Obj()
		if object != nil && object.Pkg() != nil && object.Pkg().Path() == packagePath && safeMetadataTypes[object.Name()] {
			return false
		}
		return l8CredentialSourceTypedRawType(types.Unalias(typed.Underlying()), packagePath, safeMetadataTypes, seen)
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

func TestL8CredentialSourceRawAliasAndNestedLiveStateDetection(t *testing.T) {
	file := l8ParseCredentialSourceSafeMetadataFixture(t)
	typeExpressions := l8CredentialSourceTypeExpressions(file)
	typeExpressions["rawAlias"] = ast.NewIdent("string")
	typeExpressions["rawBytes"] = &ast.ArrayType{Elt: ast.NewIdent("byte")}
	typeExpressions["nested"] = &ast.StructType{Fields: &ast.FieldList{List: []*ast.Field{
		{Names: []*ast.Ident{ast.NewIdent("payload")}, Type: ast.NewIdent("rawAlias")},
	}}}
	typeExpressions["nestedMap"] = &ast.MapType{Key: ast.NewIdent("string"), Value: ast.NewIdent("rawBytes")}
	typeExpressions["safeWrapper"] = &ast.StructType{Fields: &ast.FieldList{List: []*ast.Field{
		{Names: []*ast.Ident{ast.NewIdent("source")}, Type: ast.NewIdent("SourceRegistration")},
	}}}
	validatedSafeMetadataTypes := l8CredentialSourceValidatedSafeMetadataTypes(typeExpressions, l8CredentialSourceSafeMetadataSchemas())

	for _, name := range []string{"rawAlias", "rawBytes", "nested", "nestedMap"} {
		if !l8CredentialSourceRawType(ast.NewIdent(name), typeExpressions, validatedSafeMetadataTypes, map[string]bool{}) {
			t.Errorf("raw live state detector permits alias/nested bypass %s", name)
		}
	}
	for _, expression := range []ast.Expr{ast.NewIdent("SourceRegistration"), ast.NewIdent("safeWrapper")} {
		if l8CredentialSourceRawType(expression, typeExpressions, validatedSafeMetadataTypes, map[string]bool{}) {
			t.Errorf("raw live state detector rejects sealed safe metadata %T", expression)
		}
	}
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
			"permissions": "KeyPermission", "description": "string",
		},
		"KeyDescriptor": {
			"keyType": "string", "ownerUID": "uint32", "ownerGID": "uint32",
			"permissions": "KeyPermission", "description": "string",
		},
		"SourceRegistration": {
			"referenceID": "string", "identity": "KeyIdentity",
		},
		"AdmissionGrantRegistration": {
			"authority":          "*sandboxruntime.AuthenticatedWorkerPrincipalAuthority",
			"principal":          "sandboxruntime.AuthenticatedWorkerPrincipal",
			"request":            "sandboxruntime.JobCredentialAdmissionRequest",
			"sourceReferenceIDs": "[]string",
		},
		"RegistryConfig": {
			"authority": "*sandboxruntime.AuthenticatedWorkerPrincipalAuthority",
			"ownerUID":  "uint32",
			"ownerGID":  "uint32",
			"sources":   "[]SourceRegistration",
			"grants":    "[]AdmissionGrantRegistration",
		},
	}
}

func l8CredentialSourceSafeMetadataSchemaIssues(typeExpressions map[string]ast.Expr, schemas map[string]map[string]string) []string {
	var issues []string
	for typeName, schema := range schemas {
		expression, ok := typeExpressions[typeName]
		if !ok {
			issues = append(issues, typeName+" is missing")
			continue
		}
		structure, ok := expression.(*ast.StructType)
		if !ok {
			issues = append(issues, typeName+" is not an exact struct schema")
			continue
		}
		actual := map[string]string{}
		for _, field := range structure.Fields.List {
			if len(field.Names) != 1 {
				issues = append(issues, typeName+" contains embedded or grouped fields")
				continue
			}
			fieldName := field.Names[0].Name
			if _, exists := actual[fieldName]; exists {
				issues = append(issues, typeName+" duplicates field "+fieldName)
				continue
			}
			actual[fieldName] = l8CredentialSourceTypeString(field.Type)
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
	return issues
}

func l8CredentialSourceValidatedSafeMetadataTypes(typeExpressions map[string]ast.Expr, schemas map[string]map[string]string) map[string]bool {
	validated := map[string]bool{}
	for typeName, schema := range schemas {
		if len(l8CredentialSourceSafeMetadataSchemaIssues(typeExpressions, map[string]map[string]string{typeName: schema})) == 0 {
			validated[typeName] = true
		}
	}
	return validated
}

func l8CredentialSourceTypeString(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return l8CredentialSourceTypeString(typed.X) + "." + typed.Sel.Name
	case *ast.StarExpr:
		return "*" + l8CredentialSourceTypeString(typed.X)
	case *ast.ArrayType:
		if typed.Len != nil {
			return "[array]" + l8CredentialSourceTypeString(typed.Elt)
		}
		return "[]" + l8CredentialSourceTypeString(typed.Elt)
	case *ast.MapType:
		return "map[" + l8CredentialSourceTypeString(typed.Key) + "]" + l8CredentialSourceTypeString(typed.Value)
	case *ast.ParenExpr:
		return l8CredentialSourceTypeString(typed.X)
	default:
		return "<unexpected>"
	}
}

func l8ParseCredentialSourceSafeMetadataFixture(t *testing.T) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "safe_metadata.go", `package credentialsource
import sandboxruntime "github.com/jywlabs/hal/internal/sandboxruntime"
type KeyPermission uint32
type safeAlias = int32
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
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func l8CredentialSourceFixtureTypeSpec(t *testing.T, file *ast.File, typeName string) *ast.TypeSpec {
	t.Helper()
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, spec := range generic.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			if typeSpec.Name.Name == typeName {
				return typeSpec
			}
		}
	}
	t.Fatalf("fixture type %s not found", typeName)
	return nil
}

func l8CredentialSourceFixtureField(name string, expression ast.Expr) *ast.Field {
	return &ast.Field{Names: []*ast.Ident{ast.NewIdent(name)}, Type: expression}
}

func l8CredentialSourceRawType(expression ast.Expr, typeExpressions map[string]ast.Expr, safeMetadataTypes map[string]bool, seen map[string]bool) bool {
	switch typed := expression.(type) {
	case *ast.Ident:
		if typed.Name == "string" {
			return true
		}
		if safeMetadataTypes[typed.Name] || seen[typed.Name] {
			return false
		}
		definition, ok := typeExpressions[typed.Name]
		if !ok {
			return false
		}
		seen[typed.Name] = true
		return l8CredentialSourceRawType(definition, typeExpressions, safeMetadataTypes, seen)
	case *ast.ArrayType:
		identifier, ok := typed.Elt.(*ast.Ident)
		if ok && identifier.Name == "byte" {
			return true
		}
		return l8CredentialSourceRawType(typed.Elt, typeExpressions, safeMetadataTypes, seen)
	case *ast.StarExpr:
		return l8CredentialSourceRawType(typed.X, typeExpressions, safeMetadataTypes, seen)
	case *ast.MapType:
		return l8CredentialSourceRawType(typed.Key, typeExpressions, safeMetadataTypes, seen) || l8CredentialSourceRawType(typed.Value, typeExpressions, safeMetadataTypes, seen)
	case *ast.StructType:
		for _, field := range typed.Fields.List {
			if l8CredentialSourceRawType(field.Type, typeExpressions, safeMetadataTypes, seen) {
				return true
			}
		}
		return false
	case *ast.ParenExpr:
		return l8CredentialSourceRawType(typed.X, typeExpressions, safeMetadataTypes, seen)
	default:
		return false
	}
}
