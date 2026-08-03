package credentialmemory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestL8CredentialMemoryImportAndFormattingBoundaries(t *testing.T) {
	productionFiles, err := l8CredentialMemoryProductionFiles(".")
	if err != nil {
		t.Fatal(err)
	}
	productionSource := strings.Builder{}
	denialMethods := map[string]map[string]bool{
		"LockedMapping": {},
		"borrowedView":  {},
	}
	for _, productionPath := range productionFiles {
		source, err := os.ReadFile(productionPath)
		if err != nil {
			t.Fatal(err)
		}
		productionSource.Write(source)
		productionSource.WriteByte('\n')
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, productionPath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", productionPath, err)
		}
		rootPackage := filepath.Clean(filepath.Dir(productionPath)) == "." && file.Name.Name == "credentialmemory"
		fmtAliases, fmtDotImport := l8CredentialMemoryImportAliases(file, "fmt")
		if fmtDotImport {
			t.Errorf("production credential memory %s uses forbidden dot import of fmt", productionPath)
		}
		hasApprovedFormat := false
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "log" || importPath == "log/slog" ||
				importPath == "net" || strings.HasPrefix(importPath, "net/") ||
				importPath == "os" || importPath == "os/exec" || importPath == "io" || importPath == "io/fs" ||
				importPath == "path/filepath" || importPath == "syscall" ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/cmd") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialdelivery") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialsource") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker") ||
				strings.Contains(importPath, "/internal/provider") || strings.Contains(importPath, "/internal/process") ||
				strings.Contains(importPath, "/internal/workspace") || strings.Contains(importPath, "/internal/sandboxexecution") {
				t.Errorf("production credential memory %s imports forbidden package %q", productionPath, importPath)
			}
		}
		for _, issue := range l8CredentialMemoryForbiddenSelectorIssues(file) {
			t.Errorf("production credential memory %s %s", productionPath, issue)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.StructType:
				for _, field := range typed.Fields.List {
					if len(field.Names) == 0 || !field.Names[0].IsExported() || !l8CredentialMemoryRawType(field.Type) {
						continue
					}
					t.Errorf("production credential memory %s exposes raw live field %s", productionPath, field.Names[0].Name)
				}
			case *ast.FuncDecl:
				receiver := ""
				if typed.Recv != nil {
					receiver = l8CredentialMemoryReceiverName(typed.Recv.List[0].Type)
				}
				for _, issue := range l8CredentialMemoryFmtSelectorIssues(typed, fmtAliases, rootPackage && typed.Name.Name == "Format" && denialMethods[receiver] != nil) {
					t.Errorf("production credential memory %s %s", productionPath, issue)
				}
				if typed.Recv == nil {
					return true
				}
				switch typed.Name.Name {
				case "Unwrap", "MarshalBinary", "GobEncode", "Bytes", "Value":
					t.Errorf("production credential memory %s defines forbidden live-state method %s", productionPath, typed.Name.Name)
				case "String", "GoString", "MarshalJSON", "MarshalText", "Format":
					allowed, ok := denialMethods[receiver]
					if !ok || !rootPackage {
						t.Errorf("production credential memory %s defines formatting/codec method %s on unexpected receiver %s", productionPath, typed.Name.Name, receiver)
						return true
					}
					allowed[typed.Name.Name] = true
					if typed.Name.Name == "Format" {
						hasApprovedFormat = true
					}
				}
			}
			return true
		})
		if len(fmtAliases) != 0 && !hasApprovedFormat {
			t.Errorf("production credential memory %s imports fmt outside an exact approved Format method", productionPath)
		}
	}
	if len(productionFiles) == 0 {
		t.Fatal("L8 credential memory production package does not exist")
	}
	for receiver, found := range denialMethods {
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText", "Format"} {
			if !found[required] {
				t.Errorf("production credential memory %s omits required safe/denial method %s", receiver, required)
			}
		}
	}
	for _, required := range []string{
		"unix.Mmap(", "unix.MAP_ANON", "unix.MAP_PRIVATE", "unix.Mlock(",
		"unix.Munlock(", "unix.Munmap(", "unix.RLIMIT_CORE", "unix.PR_SET_DUMPABLE",
	} {
		if !strings.Contains(productionSource.String(), required) {
			t.Errorf("production credential memory omits direct fail-closed OS marker %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Write(", "os.WriteFile(", "io.Writer", "errors.Join(",
	} {
		if strings.Contains(productionSource.String(), forbidden) {
			t.Errorf("production credential memory contains forbidden raw write/composition marker %q", forbidden)
		}
	}
}

func TestL8CredentialMemoryRecursiveProductionDiscoveryAndAliasGuards(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{
		"root.go":                    "package credentialmemory\ntype rootMarker struct{}\n",
		"nested/live.go":             "package nested\nimport e \"errors\"\nvar _ = e.Join\n",
		"nested/deeper/live.go":      "package deeper\ntype marker struct{}\n",
		"nested/deeper/live_test.go": "package deeper\nimport e \"errors\"\nvar _ = e.Join\n",
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
	productionFiles, err := l8CredentialMemoryProductionFiles(root)
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
	if issues := l8CredentialMemoryForbiddenSelectorIssues(nested); len(issues) != 1 {
		t.Fatalf("nested production alias issues = %v, want one errors.Join denial", issues)
	}

	for _, tt := range []struct {
		name       string
		source     string
		wantIssues int
	}{
		{name: "errors alias", source: "package fixture\nimport privateerrors \"errors\"\nvar _ = privateerrors.Join\n", wantIssues: 1},
		{name: "errors dot import", source: "package fixture\nimport . \"errors\"\nvar _ = Join\n", wantIssues: 1},
		{name: "allowed errors selector", source: "package fixture\nimport e \"errors\"\nvar _ = e.Is\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if issues := l8CredentialMemoryForbiddenSelectorIssues(file); len(issues) != tt.wantIssues {
				t.Fatalf("issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func l8CredentialMemoryProductionFiles(root string) ([]string, error) {
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

func l8CredentialMemoryForbiddenSelectorIssues(file *ast.File) []string {
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
		if localName == "." && importPath == "errors" {
			issues = append(issues, "uses forbidden dot import of errors")
			continue
		}
		aliases[localName] = importPath
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && aliases[identifier.Name] == "errors" && selector.Sel.Name == "Join" {
			issues = append(issues, "uses forbidden raw-error composition errors.Join")
		}
		return true
	})
	return issues
}

func TestL8CredentialMemoryFmtUsageIsRestrictedToExactFormatMethods(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		approved   bool
		wantIssues int
	}{
		{name: "fixed formatter write", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credential-memory>\") }\n", approved: true},
		{name: "generic formatting in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { _ = safeformat.Sprintf(\"%v\", verb) }\n", approved: true, wantIssues: 1},
		{name: "formatting outside formatter", source: "package fixture\nimport safeformat \"fmt\"\nfunc render(value any) string { return safeformat.Sprint(value) }\n", wantIssues: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			aliases, dotImport := l8CredentialMemoryImportAliases(file, "fmt")
			if dotImport {
				t.Fatal("unexpected dot import in fixture")
			}
			var issues []string
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if ok {
					issues = append(issues, l8CredentialMemoryFmtSelectorIssues(function, aliases, tt.approved && function.Name.Name == "Format")...)
				}
			}
			if len(issues) != tt.wantIssues {
				t.Fatalf("fmt selector issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func l8CredentialMemoryImportAliases(file *ast.File, wantedPath string) (map[string]bool, bool) {
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
		case "_":
		default:
			aliases[alias] = true
		}
	}
	return aliases, dotImport
}

func l8CredentialMemoryFmtSelectorIssues(function *ast.FuncDecl, fmtAliases map[string]bool, approvedFormat bool) []string {
	if function.Body == nil {
		return nil
	}
	var issues []string
	ast.Inspect(function.Body, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok || !fmtAliases[identifier.Name] {
			return true
		}
		if !approvedFormat || selector.Sel.Name != "Fprint" {
			issues = append(issues, "uses fmt."+selector.Sel.Name+" outside the narrow fixed-output formatter boundary")
		}
		return true
	})
	return issues
}

func l8CredentialMemoryReceiverName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return l8CredentialMemoryReceiverName(typed.X)
	default:
		return ""
	}
}

func l8CredentialMemoryRawType(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name == "string"
	case *ast.ArrayType:
		identifier, ok := typed.Elt.(*ast.Ident)
		return ok && identifier.Name == "byte"
	case *ast.StarExpr:
		return l8CredentialMemoryRawType(typed.X)
	default:
		return false
	}
}
