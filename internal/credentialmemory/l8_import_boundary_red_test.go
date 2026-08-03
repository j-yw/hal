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
	formatLiterals := l8CredentialMemoryFormatLiterals()
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
				requiredFormat := ""
				if rootPackage && typed.Name.Name == "Format" && denialMethods[receiver] != nil {
					requiredFormat = formatLiterals[receiver]
				}
				for _, issue := range l8CredentialMemoryFmtSelectorIssues(typed, fmtAliases, requiredFormat) {
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
	for receiver, requiredFormat := range l8CredentialMemoryFormatLiterals() {
		t.Run("exact "+receiver, func(t *testing.T) {
			source := "package fixture\nimport safeformat \"fmt\"\ntype " + receiver + " struct{}\nfunc (" + receiver + ") Format(state safeformat.State, verb rune) { safeformat.Fprint(state, " + strconv.Quote(requiredFormat) + ") }\n"
			l8CredentialMemoryAssertFmtFixture(t, source, requiredFormat, false, false)
		})
	}

	for _, tt := range []struct {
		name           string
		source         string
		requiredFormat string
		wantDotImport  bool
	}{
		{name: "generic formatting in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprintf(state, \"%v\", verb) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "sprint in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { _ = safeformat.Sprint(verb) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "formatting outside formatter", source: "package fixture\nimport safeformat \"fmt\"\nfunc render(value any) string { return safeformat.Sprint(value) }\n"},
		{name: "wrong fixed literal", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialmemory.borrowedView>\") }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "package payload", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, safeformat.Stringer(nil)) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "captured payload", source: "package fixture\nimport safeformat \"fmt\"\nvar captured = \"raw\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, captured) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "raw identifier payload", source: "package fixture\nimport safeformat \"fmt\"\nvar rawIdentifier any\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, rawIdentifier) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "helper payload", source: "package fixture\nimport safeformat \"fmt\"\nfunc fixed() string { return \"fixed\" }\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, fixed()) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "receiver payload", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (mapping LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, mapping) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "wrong destination", source: "package fixture\nimport safeformat \"fmt\"\nvar other safeformat.State\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(other, \"<credentialmemory.LockedMapping>\") }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "extra argument", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialmemory.LockedMapping>\", verb) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "variadic argument", source: "package fixture\nimport safeformat \"fmt\"\nvar parts []any\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, parts...) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "concatenated payload", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialmemory.\" + \"LockedMapping>\") }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "multiple calls", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialmemory.LockedMapping>\"); safeformat.Fprint(state, \"<credentialmemory.LockedMapping>\") }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "import alias shadowed by receiver", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (safeformat LockedMapping) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<credentialmemory.LockedMapping>\") }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "state shadowed in closure", source: "package fixture\nimport safeformat \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state safeformat.State, verb rune) { func(state safeformat.State) { safeformat.Fprint(state, \"<credentialmemory.LockedMapping>\") }(state) }\n", requiredFormat: "<credentialmemory.LockedMapping>"},
		{name: "dot import", source: "package fixture\nimport . \"fmt\"\ntype LockedMapping struct{}\nfunc (LockedMapping) Format(state State, verb rune) { Fprint(state, \"<credentialmemory.LockedMapping>\") }\n", requiredFormat: "<credentialmemory.LockedMapping>", wantDotImport: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l8CredentialMemoryAssertFmtFixture(t, tt.source, tt.requiredFormat, tt.wantDotImport, true)
		})
	}
}

func l8CredentialMemoryAssertFmtFixture(t *testing.T, source, requiredFormat string, wantDotImport, wantIssue bool) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliases, dotImport := l8CredentialMemoryImportAliases(file, "fmt")
	if dotImport != wantDotImport {
		t.Fatalf("fmt dot import = %t, want %t", dotImport, wantDotImport)
	}
	var issues []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok {
			approved := ""
			if function.Name.Name == "Format" {
				approved = requiredFormat
			}
			issues = append(issues, l8CredentialMemoryFmtSelectorIssues(function, aliases, approved)...)
		}
	}
	if wantIssue == (len(issues) == 0 && !dotImport) {
		t.Fatalf("fmt issues = %v, dot import = %t, want issue %t", issues, dotImport, wantIssue)
	}
}

func l8CredentialMemoryFormatLiterals() map[string]string {
	return map[string]string{
		"LockedMapping": "<credentialmemory.LockedMapping>",
		"borrowedView":  "<credentialmemory.borrowedView>",
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

func l8CredentialMemoryFmtSelectorIssues(function *ast.FuncDecl, fmtAliases map[string]bool, requiredFormat string) []string {
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
		if requiredFormat == "" {
			issues = append(issues, "uses fmt."+selector.Sel.Name+" outside the narrow fixed-output formatter boundary")
		}
		return true
	})
	if requiredFormat != "" && !l8CredentialMemoryExactFormatMethod(function, fmtAliases, requiredFormat) {
		issues = append(issues, "Format method is not the exact single fixed-literal fmt.Fprint boundary")
	}
	return issues
}

func l8CredentialMemoryExactFormatMethod(function *ast.FuncDecl, fmtAliases map[string]bool, requiredFormat string) bool {
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
	if !ok || !fmtAliases[fmtIdentifier.Name] {
		return false
	}
	verbType, ok := verbField.Type.(*ast.Ident)
	if !ok || verbType.Name != "rune" {
		return false
	}
	for _, name := range []string{stateField.Names[0].Name, verbField.Names[0].Name, l8CredentialMemoryReceiverIdentifier(function)} {
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
	if !ok || !fmtAliases[qualifier.Name] || qualifier.Obj != nil {
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

func l8CredentialMemoryReceiverIdentifier(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
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
