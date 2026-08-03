package sandboxruntime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8JobCredentialLiveHandlesUseOnlySafeFormattingAndDenialCodecs(t *testing.T) {
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	liveProduction := 0
	denialMethods := map[string]map[string]bool{
		"AuthenticatedWorkerPrincipalAuthority": {},
		"authenticatedWorkerPrincipal":          {},
		"JobCredentialLifecycle":                {},
		"JobCredentialActiveProof":              {},
		"JobCredentialCleanupProof":             {},
	}
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		allowedLiveFile := strings.HasPrefix(filepath.Base(path), "job_credential")
		if allowedLiveFile {
			liveProduction++
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		fmtAliases, fmtDotImport := l8JobCredentialImportAliases(file, "fmt")
		if allowedLiveFile && fmtDotImport {
			t.Errorf("neutral job credential contract %s uses forbidden dot import of fmt", path)
		}
		hasApprovedFormat := false
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if allowedLiveFile && (importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "log" || importPath == "log/slog" ||
				importPath == "os" || importPath == "os/exec" || importPath == "syscall" || importPath == "unsafe" ||
				importPath == "net" || strings.HasPrefix(importPath, "net/") || importPath == "golang.org/x/sys/unix") {
				t.Errorf("neutral job credential contract %s imports forbidden encoder/formatter/live peer-credential package %q", path, importPath)
			}
		}
		for _, issue := range l8JobCredentialRawErrorCompositionIssues(file) {
			t.Errorf("sandboxruntime production file %s %s", path, issue)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.TypeSpec:
				if l8CredentialLiveDeclarationName(typed.Name.Name) && !allowedLiveFile {
					t.Errorf("live job credential type %s bypasses allowed job_credential files in %s", typed.Name.Name, path)
				}
			case *ast.FuncDecl:
				if typed.Name.Name == "NewAuthenticatedWorkerPrincipal" {
					t.Errorf("%s exposes forbidden direct principal minting constructor", path)
				}
				if l8CredentialLiveDeclarationName(typed.Name.Name) && !allowedLiveFile {
					t.Errorf("live job credential function %s bypasses allowed job_credential files in %s", typed.Name.Name, path)
				}
				receiver := ""
				if typed.Recv != nil {
					receiver = l8ReceiverName(typed.Recv.List[0].Type)
				}
				approvedFormat := allowedLiveFile && typed.Name.Name == "Format" && denialMethods[receiver] != nil
				if allowedLiveFile {
					for _, issue := range l8JobCredentialFmtSelectorIssues(typed, fmtAliases, approvedFormat) {
						t.Errorf("neutral job credential contract %s %s", path, issue)
					}
				}
				if typed.Recv == nil || !allowedLiveFile {
					return true
				}
				switch typed.Name.Name {
				case "MarshalBinary", "GobEncode", "Bytes", "Value", "Unwrap":
					t.Errorf("live job credential receiver %s defines forbidden method %s", receiver, typed.Name.Name)
				case "String", "GoString", "MarshalJSON", "MarshalText", "Format":
					allowed, ok := denialMethods[receiver]
					if !ok {
						t.Errorf("live job credential receiver %s defines unexpected formatting/codec method %s", receiver, typed.Name.Name)
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
		if allowedLiveFile && len(fmtAliases) != 0 && !hasApprovedFormat {
			t.Errorf("neutral job credential contract %s imports fmt outside an exact approved Format method", path)
		}
	}
	if liveProduction == 0 {
		t.Fatal("L8 neutral job credential production contracts do not exist")
	}
	for receiver, found := range denialMethods {
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText", "Format"} {
			if !found[required] {
				t.Errorf("live job credential receiver %s omits safe/denial method %s", receiver, required)
			}
		}
	}
}

func TestL8JobCredentialRawErrorCompositionGuardIsAliasAware(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		wantIssues int
	}{
		{name: "default join", source: "package fixture\nimport \"errors\"\nvar _ = errors.Join\n", wantIssues: 1},
		{name: "aliased join", source: "package fixture\nimport stableerrors \"errors\"\nvar _ = stableerrors.Join\n", wantIssues: 1},
		{name: "dot import rejected", source: "package fixture\nimport . \"errors\"\nvar _ = Join\n", wantIssues: 1},
		{name: "default is allowed", source: "package fixture\nimport \"errors\"\nvar _ = errors.Is\n"},
		{name: "aliased is allowed", source: "package fixture\nimport stableerrors \"errors\"\nvar _ = stableerrors.Is\n"},
		{name: "unrelated join allowed", source: "package fixture\ntype helper struct{}\nfunc (helper) Join() {}\nvar value helper\nvar _ = value.Join\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if issues := l8JobCredentialRawErrorCompositionIssues(file); len(issues) != tt.wantIssues {
				t.Fatalf("raw error composition issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func TestL8JobCredentialRawErrorCompositionGuardCoversCrossFileHelpers(t *testing.T) {
	for _, tt := range []struct {
		name       string
		files      map[string]string
		wantIssues int
	}{
		{
			name: "generic helper joins raw causes",
			files: map[string]string{
				"job_credential_live.go": "package sandboxruntime\nfunc denyLive() error { return composeCredentialErrors() }\n",
				"errors.go":              "package sandboxruntime\nimport stableerrors \"errors\"\nfunc composeCredentialErrors() error { return stableerrors.Join() }\n",
			},
			wantIssues: 1,
		},
		{
			name: "legitimate helpers remain available",
			files: map[string]string{
				"job_credential_live.go": "package sandboxruntime\nfunc inspectLive(err error) bool { return inspectCredentialError(err) }\n",
				"helpers.go":             "package sandboxruntime\nimport (\"errors\"; \"strings\")\nfunc inspectCredentialError(err error) bool { _ = strings.Join([]string{\"safe\"}, \",\"); return errors.Is(err, nil) }\n",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var files []*ast.File
			for name, source := range tt.files {
				file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, file)
			}
			if issues := l8JobCredentialRawErrorCompositionIssues(files...); len(issues) != tt.wantIssues {
				t.Fatalf("package-wide raw error composition issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func l8JobCredentialRawErrorCompositionIssues(files ...*ast.File) []string {
	var issues []string
	for _, file := range files {
		aliases := map[string]bool{}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil || importPath != "errors" {
				continue
			}
			alias := "errors"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias == "." {
				issues = append(issues, "uses forbidden dot import of errors")
				continue
			}
			if alias != "_" {
				aliases[alias] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Join" {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && aliases[identifier.Name] {
				issues = append(issues, "uses forbidden raw-error composition errors.Join")
			}
			return true
		})
	}
	return issues
}

func TestL8JobCredentialFmtUsageIsRestrictedToExactFormatMethods(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		approved   bool
		wantIssues int
	}{
		{name: "fixed formatter write", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<job-credential>\") }\n", approved: true},
		{name: "generic formatting in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { _ = safeformat.Sprintf(\"%v\", verb) }\n", approved: true, wantIssues: 1},
		{name: "formatting outside formatter", source: "package fixture\nimport safeformat \"fmt\"\nfunc render(value any) string { return safeformat.Sprint(value) }\n", wantIssues: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			aliases, dotImport := l8JobCredentialImportAliases(file, "fmt")
			if dotImport {
				t.Fatal("unexpected dot import in fixture")
			}
			var issues []string
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if ok {
					issues = append(issues, l8JobCredentialFmtSelectorIssues(function, aliases, tt.approved && function.Name.Name == "Format")...)
				}
			}
			if len(issues) != tt.wantIssues {
				t.Fatalf("fmt selector issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func l8JobCredentialImportAliases(file *ast.File, wantedPath string) (map[string]bool, bool) {
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

func l8JobCredentialFmtSelectorIssues(function *ast.FuncDecl, fmtAliases map[string]bool, approvedFormat bool) []string {
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

func l8CredentialLiveDeclarationName(name string) bool {
	return strings.HasPrefix(name, "JobCredential") ||
		strings.Contains(name, "AuthenticatedWorkerPrincipal") ||
		strings.Contains(name, "CredentialAdmission") ||
		strings.HasPrefix(name, "AuthorizedCredential") ||
		name == "LiveSecretSource" ||
		strings.HasPrefix(name, "ValidateJobCredential") ||
		strings.HasPrefix(name, "NewJobCredential")
}

func l8ReceiverName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return l8ReceiverName(value.X)
	case *ast.IndexExpr:
		return l8ReceiverName(value.X)
	case *ast.IndexListExpr:
		return l8ReceiverName(value.X)
	default:
		return ""
	}
}
