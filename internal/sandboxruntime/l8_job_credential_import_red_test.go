package sandboxruntime

import (
	"go/ast"
	"go/parser"
	"go/token"
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
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if allowedLiveFile && (importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "fmt" || importPath == "log" || importPath == "log/slog" ||
				importPath == "os" || importPath == "os/exec" || importPath == "syscall" || importPath == "unsafe" ||
				importPath == "net" || strings.HasPrefix(importPath, "net/") || importPath == "golang.org/x/sys/unix") {
				t.Errorf("neutral job credential contract %s imports forbidden encoder/formatter/live peer-credential package %q", path, importPath)
			}
		}
		if allowedLiveFile {
			for _, issue := range l8JobCredentialRawErrorCompositionIssues(file) {
				t.Errorf("live job credential contract %s %s", path, issue)
			}
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
				if typed.Recv == nil || !allowedLiveFile {
					return true
				}
				receiver := l8ReceiverName(typed.Recv.List[0].Type)
				switch typed.Name.Name {
				case "MarshalBinary", "GobEncode", "Bytes", "Value", "Unwrap":
					t.Errorf("live job credential receiver %s defines forbidden method %s", receiver, typed.Name.Name)
				case "String", "GoString", "MarshalJSON", "MarshalText":
					allowed, ok := denialMethods[receiver]
					if !ok {
						t.Errorf("live job credential receiver %s defines unexpected formatting/codec method %s", receiver, typed.Name.Name)
						return true
					}
					allowed[typed.Name.Name] = true
				}
			}
			return true
		})
	}
	if liveProduction == 0 {
		t.Fatal("L8 neutral job credential production contracts do not exist")
	}
	for receiver, found := range denialMethods {
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText"} {
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

func l8JobCredentialRawErrorCompositionIssues(file *ast.File) []string {
	aliases := map[string]bool{}
	var issues []string
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
