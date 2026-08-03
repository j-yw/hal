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
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				identifier, ok := typed.X.(*ast.Ident)
				if ok && identifier.Name == "errors" && typed.Sel.Name == "Join" && allowedLiveFile {
					t.Errorf("live job credential contract %s uses forbidden raw-error composition errors.Join", path)
				}
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
