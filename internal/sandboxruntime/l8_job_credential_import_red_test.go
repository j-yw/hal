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
	matches, err := filepath.Glob("job_credential*.go")
	if err != nil {
		t.Fatal(err)
	}
	production := 0
	denialMethods := map[string]map[string]bool{
		"AuthenticatedWorkerPrincipal": {},
		"JobCredentialLifecycle":       {},
		"JobCredentialActiveProof":     {},
		"JobCredentialCleanupProof":    {},
	}
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		production++
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
			if importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "fmt" || importPath == "log" || importPath == "log/slog" {
				t.Errorf("neutral job credential contract %s imports forbidden encoder/formatter %q", path, importPath)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			function, ok := node.(*ast.FuncDecl)
			if !ok || function.Recv == nil {
				return true
			}
			receiver := l8ReceiverName(function.Recv.List[0].Type)
			switch function.Name.Name {
			case "MarshalBinary", "GobEncode", "Bytes", "Value":
				t.Errorf("live job credential receiver %s defines forbidden method %s", receiver, function.Name.Name)
			case "String", "GoString", "MarshalJSON", "MarshalText":
				allowed, ok := denialMethods[receiver]
				if !ok {
					t.Errorf("live job credential receiver %s defines unexpected formatting/codec method %s", receiver, function.Name.Name)
					return true
				}
				allowed[function.Name.Name] = true
			}
			return true
		})
	}
	if production == 0 {
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
