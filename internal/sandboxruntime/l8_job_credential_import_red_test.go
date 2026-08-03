package sandboxruntime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8JobCredentialLiveHandlesCannotFormatOrMarshal(t *testing.T) {
	matches, err := filepath.Glob("job_credential*.go")
	if err != nil {
		t.Fatal(err)
	}
	production := 0
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
		ast.Inspect(file, func(node ast.Node) bool {
			function, ok := node.(*ast.FuncDecl)
			if !ok || function.Recv == nil {
				return true
			}
			receiver := l8ReceiverName(function.Recv.List[0].Type)
			live := strings.Contains(receiver, "Session") || strings.Contains(receiver, "ExecBinding") || strings.Contains(receiver, "LiveSecret") || strings.Contains(receiver, "Borrowed")
			if live {
				switch function.Name.Name {
				case "String", "GoString", "MarshalJSON", "MarshalText", "MarshalBinary", "GobEncode":
					t.Errorf("live job credential receiver %s defines forbidden method %s", receiver, function.Name.Name)
				}
			}
			return true
		})
	}
	if production == 0 {
		t.Fatal("L8 neutral job credential production contracts do not exist")
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
