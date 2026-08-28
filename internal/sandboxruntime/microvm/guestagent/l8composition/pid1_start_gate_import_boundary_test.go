package l8composition

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestPID1StartGateExactPureImportBoundary(t *testing.T) {
	t.Parallel()

	const source = "pid1_start_gate.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{
		"bytes",
		"crypto/sha256",
		"errors",
		"fmt",
		"sync",
	}
	if len(file.Imports) != len(allowed) {
		t.Fatalf("imports = %d, want exact %d", len(file.Imports), len(allowed))
	}
	for index, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if imported.Name != nil || path != allowed[index] {
			t.Errorf("import %d = %q, want exact %q without alias", index, path, allowed[index])
		}
	}
}

func TestPID1StartGateHasNoLiveGenericDurableOrMutableGlobalSurface(t *testing.T) {
	t.Parallel()

	const source = "pid1_start_gate.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Name.Name == "init" {
				t.Error("PID1 start gate declares init")
			}
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("PID1 start gate declares generic function %s", typed.Name)
			}
		case *ast.GenDecl:
			if typed.Tok == token.TYPE {
				for _, specification := range typed.Specs {
					typeSpecification := specification.(*ast.TypeSpec)
					if typeSpecification.TypeParams != nil && len(typeSpecification.TypeParams.List) != 0 {
						t.Errorf("PID1 start gate declares generic type %s", typeSpecification.Name)
					}
				}
			}
			if typed.Tok == token.VAR {
				for _, specification := range typed.Specs {
					valueSpecification := specification.(*ast.ValueSpec)
					for _, value := range valueSpecification.Values {
						call, ok := value.(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							t.Error("PID1 start gate has mutable package-global state")
							continue
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						packageName, packageOK := selector.X.(*ast.Ident)
						if !ok || !packageOK || packageName.Name != "errors" || selector.Sel.Name != "New" {
							t.Error("PID1 start gate globals must be stable errors only")
						}
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.MapType:
			t.Errorf("PID1 start gate declares map at %d", typed.Pos())
		case *ast.InterfaceType:
			t.Errorf("PID1 start gate declares interface/any at %d", typed.Pos())
		case *ast.StructType:
			for _, field := range typed.Fields.List {
				if field.Tag != nil {
					t.Errorf("PID1 start gate field has durable tag %s", field.Tag.Value)
				}
				for _, name := range field.Names {
					if name.IsExported() && (name.Name == "Body" || name.Name == "Raw" || name.Name == "Bytes" || name.Name == "FD") {
						t.Errorf("PID1 start gate exposes generic/live field %s", name.Name)
					}
				}
			}
		}
		return true
	})
}

func TestPID1StartGateSourceOwnsDescriptorValidationWithoutProcessConstructors(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "pid1_start_gate.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	validateCalls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		identifier, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch identifier.Name {
		case "ValidateProcessDescriptors":
			validateCalls++
		case "NewHelper", "NewClient", "NewAgent":
			t.Errorf("PID1 start gate constructs process-local object via %s", identifier.Name)
		}
		return true
	})
	if validateCalls != 1 {
		t.Fatalf("ValidateProcessDescriptors calls = %d, want 1", validateCalls)
	}

	source, err := os.ReadFile("pid1_start_gate.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"NewHelper(",
		"NewClient(",
		"NewAgent(",
		"sshrelay",
		"credentialhelper",
		"credentialclient",
		"syscall",
		"unsafe",
		"os/exec",
		"net.Listen",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Errorf("PID1 start gate contains forbidden authority marker %q", forbidden)
		}
	}
}
