package credentialhelper

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialHelperContractImportBoundaries(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	allowedInternal := map[string]bool{
		"github.com/jywlabs/hal/internal/credentialmemory":                                     true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol": true,
	}
	allowedStandard := map[string]bool{
		"context":       true,
		"crypto/sha256": true,
		"errors":        true,
		"fmt":           true,
		"reflect":       true,
		"time":          true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !isCredentialHelperContractFile(entry.Name()) {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, imported := range file.Imports {
			path, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr != nil {
				t.Fatal(unquoteErr)
			}
			if strings.HasPrefix(path, "github.com/jywlabs/hal/internal/") && !allowedInternal[path] {
				t.Errorf("%s imports forbidden internal package %q", entry.Name(), path)
			}
			if !strings.Contains(path, ".") && !allowedStandard[path] {
				t.Errorf("%s imports forbidden standard package %q", entry.Name(), path)
			}
		}
	}
}

func TestCredentialHelperContractImportGuardExcludesFutureImplementationFiles(t *testing.T) {
	for _, name := range []string{"service.go", "policy.go", "core_state.go", "sshrelay.go", "future_linux.go"} {
		if isCredentialHelperContractFile(name) {
			t.Errorf("future implementation file %q is in the D2 foundation allowlist", name)
		}
	}
	for _, name := range []string{"contracts.go", "registry.go", "opaque.go", "format.go", "core_contract_error.go", "core_capabilities.go", "core_requests.go", "core_results.go", "core_accessors.go"} {
		if !isCredentialHelperContractFile(name) {
			t.Errorf("foundation file %q is outside the import guard", name)
		}
	}
}

func isCredentialHelperContractFile(name string) bool {
	switch name {
	case "contracts.go", "registry.go", "opaque.go", "format.go", "core_contract_error.go", "core_capabilities.go", "core_requests.go", "core_results.go", "core_accessors.go":
		return true
	default:
		return false
	}
}

func TestCredentialHelperHasNoGlobalOrSideEffectRegistration(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, declaration := range file.Decls {
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				if value.Name.Name == "init" {
					t.Errorf("%s defines init", path)
				}
				if value.Recv == nil && (value.Name.Name == "Register" || value.Name.Name == "MustRegister") {
					t.Errorf("%s defines forbidden registration function %s", path, value.Name.Name)
				}
				if value.Recv == nil && ast.IsExported(value.Name.Name) && value.Type.Results != nil {
					for _, result := range value.Type.Results.List {
						if strings.Contains(expressionText(result.Type), "ExecBindingCapability") {
							t.Errorf("%s exposes capability minting function %s", path, value.Name.Name)
						}
					}
				}
			case *ast.GenDecl:
				for _, spec := range value.Specs {
					importSpec, ok := spec.(*ast.ImportSpec)
					if ok && importSpec.Name != nil && importSpec.Name.Name == "_" {
						t.Errorf("%s has blank import %s", path, importSpec.Path.Value)
					}
					if ok {
						importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
						if unquoteErr != nil {
							t.Fatal(unquoteErr)
						}
						for _, forbidden := range []string{
							"github.com/jywlabs/hal/cmd",
							"github.com/jywlabs/hal/internal/factory",
							"github.com/jywlabs/hal/internal/sandboxworker",
							"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper/sshrelay",
							"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient",
							"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition",
							"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/sshrelay",
						} {
							if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
								t.Errorf("%s imports forbidden implementation package %q", path, importPath)
							}
						}
					}
					valueSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					if value.Tok == token.VAR && !isSentinelErrorSpec(valueSpec) && !isContractSentinelSpec(valueSpec) {
						t.Errorf("%s declares forbidden mutable package-global state", path)
					}
				}
			}
		}
	}
}

func isContractSentinelSpec(spec *ast.ValueSpec) bool {
	if spec == nil || spec.Type != nil || len(spec.Names) == 0 || len(spec.Values) != len(spec.Names) {
		return false
	}
	for index, name := range spec.Names {
		if !strings.HasPrefix(name.Name, "ErrContract") {
			return false
		}
		literal, ok := spec.Values[index].(*ast.CompositeLit)
		if !ok || expressionText(literal.Type) != "ContractError" || len(literal.Elts) != 1 {
			return false
		}
		field, ok := literal.Elts[0].(*ast.KeyValueExpr)
		if !ok || expressionText(field.Key) != "code" {
			return false
		}
		identifier, ok := field.Value.(*ast.Ident)
		if !ok || !strings.HasPrefix(identifier.Name, "Contract") {
			return false
		}
	}
	return true
}

func TestGlobalRegistrationGuardRejectsMutableStateEvasions(t *testing.T) {
	tests := []struct {
		name        string
		declaration string
		forbidden   bool
	}{
		{name: "sentinel error", declaration: `var ErrSafe = errors.New("safe")`, forbidden: false},
		{name: "entry slice", declaration: `var entries []extensionEntry`, forbidden: true},
		{name: "factory map", declaration: `var factories map[credentialprotocol.ExtensionID]ExtensionFactory`, forbidden: true},
		{name: "default factory", declaration: `var defaultFactory ExtensionFactory`, forbidden: true},
		{name: "registry pointer", declaration: `var registry *ExtensionRegistry`, forbidden: true},
		{name: "registration literal", declaration: `var registration = ExtensionRegistration{}`, forbidden: true},
		{name: "session channel", declaration: `var sessions chan ExtensionSession`, forbidden: true},
		{name: "function", declaration: `var opener = func() {}`, forbidden: true},
		{name: "unrelated mutable scalar", declaration: `var generation uint64`, forbidden: true},
		{name: "fake error registry", declaration: `var ErrRegistry = &ExtensionRegistry{}`, forbidden: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := "package credentialhelper\nimport (\"errors\"; \"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol\")\n" + test.declaration
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			var got bool
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok || general.Tok != token.VAR {
					continue
				}
				for _, spec := range general.Specs {
					if !isSentinelErrorSpec(spec.(*ast.ValueSpec)) {
						got = true
					}
				}
			}
			if got != test.forbidden {
				t.Fatalf("forbidden = %v, want %v", got, test.forbidden)
			}
		})
	}
}

func isSentinelErrorSpec(spec *ast.ValueSpec) bool {
	if spec == nil || spec.Type != nil || len(spec.Names) == 0 || len(spec.Values) != len(spec.Names) {
		return false
	}
	for index, name := range spec.Names {
		if !strings.HasPrefix(name.Name, "Err") || !isErrorsNewCall(spec.Values[index]) {
			return false
		}
	}
	return true
}

func isErrorsNewCall(expression ast.Expr) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "New" || expressionText(selector.X) != "errors" {
		return false
	}
	_, ok = call.Args[0].(*ast.BasicLit)
	return ok
}

func expressionText(expression ast.Expr) string {
	switch value := expression.(type) {
	case nil:
		return ""
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return expressionText(value.X)
	case *ast.ArrayType:
		return expressionText(value.Elt)
	case *ast.SelectorExpr:
		return expressionText(value.X) + "." + value.Sel.Name
	case *ast.CompositeLit:
		if identifier, ok := value.Type.(*ast.Ident); ok {
			return identifier.Name
		}
	case *ast.CallExpr:
		if identifier, ok := value.Fun.(*ast.Ident); ok {
			return identifier.Name
		}
	case *ast.UnaryExpr:
		return expressionText(value.X)
	}
	return ""
}
