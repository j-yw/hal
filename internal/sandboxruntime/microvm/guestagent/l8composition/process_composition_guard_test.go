package l8composition

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestL8D6CompositionSourceOwnsOnlyExplicitProcessLocalAssembly(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("process_composition.go")
	if err != nil {
		t.Fatalf("ReadFile(process_composition.go): %v", err)
	}
	if err := validateL8D6CompositionSource(source); err != nil {
		t.Fatal(err)
	}
}

func TestL8D6CompositionSourceGuardRejectsAuthorityMutations(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("process_composition.go")
	if err != nil {
		t.Fatalf("ReadFile(process_composition.go): %v", err)
	}
	mutations := []struct {
		name string
		old  string
		new  string
	}{
		{name: "derive host from core", old: "Host: options.Host,", new: "Host: options.Core.(credentialhelper.ExtensionHost),"},
		{name: "derive runtime from core", old: "Runtime: options.Runtime,", new: "Runtime: options.Core.(credentialhelper.ServiceRuntime),"},
		{name: "omit helper registration", old: "credentialhelper.NewExtensionRegistry(options.SSH)", new: "credentialhelper.NewExtensionRegistry()"},
		{name: "extra helper registration", old: "credentialhelper.NewExtensionRegistry(options.SSH)", new: "credentialhelper.NewExtensionRegistry(options.SSH, options.SSH)"},
		{name: "omit client registration", old: "credentialclient.NewExtensionRegistry(options.SSH)", new: "credentialclient.NewExtensionRegistry()"},
		{name: "extra client registration", old: "credentialclient.NewExtensionRegistry(options.SSH)", new: "credentialclient.NewExtensionRegistry(options.SSH, options.SSH)"},
		{name: "replace explicit host", old: "Host: options.Host,", new: "Host: nil,"},
		{name: "replace explicit runtime", old: "Runtime: options.Runtime,", new: "Runtime: nil,"},
		{name: "drop client descriptor view", old: "Descriptor: view,", new: "Descriptor: nil,"},
		{name: "default SSH helper", old: "registry, err := credentialhelper.NewExtensionRegistry(options.SSH)", new: "registration, _ := sshrelay.NewHelperExtension(sshrelay.HelperOptions{})\nregistry, err := credentialhelper.NewExtensionRegistry(registration)"},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			mutated := strings.Replace(string(source), mutation.old, mutation.new, 1)
			if mutated == string(source) {
				t.Fatal("mutation did not change production source")
			}
			if err := validateL8D6CompositionSource([]byte(mutated)); err == nil {
				t.Fatal("composition source guard accepted authority mutation")
			}
		})
	}
}

func TestL8D6CredentialClientDescriptorMappingIsDestroyedAndNotRetained(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("../server/credentialclient/client.go")
	if err != nil {
		t.Fatalf("ReadFile(credentialclient/client.go): %v", err)
	}
	if strings.Count(string(source), "destroyErr := mapping.Destroy()") != 1 {
		t.Fatal("credentialclient constructor does not destroy its sole temporary descriptor mapping exactly once")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "client.go", source, 0)
	if err != nil {
		t.Fatalf("parse credentialclient client.go: %v", err)
	}
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.TYPE {
			continue
		}
		for _, specification := range generic.Specs {
			typeSpec := specification.(*ast.TypeSpec)
			if typeSpec.Name.Name != "Client" {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatal("credentialclient.Client is not a struct")
			}
			for _, field := range structure.Fields.List {
				text := l8D6ExpressionText(field.Type)
				if text == "ClientProcessDescriptor" || text == "[]byte" {
					t.Fatalf("credentialclient.Client retains descriptor authority as %s", text)
				}
			}
		}
	}
}

func validateL8D6CompositionSource(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "process_composition.go", source, 0)
	if err != nil {
		return fmt.Errorf("parse D6 composition: %w", err)
	}
	approvedImports := map[string]bool{
		"crypto/sha256": true,
		"errors":        true,
		"fmt":           true,
		"reflect":       true,
		"github.com/jywlabs/hal/internal/credentialmemory":                                          true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper":        true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol":      true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient": true,
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return fmt.Errorf("unquote D6 composition import: %w", err)
		}
		if imported.Name != nil || !approvedImports[path] {
			return fmt.Errorf("D6 composition imports unapproved dependency %q", path)
		}
	}

	var typeAssertion bool
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "init" {
			return fmt.Errorf("D6 composition declares forbidden init")
		}
		if generic, ok := declaration.(*ast.GenDecl); ok && generic.Tok == token.VAR {
			for _, specification := range generic.Specs {
				value := specification.(*ast.ValueSpec)
				if typeContainsMutableCompositionState(value.Type) || valueContainsMutableCompositionState(value.Values) {
					return fmt.Errorf("D6 composition declares mutable package-global state")
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if _, ok := node.(*ast.TypeAssertExpr); ok {
			typeAssertion = true
		}
		return true
	})
	if typeAssertion {
		return fmt.Errorf("D6 composition uses a hidden type assertion")
	}

	normalized := strings.Join(strings.Fields(string(source)), " ")
	for _, required := range []struct {
		text  string
		count int
	}{
		{text: "registry, err := credentialhelper.NewExtensionRegistry(options.SSH)", count: 1},
		{text: "registry, err := credentialclient.NewExtensionRegistry(options.SSH)", count: 1},
		{text: "Core: options.Core,", count: 1},
		{text: "Transport: options.Transport,", count: 2},
		{text: "Policy: options.Policy,", count: 2},
		{text: "Extensions: registry,", count: 2},
		{text: "Host: options.Host,", count: 1},
		{text: "Runtime: options.Runtime,", count: 1},
		{text: "Descriptor: view,", count: 1},
		{text: "credentialhelper.NewService(credentialhelper.ServiceOptions{", count: 1},
		{text: "credentialclient.NewClient(credentialclient.ClientOptions{", count: 1},
	} {
		if strings.Count(normalized, strings.Join(strings.Fields(required.text), " ")) != required.count {
			return fmt.Errorf("D6 composition requires %d exact %q occurrences", required.count, required.text)
		}
	}
	for _, forbidden := range []string{
		"NewHelperExtension",
		"NewClientExtension",
		"credentialhelper/sshrelay",
		"credentialclient/sshrelay",
		"guestagent/credentialhelper/linux",
		"syscall",
		"unsafe",
		"os/exec",
	} {
		if strings.Contains(string(source), forbidden) {
			return fmt.Errorf("D6 composition contains forbidden authority marker %q", forbidden)
		}
	}
	return nil
}

func typeContainsMutableCompositionState(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.ArrayType, *ast.MapType:
		return true
	case *ast.StarExpr:
		return typeContainsMutableCompositionState(typed.X)
	default:
		return false
	}
}

func valueContainsMutableCompositionState(expressions []ast.Expr) bool {
	for _, expression := range expressions {
		mutable := false
		ast.Inspect(expression, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CompositeLit:
				mutable = mutable || typeContainsMutableCompositionState(typed.Type)
			case *ast.CallExpr:
				identifier, ok := typed.Fun.(*ast.Ident)
				if ok && (identifier.Name == "make" || identifier.Name == "new") && len(typed.Args) > 0 {
					mutable = mutable || typeContainsMutableCompositionState(typed.Args[0])
				}
			}
			return !mutable
		})
		if mutable {
			return true
		}
	}
	return false
}

func l8D6ExpressionText(expression ast.Expr) string {
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	if array, ok := expression.(*ast.ArrayType); ok && array.Len == nil {
		return "[]" + l8D6ExpressionText(array.Elt)
	}
	return fmt.Sprintf("%T", expression)
}
