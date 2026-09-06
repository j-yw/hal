package credentialclient

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFoundationGuardScopeExcludesFutureLifecycleFiles(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"contracts.go",
		"client_policy.go",
		"extension_packet.go",
		"registry.go",
		"ssh_connection.go",
	} {
		if !isFoundationProductionFile(name) {
			t.Errorf("isFoundationProductionFile(%q) = false, want true", name)
		}
	}
	for _, name := range []string{
		"client.go",
		"client_options.go",
		"dispatch.go",
		"transport.go",
		"future_slice.go",
		"registry_test.go",
	} {
		if isFoundationProductionFile(name) {
			t.Errorf("isFoundationProductionFile(%q) = true, want false", name)
		}
	}
}

func TestCredentialClientImportBoundaryAndNoGlobalRegistration(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	const protocolImport = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	const credentialMemoryImport = "github.com/jywlabs/hal/internal/credentialmemory"
	const sessionImport = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	const controlImport = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
	forbiddenStandardLibrary := map[string]bool{
		"net": true, "net/http": true, "net/url": true,
		"os": true, "os/exec": true, "path/filepath": true,
		"syscall": true, "unsafe": true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", path, err)
			}
			if imported.Name != nil && (imported.Name.Name == "_" || imported.Name.Name == ".") {
				t.Errorf("production file %s uses side-effect/implicit import %q", path, name)
			}
			if !isFoundationProductionFile(path) && !isGuestControlContractProductionFile(path) {
				continue
			}
			if name == protocolImport ||
				(name == credentialMemoryImport && (filepath.Base(path) == "ssh_connection.go" || filepath.Base(path) == "control_contract_red.go")) ||
				(name == sessionImport && filepath.Base(path) == "control_contract_red.go") ||
				(name == controlImport && (filepath.Base(path) == "contracts.go" || filepath.Base(path) == "control_contract_red.go")) {
				continue
			}
			standardPackage, standardErr := build.Default.Import(name, ".", build.FindOnly)
			if standardErr != nil || !standardPackage.Goroot || forbiddenStandardLibrary[name] {
				t.Errorf("production file %s imports %q outside the exact credentialclient contract boundary", path, name)
			}
		}
		for _, declaration := range file.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if typed.Name.Name == "init" {
					t.Errorf("production file %s declares init", path)
				}
				if typed.Recv == nil && ast.IsExported(typed.Name.Name) && strings.Contains(strings.ToLower(typed.Name.Name), "register") && typed.Name.Name != "NewExtensionRegistry" {
					t.Errorf("production file %s exposes registration function %s", path, typed.Name.Name)
				}
			case *ast.GenDecl:
				if typed.Tok == token.TYPE && isFoundationProductionFile(path) {
					for _, spec := range typed.Specs {
						typeSpec := spec.(*ast.TypeSpec)
						if typeSpec.Name.Name == "Client" || typeSpec.Name.Name == "ClientOptions" {
							t.Errorf("production file %s implements out-of-scope %s orchestration", path, typeSpec.Name.Name)
						}
					}
					continue
				}
				if typed.Tok != token.VAR {
					continue
				}
				for _, spec := range typed.Specs {
					valueSpec := spec.(*ast.ValueSpec)
					if typeContainsRegistryOrMutableCollection(valueSpec.Type) || valueContainsRegistryOrMutableCollection(valueSpec.Values) {
						t.Errorf("production file %s declares mutable package-global registry/collection", path)
					}
				}
			}
		}
	}
}

func isFoundationProductionFile(name string) bool {
	switch filepath.Base(name) {
	case "contracts.go", "client_policy.go", "extension_packet.go", "registry.go", "ssh_connection.go":
		return true
	default:
		return false
	}
}

func isGuestControlContractProductionFile(name string) bool {
	switch filepath.Base(name) {
	case "contracts.go", "control_contract_red.go":
		return true
	default:
		return false
	}
}

func TestExtensionPacketAndRightsSourceShapeIsClosed(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.TypeSpec:
				protected := typed.Name.Name == "ExtensionPacket" ||
					typed.Name.Name == "SSHAcceptedPacket" ||
					typed.Name.Name == "sshConnectionOwnership" ||
					typed.Name.Name == "sshConnectionView" ||
					strings.Contains(strings.ToLower(typed.Name.Name), "right")
				if !protected {
					return true
				}
				if structure, ok := typed.Type.(*ast.StructType); ok {
					for _, field := range structure.Fields.List {
						for _, name := range field.Names {
							lower := strings.ToLower(name.Name)
							if strings.Contains(lower, "fd") || strings.Contains(lower, "body") || strings.Contains(lower, "payload") {
								t.Errorf("%s contains forbidden field %s", typed.Name.Name, name.Name)
							}
						}
						if isForbiddenRightFieldType(field.Type) {
							t.Errorf("%s contains raw/generic right field type", typed.Name.Name)
						}
					}
				}
			case *ast.FuncDecl:
				lower := strings.ToLower(typed.Name.Name)
				if typed.Recv == nil && ast.IsExported(typed.Name.Name) && (strings.Contains(lower, "right") || strings.Contains(lower, "extensionpacket")) {
					t.Errorf("production API exposes right/packet constructor %s", typed.Name.Name)
				}
				if typed.Recv != nil && ast.IsExported(typed.Name.Name) && (strings.Contains(lower, "fd") || strings.Contains(lower, "right") || strings.Contains(lower, "body") || strings.Contains(lower, "payload")) {
					t.Errorf("production API exposes raw right/body accessor %s", typed.Name.Name)
				}
			}
			return true
		})
	}
}

func typeContainsRegistryOrMutableCollection(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name == "ExtensionRegistry"
	case *ast.ArrayType, *ast.MapType:
		return true
	case *ast.StarExpr:
		return typeContainsRegistryOrMutableCollection(typed.X)
	case nil:
		return false
	default:
		return false
	}
}

func valueContainsRegistryOrMutableCollection(expressions []ast.Expr) bool {
	for _, expression := range expressions {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CompositeLit:
				found = found || typeContainsRegistryOrMutableCollection(typed.Type)
			case *ast.CallExpr:
				if identifier, ok := typed.Fun.(*ast.Ident); ok && (identifier.Name == "make" || identifier.Name == "new") && len(typed.Args) > 0 {
					found = found || typeContainsRegistryOrMutableCollection(typed.Args[0])
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func isForbiddenRightFieldType(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name == "int" || typed.Name == "uintptr" || typed.Name == "any"
	case *ast.ArrayType:
		return typed.Len == nil
	case *ast.MapType, *ast.InterfaceType:
		return true
	case *ast.SelectorExpr:
		return typed.Sel.Name == "Pointer" || typed.Sel.Name == "RawMessage"
	default:
		return false
	}
}
