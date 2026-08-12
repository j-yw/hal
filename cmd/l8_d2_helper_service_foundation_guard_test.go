package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D2HelperServiceFoundationGuard(t *testing.T) {
	helperDir := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "credentialhelper")
	protocolDir := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "credentialprotocol")

	for _, typeName := range []string{
		"ExtensionOpenRequest",
		"ExtensionPrepareRequest",
		"ExtensionPrepareResult",
		"ExtensionExecRequest",
		"ExtensionExecResult",
		"ExtensionRenewRequest",
		"ExtensionRevokeRequest",
		"SSHAgentEndpointRequest",
		"SSHAcceptedPublication",
	} {
		assertL8D2StructHasNoExportedFields(t, helperDir, typeName)
	}

	assertL8D2PackageMarkers(t, helperDir, []string{
		"type ServiceOptions struct",
		"type ServiceRuntime interface",
		"type ServiceResult struct",
		"type ServiceBootstrap struct",
		"type ServiceAgentBindingRequest struct",
		"type ServiceJobObservationRequest struct",
		"type ServiceJobObservation struct",
		"type ServiceLoss struct",
		"type CoreExecutionEvent struct",
		"type CoreOutputBody interface",
		"func NewCoreExecutionOutputEvent(",
		"func NewCoreExecutionCompleteEvent(",
		"body.Borrow(ctx",
		"subtle.ConstantTimeCompare(wireSHA[:], sink.bodySHA[:])",
		"ordinal > credentialprotocol.SSHAgentRelayMaxLifetimeConnections",
	})
	assertL8D2PackageMarkers(t, protocolDir, []string{
		"type HelperExecTransactionSeed struct",
		"func NewHelperExecTransactionSeed(",
		"*HelperExecTransactionSeed) Begin(",
		"*HelperExecTransactionSeed) BeginComparison(",
		"*HelperExecTransactionSeed) Close(",
	})
	assertL8D2FoundationRemainsPure(t, []string{
		filepath.Join(helperDir, "extension_values.go"),
		filepath.Join(helperDir, "service_values.go"),
		filepath.Join(helperDir, "core_execution_event.go"),
		filepath.Join(protocolDir, "helper_exec_transaction_seed.go"),
	})
}

func assertL8D2StructHasNoExportedFields(t *testing.T, dir, typeName string) {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(node ast.Node) bool {
				declaration, ok := node.(*ast.TypeSpec)
				if !ok || declaration.Name.Name != typeName {
					return true
				}
				found = true
				structure, ok := declaration.Type.(*ast.StructType)
				if !ok {
					t.Fatalf("%s is not a struct", typeName)
				}
				for _, field := range structure.Fields.List {
					for _, name := range field.Names {
						if name.IsExported() {
							t.Errorf("%s retains exported field %s", typeName, name.Name)
						}
					}
				}
				return false
			})
		}
	}
	if !found {
		t.Errorf("missing %s", typeName)
	}
}

func assertL8D2PackageMarkers(t *testing.T, dir string, markers []string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source.Write(contents)
	}
	for _, marker := range markers {
		if !strings.Contains(source.String(), marker) {
			t.Errorf("missing L8 D2 helper foundation marker %q", marker)
		}
	}
}

func assertL8D2FoundationRemainsPure(t *testing.T, paths []string) {
	t.Helper()
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, contents, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			value := strings.Trim(imported.Path.Value, `"`)
			if value == "os" || value == "net" || value == "syscall" || strings.HasPrefix(value, "golang.org/x/sys") {
				t.Errorf("L8 D2 foundation %s imports live package %q", filepath.Base(path), value)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.GoStmt:
				t.Errorf("L8 D2 foundation %s starts a goroutine", filepath.Base(path))
			case *ast.FuncDecl:
				if value.Name.Name == "NewService" || value.Name.Name == "Serve" {
					t.Errorf("L8 D2 foundation %s implements deferred Service FSM entry %s", filepath.Base(path), value.Name.Name)
				}
			case *ast.SelectorExpr:
				identifier, ok := value.X.(*ast.Ident)
				if ok && identifier.Name == "time" && (value.Sel.Name == "Now" || value.Sel.Name == "After" || value.Sel.Name == "Since" || value.Sel.Name == "Until") {
					t.Errorf("L8 D2 foundation %s reads a clock through time.%s", filepath.Base(path), value.Sel.Name)
				}
			}
			return true
		})
	}
}
