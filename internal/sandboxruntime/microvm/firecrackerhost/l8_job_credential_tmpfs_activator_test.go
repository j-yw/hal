package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8JobCredentialFileTmpfsActivatorPublicAPIIsExact(t *testing.T) {
	constructor := reflect.TypeOf(NewProductionL8JobCredentialFileTmpfsActivator)
	wantConstructor := reflect.TypeOf((func(L8JobCredentialFileTmpfsActivatorOptions) (*L8JobCredentialFileTmpfsActivator, error))(nil))
	if constructor != wantConstructor {
		t.Fatalf("NewProductionL8JobCredentialFileTmpfsActivator type = %v, want %v", constructor, wantConstructor)
	}
	activatorType := reflect.TypeOf((*L8JobCredentialFileTmpfsActivator)(nil))
	l8D6AssertExactExportedMethodSet(t, activatorType, map[string]reflect.Type{
		"Format":        reflect.TypeOf((func(*L8JobCredentialFileTmpfsActivator, fmt.State, rune))(nil)),
		"GoString":      reflect.TypeOf((func(*L8JobCredentialFileTmpfsActivator) string)(nil)),
		"MarshalBinary": reflect.TypeOf((func(*L8JobCredentialFileTmpfsActivator) ([]byte, error))(nil)),
		"MarshalJSON":   reflect.TypeOf((func(*L8JobCredentialFileTmpfsActivator) ([]byte, error))(nil)),
		"MarshalText":   reflect.TypeOf((func(*L8JobCredentialFileTmpfsActivator) ([]byte, error))(nil)),
		"Materialize":   reflect.TypeOf((func(*L8JobCredentialFileTmpfsActivator, context.Context, sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest, sandboxruntime.LiveSecretSource) (l8JobCredentialFileHandle, error))(nil)),
		"String":        reflect.TypeOf((func(*L8JobCredentialFileTmpfsActivator) string)(nil)),
	})
	var _ l8JobCredentialFileTmpfsActivator = (*L8JobCredentialFileTmpfsActivator)(nil)
	var _ l8JobCredentialFileHandle = (*l8JobCredentialFileHandleProduction)(nil)
}

func TestL8JobCredentialFileTmpfsActivatorRemainsDefaultOff(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	set := token.NewFileSet()
	callers := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if name == "NewProductionL8JobCredentialFileTmpfsActivator" {
				callers++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers != 0 {
		t.Fatalf("production NewProductionL8JobCredentialFileTmpfsActivator callers = %d, want zero", callers)
	}

	runtimeSource, err := os.ReadFile("l8_job_credential_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(runtimeSource, []byte("NewProductionL8JobCredentialFileTmpfsActivator")) {
		t.Fatal("NewProductionL8JobCredentialRuntime wires the production file-tmpfs activator")
	}
	for _, name := range []string{"adapter.go", "live_driver.go", "l7_live_composition.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"NewProductionL8JobCredentialFileTmpfsActivator", "L8JobCredentialFileTmpfsActivator"} {
			if bytes.Contains(source, []byte(forbidden)) {
				t.Fatalf("%s wires file-tmpfs activator marker %q", name, forbidden)
			}
		}
	}
}

func TestL8JobCredentialFileHandleRedactsAndDeniesSerialization(t *testing.T) {
	canary := "sk_live_tmpfs_canary /private/secret.sock /home/user/.hal/scratch"
	values := []any{
		&L8JobCredentialFileTmpfsActivator{rootDir: "/home/user/.hal/scratch"},
		&l8JobCredentialFileHandleProduction{
			targetPath: "binding-1",
			digest:     canary,
			dir:        "/home/user/.hal/scratch",
			filePath:   "/private/secret.sock",
			owned:      true,
		},
	}
	for _, value := range values {
		if encoded, marshalErr := json.Marshal(value); marshalErr == nil || encoded != nil || !errors.Is(marshalErr, ErrL8JobCredentialRuntimeSerialization) {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, marshalErr)
		}
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
			if rendered != l8JobCredentialFileTmpfsValuePlaceholder {
				t.Fatalf("format %T = %q", value, rendered)
			}
			if strings.Contains(rendered, "sk_live") || strings.Contains(rendered, "/private/") || strings.Contains(rendered, ".hal") {
				t.Fatalf("format leaked canary from %T: %q", value, rendered)
			}
		}
	}
}

func TestL8JobCredentialFileHandleHasNoLiveSecretSourceField(t *testing.T) {
	handleType := reflect.TypeOf(l8JobCredentialFileHandleProduction{})
	sourceType := reflect.TypeOf((*sandboxruntime.LiveSecretSource)(nil)).Elem()
	for index := 0; index < handleType.NumField(); index++ {
		field := handleType.Field(index)
		if field.Type == sourceType || field.Type.Kind() == reflect.Interface && field.Type.Implements(sourceType) {
			t.Fatalf("file handle retains live secret source field %s", field.Name)
		}
	}
	activatorType := reflect.TypeOf(L8JobCredentialFileTmpfsActivator{})
	for index := 0; index < activatorType.NumField(); index++ {
		field := activatorType.Field(index)
		if field.Type == sourceType || field.Type.Kind() == reflect.Interface && field.Type.Implements(sourceType) {
			t.Fatalf("file-tmpfs activator retains live secret source field %s", field.Name)
		}
	}
}
