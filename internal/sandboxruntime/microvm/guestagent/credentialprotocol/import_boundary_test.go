package credentialprotocol

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialProtocolImportBoundary(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	const approvedMemoryContract = "github.com/jywlabs/hal/internal/credentialmemory"
	forbiddenStandardLibrary := map[string]bool{
		"net": true, "net/http": true, "net/url": true,
		"os": true, "os/exec": true, "path/filepath": true,
		"syscall": true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", path, err)
			}
			if imported.Name != nil && imported.Name.Name == "_" {
				t.Errorf("production file %s uses blank import %q", path, name)
				continue
			}
			if name == approvedMemoryContract {
				continue
			}
			standardPackage, standardErr := build.Default.Import(name, ".", build.FindOnly)
			if standardErr != nil || !standardPackage.Goroot || forbiddenStandardLibrary[name] {
				t.Errorf("production file %s imports %q; credentialprotocol permits non-live standard library plus credentialmemory only", path, name)
			}
		}
	}
}

func TestCredentialProtocolCatalogHasNoLiveOrDurableSurface(t *testing.T) {
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
		for _, declaration := range file.Decls {
			global, ok := declaration.(*ast.GenDecl)
			if !ok || global.Tok != token.VAR {
				continue
			}
			for _, spec := range global.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if _, ok := valueSpec.Type.(*ast.ArrayType); ok {
					t.Errorf("production file %s declares mutable package-global slice/array", entry.Name())
				}
				if _, ok := valueSpec.Type.(*ast.MapType); ok {
					t.Errorf("production file %s declares mutable package-global map", entry.Name())
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if typed, ok := node.(*ast.FuncDecl); ok && typed.Name.Name == "init" {
				t.Errorf("production file %s declares init", entry.Name())
			}
			return true
		})
	}

	typeOfDescriptor := reflect.TypeOf(ExtensionDescriptor{})
	for index := 0; index < typeOfDescriptor.NumField(); index++ {
		field := typeOfDescriptor.Field(index)
		if field.Tag != "" {
			t.Errorf("ExtensionDescriptor.%s tag = %q, want none", field.Name, field.Tag)
		}
	}
}

func TestHelperEnvelopeUsesOnlyPureStandardLibraryAndHasNoDurableMethods(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"helper_envelope.go", "helper_primitives.go", "helper_catalog.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", name, err)
			}
			if path != "encoding/binary" && path != "errors" {
				t.Errorf("helper contract file %s imports %q; only pure codec/error packages are allowed", name, path)
			}
		}
	}

	for _, value := range []any{HelperPacketHeader{}} {
		typeOf := reflect.TypeOf(value)
		for methodIndex := 0; methodIndex < typeOf.NumMethod(); methodIndex++ {
			method := typeOf.Method(methodIndex)
			switch method.Name {
			case "MarshalJSON", "UnmarshalJSON", "MarshalText", "UnmarshalText", "String", "GoString":
				t.Errorf("%s exposes durable/formatting method %s", typeOf, method.Name)
			}
		}
		for fieldIndex := 0; fieldIndex < typeOf.NumField(); fieldIndex++ {
			field := typeOf.Field(fieldIndex)
			if field.Tag != "" {
				t.Errorf("%s.%s tag = %q, want none", typeOf, field.Name, field.Tag)
			}
		}
	}
}

func TestHelperEnvelopeExposesNoGenericBodyOwnerOrBodyReturningAPI(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "helper_envelope.go", nil, 0)
	if err != nil {
		t.Fatalf("parse helper_envelope.go: %v", err)
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok != token.TYPE {
				continue
			}
			for _, spec := range typed.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structure.Fields.List {
					if identifier, ok := field.Type.(*ast.Ident); ok && identifier.Name == "string" {
						t.Errorf("helper envelope struct %s has string body-capable field", typeSpec.Name)
					}
					if array, ok := field.Type.(*ast.ArrayType); ok && array.Len == nil {
						t.Errorf("helper envelope struct %s has slice body-capable field", typeSpec.Name)
					}
				}
			}
		case *ast.FuncDecl:
			if typed.Name.Name == "EncodeHelperPacket" || typed.Name.Name == "DecodeHelperPacket" {
				t.Errorf("helper envelope exposes forbidden generic body API %s", typed.Name.Name)
			}
			if typed.Type.Results == nil {
				continue
			}
			for _, result := range typed.Type.Results.List {
				if identifier, ok := result.Type.(*ast.Ident); ok && identifier.Name == "string" {
					t.Errorf("helper envelope API %s returns a body-capable string", typed.Name.Name)
				}
				if array, ok := result.Type.(*ast.ArrayType); ok && array.Len == nil {
					t.Errorf("helper envelope API %s returns a body-capable slice", typed.Name.Name)
				}
			}
		}
	}
}
