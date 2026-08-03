package credentialsource

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

func TestL8CredentialSourceImportAndIngressBoundaries(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	production := 0
	foundCredentialMemory := false
	foundDirectKeyctl := false
	productionSource := strings.Builder{}
	typeExpressions := map[string]ast.Expr{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, declaration := range file.Decls {
			generic, ok := declaration.(*ast.GenDecl)
			if !ok || generic.Tok != token.TYPE {
				continue
			}
			for _, spec := range generic.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				typeExpressions[typeSpec.Name.Name] = typeSpec.Type
			}
		}
	}
	denialMethods := map[string]map[string]bool{
		"Registry":                   {},
		"RegistryConfig":             {},
		"SourceRegistration":         {},
		"AdmissionGrantRegistration": {},
		"KeyIdentity":                {},
		"KeyDescriptor":              {},
		"registryAuthorization":      {},
		"keyringLiveSecretSource":    {},
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		production++
		path := entry.Name()
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", path, err)
			}
			forbidden := importPath == "os" || importPath == "os/exec" || importPath == "io/ioutil" || importPath == "io/fs" || importPath == "path/filepath" ||
				importPath == "bytes" || importPath == "bufio" ||
				importPath == "net" || strings.HasPrefix(importPath, "net/") || importPath == "syscall" || importPath == "unsafe" ||
				importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "fmt" || importPath == "log" || importPath == "log/slog" ||
				strings.Contains(importPath, "/cmd") || strings.Contains(importPath, "/internal/sandboxworker") ||
				(strings.Contains(importPath, "/internal/sandboxruntime/") && importPath != "github.com/jywlabs/hal/internal/sandboxruntime") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
				strings.Contains(importPath, "credentialdelivery") || strings.Contains(importPath, "provider") ||
				strings.Contains(importPath, "process") || strings.Contains(importPath, "workspace") || strings.Contains(importPath, "sandboxexecution")
			if forbidden {
				t.Errorf("production credential source %s imports forbidden ingress %q", path, importPath)
			}
			if importPath == "github.com/jywlabs/hal/internal/credentialmemory" {
				foundCredentialMemory = true
			}
			if importPath == "golang.org/x/sys/unix" {
				foundDirectKeyctl = true
			}
		}
		source, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		productionSource.Write(source)
		productionSource.WriteByte('\n')
		for _, marker := range []string{
			"os.Getenv(", "os.LookupEnv(", "os.ReadFile(", "exec.Command(", "exec.CommandContext(",
			"io.ReadAll(", "bytes.Buffer", "strings.Builder", "ResolvedRunSecret", "SecretBroker", "Value string", "json.Marshal(", "errors.Join(",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production credential source %s contains forbidden ingress/marshal marker %q", path, marker)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				identifier, ok := typed.X.(*ast.Ident)
				if !ok || identifier.Name != "unix" {
					return true
				}
				allowedUnix := map[string]bool{
					"KeyctlBuffer": true, "KEYCTL_DESCRIBE": true, "KEYCTL_READ": true,
					"ENOKEY": true, "EKEYEXPIRED": true, "EKEYREVOKED": true,
					"EACCES": true, "EPERM": true, "EINVAL": true,
				}
				if !allowedUnix[typed.Sel.Name] {
					t.Errorf("production credential source %s uses unapproved unix selector %s", path, typed.Sel.Name)
				}
			case *ast.TypeSpec:
				structure, ok := typed.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range structure.Fields.List {
					if len(field.Names) == 0 {
						continue
					}
					if field.Names[0].IsExported() {
						t.Errorf("production credential source %s type %s exposes live/config field %s", path, typed.Name.Name, field.Names[0].Name)
					}
					if (typed.Name.Name == "keyringLiveSecretSource" || strings.Contains(typed.Name.Name, "Sink")) && l8CredentialSourceRawType(field.Type, typeExpressions, map[string]bool{}) {
						t.Errorf("production credential source %s live source/sink %s retains raw byte/string field %s", path, typed.Name.Name, field.Names[0].Name)
					}
				}
			case *ast.FuncDecl:
				if typed.Recv == nil {
					return true
				}
				receiver := l8CredentialSourceReceiverName(typed.Recv.List[0].Type)
				switch typed.Name.Name {
				case "Unwrap", "MarshalBinary", "GobEncode", "Bytes", "Value":
					t.Errorf("production credential source %s defines forbidden live/raw method %s on %s", path, typed.Name.Name, receiver)
				case "String", "GoString", "MarshalJSON", "MarshalText":
					allowed, ok := denialMethods[receiver]
					if !ok {
						t.Errorf("production credential source %s defines formatting/codec method %s on unexpected receiver %s", path, typed.Name.Name, receiver)
						return true
					}
					allowed[typed.Name.Name] = true
				}
			}
			return true
		})
	}
	if production == 0 {
		t.Fatal("L8 credential source production package does not exist")
	}
	if !foundCredentialMemory {
		t.Fatal("L8 credential source does not use the owned credentialmemory boundary")
	}
	if !foundDirectKeyctl {
		t.Fatal("L8 credential source does not use direct Linux keyctl syscalls")
	}
	for receiver, found := range denialMethods {
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText"} {
			if !found[required] {
				t.Errorf("production credential source %s omits safe/denial method %s", receiver, required)
			}
		}
	}
	for _, required := range []string{"unix.KeyctlBuffer(", "unix.KEYCTL_DESCRIBE", "unix.KEYCTL_READ"} {
		if !strings.Contains(productionSource.String(), required) {
			t.Errorf("L8 credential source omits direct keyctl read marker %q", required)
		}
	}
}

func TestL8CredentialSourceRawAliasAndNestedLiveStateDetection(t *testing.T) {
	typeExpressions := map[string]ast.Expr{
		"rawAlias": ast.NewIdent("string"),
		"rawBytes": &ast.ArrayType{Elt: ast.NewIdent("byte")},
		"nested": &ast.StructType{Fields: &ast.FieldList{List: []*ast.Field{
			{Names: []*ast.Ident{ast.NewIdent("payload")}, Type: ast.NewIdent("rawAlias")},
		}}},
		"nestedMap": &ast.MapType{Key: ast.NewIdent("string"), Value: ast.NewIdent("rawBytes")},
		"safeWrapper": &ast.StructType{Fields: &ast.FieldList{List: []*ast.Field{
			{Names: []*ast.Ident{ast.NewIdent("source")}, Type: ast.NewIdent("SourceRegistration")},
		}}},
	}

	for _, name := range []string{"rawAlias", "rawBytes", "nested", "nestedMap"} {
		if !l8CredentialSourceRawType(ast.NewIdent(name), typeExpressions, map[string]bool{}) {
			t.Errorf("raw live state detector permits alias/nested bypass %s", name)
		}
	}
	for _, expression := range []ast.Expr{ast.NewIdent("SourceRegistration"), ast.NewIdent("safeWrapper")} {
		if l8CredentialSourceRawType(expression, typeExpressions, map[string]bool{}) {
			t.Errorf("raw live state detector rejects sealed safe metadata %T", expression)
		}
	}
}

func l8CredentialSourceReceiverName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return l8CredentialSourceReceiverName(typed.X)
	default:
		return ""
	}
}

func l8CredentialSourceRawType(expression ast.Expr, typeExpressions map[string]ast.Expr, seen map[string]bool) bool {
	switch typed := expression.(type) {
	case *ast.Ident:
		if typed.Name == "string" {
			return true
		}
		if map[string]bool{
			"KeyIdentity": true, "KeyDescriptor": true, "SourceRegistration": true,
			"AdmissionGrantRegistration": true, "RegistryConfig": true,
		}[typed.Name] || seen[typed.Name] {
			return false
		}
		definition, ok := typeExpressions[typed.Name]
		if !ok {
			return false
		}
		seen[typed.Name] = true
		return l8CredentialSourceRawType(definition, typeExpressions, seen)
	case *ast.ArrayType:
		identifier, ok := typed.Elt.(*ast.Ident)
		if ok && identifier.Name == "byte" {
			return true
		}
		return l8CredentialSourceRawType(typed.Elt, typeExpressions, seen)
	case *ast.StarExpr:
		return l8CredentialSourceRawType(typed.X, typeExpressions, seen)
	case *ast.MapType:
		return l8CredentialSourceRawType(typed.Key, typeExpressions, seen) || l8CredentialSourceRawType(typed.Value, typeExpressions, seen)
	case *ast.StructType:
		for _, field := range typed.Fields.List {
			if l8CredentialSourceRawType(field.Type, typeExpressions, seen) {
				return true
			}
		}
		return false
	case *ast.ParenExpr:
		return l8CredentialSourceRawType(typed.X, typeExpressions, seen)
	default:
		return false
	}
}
