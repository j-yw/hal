package credentialmemory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestL8CredentialMemoryImportAndFormattingBoundaries(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	production := 0
	productionSource := strings.Builder{}
	denialMethods := map[string]map[string]bool{
		"LockedMapping": {},
		"borrowedView":  {},
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		production++
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		productionSource.Write(source)
		productionSource.WriteByte('\n')
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "fmt" || importPath == "log" || importPath == "log/slog" ||
				importPath == "net" || strings.HasPrefix(importPath, "net/") ||
				importPath == "os" || importPath == "os/exec" || importPath == "io" || importPath == "io/fs" ||
				importPath == "path/filepath" || importPath == "syscall" ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/cmd") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialdelivery") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialsource") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker") ||
				strings.Contains(importPath, "/internal/provider") || strings.Contains(importPath, "/internal/process") ||
				strings.Contains(importPath, "/internal/workspace") || strings.Contains(importPath, "/internal/sandboxexecution") {
				t.Errorf("production credential memory %s imports forbidden package %q", entry.Name(), importPath)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				identifier, ok := typed.X.(*ast.Ident)
				if ok && identifier.Name == "errors" && typed.Sel.Name == "Join" {
					t.Errorf("production credential memory %s uses forbidden raw-error composition errors.Join", entry.Name())
				}
			case *ast.StructType:
				for _, field := range typed.Fields.List {
					if len(field.Names) == 0 || !field.Names[0].IsExported() || !l8CredentialMemoryRawType(field.Type) {
						continue
					}
					t.Errorf("production credential memory %s exposes raw live field %s", entry.Name(), field.Names[0].Name)
				}
			case *ast.FuncDecl:
				if typed.Recv == nil {
					return true
				}
				receiver := l8CredentialMemoryReceiverName(typed.Recv.List[0].Type)
				switch typed.Name.Name {
				case "Unwrap", "MarshalBinary", "GobEncode", "Bytes", "Value":
					t.Errorf("production credential memory %s defines forbidden live-state method %s", entry.Name(), typed.Name.Name)
				case "String", "GoString", "MarshalJSON", "MarshalText":
					allowed, ok := denialMethods[receiver]
					if !ok {
						t.Errorf("production credential memory %s defines formatting/codec method %s on unexpected receiver %s", entry.Name(), typed.Name.Name, receiver)
						return true
					}
					allowed[typed.Name.Name] = true
				}
			}
			return true
		})
	}
	if production == 0 {
		t.Fatal("L8 credential memory production package does not exist")
	}
	for receiver, found := range denialMethods {
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText"} {
			if !found[required] {
				t.Errorf("production credential memory %s omits required safe/denial method %s", receiver, required)
			}
		}
	}
	for _, required := range []string{
		"unix.Mmap(", "unix.MAP_ANON", "unix.MAP_PRIVATE", "unix.Mlock(",
		"unix.Munlock(", "unix.Munmap(", "unix.RLIMIT_CORE", "unix.PR_SET_DUMPABLE",
	} {
		if !strings.Contains(productionSource.String(), required) {
			t.Errorf("production credential memory omits direct fail-closed OS marker %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Write(", "os.WriteFile(", "io.Writer", "errors.Join(",
	} {
		if strings.Contains(productionSource.String(), forbidden) {
			t.Errorf("production credential memory contains forbidden raw write/composition marker %q", forbidden)
		}
	}
}

func l8CredentialMemoryReceiverName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return l8CredentialMemoryReceiverName(typed.X)
	default:
		return ""
	}
}

func l8CredentialMemoryRawType(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name == "string"
	case *ast.ArrayType:
		identifier, ok := typed.Elt.(*ast.Ident)
		return ok && identifier.Name == "byte"
	case *ast.StarExpr:
		return l8CredentialMemoryRawType(typed.X)
	default:
		return false
	}
}
