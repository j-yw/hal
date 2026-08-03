package credentialsource

import (
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
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		production++
		path := entry.Name()
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", path, err)
			}
			forbidden := importPath == "os" || importPath == "os/exec" || importPath == "io/ioutil" || importPath == "path/filepath" ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
				strings.Contains(importPath, "credentialdelivery") || strings.Contains(importPath, "provider")
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
			"ResolvedRunSecret", "SecretBroker", "Value string", "json.Marshal(", "MarshalJSON(", "MarshalText(",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production credential source %s contains forbidden ingress/marshal marker %q", path, marker)
			}
		}
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
	for _, required := range []string{"unix.KeyctlBuffer(", "unix.KEYCTL_READ"} {
		if !strings.Contains(productionSource.String(), required) {
			t.Errorf("L8 credential source omits direct keyctl read marker %q", required)
		}
	}
}
