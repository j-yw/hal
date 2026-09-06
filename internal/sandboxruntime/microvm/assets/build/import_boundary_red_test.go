package build

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL5BuildMetadataPackageStaysDataAndDigestOnly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(build package) error = %v", err)
	}

	productionFiles := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		productionFiles++
		path := filepath.Clean(entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", path, err)
		}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", path, err)
			}
			if message := l5BuildForbiddenImportMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
	if productionFiles == 0 {
		t.Fatal("L5 build metadata package has no production implementation")
	}
}

func TestL5BuildMetadataImportGuardRejectsForbiddenFixtures(t *testing.T) {
	for _, importPath := range []string{
		"os",
		"os/exec",
		"path/filepath",
		"net",
		"net/http",
		"github.com/jywlabs/hal/cmd",
		"github.com/jywlabs/hal/internal/factory",
		"github.com/jywlabs/hal/internal/sandboxworker",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker",
		"github.com/jywlabs/hal/internal/sandbox/provider/hetzner",
		"github.com/firecracker-microvm/firecracker-go-sdk",
		"github.com/aws/aws-sdk-go-v2",
		"google.golang.org/api",
	} {
		if message := l5BuildForbiddenImportMessage("fixture.go", importPath); message == "" {
			t.Fatalf("build metadata import guard accepted forbidden import %q", importPath)
		}
	}
	for _, importPath := range []string{
		"crypto/sha256",
		"encoding/hex",
		"encoding/json",
		"errors",
		"fmt",
		"sort",
		"strings",
	} {
		if message := l5BuildForbiddenImportMessage("fixture.go", importPath); message != "" {
			t.Fatalf("build metadata import guard rejected %q: %s", importPath, message)
		}
	}
}

func l5BuildForbiddenImportMessage(fileName, importPath string) string {
	allowed := map[string]bool{
		"crypto/sha256": true,
		"encoding/hex":  true,
		"encoding/json": true,
		"errors":        true,
		"fmt":           true,
		"sort":          true,
		"strings":       true,
	}
	if allowed[importPath] {
		return ""
	}
	return fmt.Sprintf("L5 build metadata purity boundary: %s imports forbidden package %s", filepath.Base(fileName), importPath)
}
