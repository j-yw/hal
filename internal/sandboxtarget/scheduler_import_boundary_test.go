package sandboxtarget

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSchedulerProductionImportsStayCommandAgnosticAndOffline(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", sandboxtargetPackagePath, err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "scheduler_") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := sandboxtargetImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSchedulerImportBoundaryRejectsWorkerProviderAndNetworkCoupling(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "worker clients", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker client package"},
		{name: "sandbox execution", importPath: "github.com/jywlabs/hal/internal/sandboxexec", want: "sandbox execution package"},
		{name: "execution records", importPath: "github.com/jywlabs/hal/internal/sandboxexecution", want: "sandbox execution record package"},
		{name: "workspace materialization", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace", want: "sandbox workspace package"},
		{name: "concrete runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete runtime adapter package"},
		{name: "standard network client", importPath: "net/http", want: "network-only package"},
		{name: "Docker client", importPath: "github.com/docker/docker/client", want: "network-only package"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "network-only package"},
		{name: "cloud provider client", importPath: "github.com/digitalocean/godo", want: "network-only package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxtargetImportBoundaryMessage("scheduler_candidates.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}
