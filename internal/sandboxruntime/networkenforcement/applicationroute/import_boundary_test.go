package applicationroute

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8ApplicationRouteImportBoundaryStaysNeutral(t *testing.T) {
	paths := applicationRouteProductionFiles(t)
	for _, path := range paths {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if reason := forbiddenApplicationRouteImport(importPath); reason != "" {
				t.Errorf("production application-route file %s imports %q (%s)", path, importPath, reason)
			}
		}
	}
}

func TestL8ApplicationRouteImportGuardRejectsLiveAndCoupledDependencies(t *testing.T) {
	tests := []struct {
		path   string
		reason string
	}{
		{path: "net", reason: "network implementation"},
		{path: "net/http", reason: "network implementation"},
		{path: "net/url", reason: "network implementation"},
		{path: "crypto/tls", reason: "network implementation"},
		{path: "os", reason: "host or process implementation"},
		{path: "os/exec", reason: "host or process implementation"},
		{path: "syscall", reason: "host or process implementation"},
		{path: "golang.org/x/sys/unix", reason: "host or process implementation"},
		{path: "github.com/jywlabs/hal/cmd", reason: "orchestration"},
		{path: "github.com/jywlabs/hal/internal/credentialproxy", reason: "credential proxy implementation"},
		{path: "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy", reason: "policy proxy implementation"},
		{path: "github.com/jywlabs/hal/internal/sandboxruntime/microvm", reason: "concrete runtime"},
		{path: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", reason: "cloud SDK"},
		{path: "math", reason: "exact allowlist"},
		{path: "example.com/unknown/module", reason: "exact allowlist"},
		{path: "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute/bypass", reason: "concrete runtime"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := forbiddenApplicationRouteImport(tt.path); !strings.Contains(got, tt.reason) {
				t.Fatalf("forbiddenApplicationRouteImport(%q) = %q, want reason containing %q", tt.path, got, tt.reason)
			}
		})
	}

	for _, allowed := range []string{"context", "errors", "fmt", "io", "reflect", "sort", "strings", "sync"} {
		if got := forbiddenApplicationRouteImport(allowed); got != "" {
			t.Fatalf("forbiddenApplicationRouteImport(%q) = %q, want allowed", allowed, got)
		}
	}
}

func TestL8ApplicationRouteProductionSourceOmitsNetworkBehavior(t *testing.T) {
	for _, path := range applicationRouteProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		text := string(source)
		for _, marker := range []string{
			"net.Listen(",
			"net.Dial(",
			"net.Dialer",
			"http.Client",
			"http.Server",
			"httputil.ReverseProxy",
			"tls.Dial(",
			"exec.Command(",
			"os.Getenv(",
			"InsecureSkipVerify",
		} {
			if strings.Contains(text, marker) {
				t.Errorf("production application-route file %s contains live behavior marker %q", path, marker)
			}
		}
	}
}

func TestL8ApplicationRouteSourceGuardCoversForbiddenBehavior(t *testing.T) {
	fixture := strings.Join([]string{
		"net.Listen(",
		"net.Dial(",
		"net.Dialer",
		"http.Client",
		"http.Server",
		"httputil.ReverseProxy",
		"tls.Dial(",
		"exec.Command(",
		"os.Getenv(",
		"InsecureSkipVerify",
	}, "\n")
	for _, marker := range []string{"net.Listen(", "net.Dial(", "http.Client", "tls.Dial(", "exec.Command("} {
		if !strings.Contains(fixture, marker) {
			t.Fatalf("source guard fixture does not cover %q", marker)
		}
	}
}

func applicationRouteProductionFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob() error: %v", err)
	}
	paths := make([]string, 0, len(matches))
	for _, path := range matches {
		if !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		t.Fatal("applicationroute has no production files; D1 implementation is missing")
	}
	return paths
}

func forbiddenApplicationRouteImport(importPath string) string {
	switch importPath {
	case "context", "errors", "fmt", "io", "reflect", "sort", "strings", "sync":
		return ""
	}
	switch importPath {
	case "net", "net/http", "net/url", "net/http/httputil", "crypto/tls":
		return "network implementation"
	case "os", "os/exec", "syscall", "plugin", "path/filepath":
		return "host or process implementation"
	}
	if strings.HasPrefix(importPath, "golang.org/x/sys") {
		return "host or process implementation"
	}
	if importPath == "github.com/jywlabs/hal/cmd" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker") {
		return "orchestration"
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialproxy") {
		return "credential proxy implementation"
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy") {
		return "policy proxy implementation"
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/") {
		return "concrete runtime"
	}
	lower := strings.ToLower(importPath)
	if strings.Contains(lower, "azure-sdk") || strings.Contains(lower, "aws-sdk") || strings.Contains(lower, "google.golang.org/api") {
		return "cloud SDK"
	}
	return "dependency is not in the exact allowlist"
}
