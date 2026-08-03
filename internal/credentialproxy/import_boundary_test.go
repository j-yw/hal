package credentialproxy

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

func TestL8CredentialProxyCatalogImportBoundaryIsDataOnly(t *testing.T) {
	for _, path := range credentialProxyCatalogProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if reason := forbiddenCredentialProxyCatalogImport(importPath); reason != "" {
				t.Errorf("production credential catalog file %s imports %q (%s)", path, importPath, reason)
			}
		}
	}
}

func TestL8CredentialProxyCatalogImportGuardRejectsLiveDependencies(t *testing.T) {
	tests := []struct {
		path   string
		reason string
	}{
		{path: "net", reason: "network implementation"},
		{path: "net/http", reason: "network implementation"},
		{path: "net/url", reason: "network implementation"},
		{path: "crypto/tls", reason: "network implementation"},
		{path: "os", reason: "host secret or process implementation"},
		{path: "os/exec", reason: "host secret or process implementation"},
		{path: "syscall", reason: "host secret or process implementation"},
		{path: "golang.org/x/sys/unix", reason: "host secret or process implementation"},
		{path: "github.com/jywlabs/hal/cmd", reason: "orchestration"},
		{path: "github.com/jywlabs/hal/internal/engine/pi", reason: "consumer implementation"},
		{path: "github.com/jywlabs/hal/internal/factory", reason: "orchestration"},
		{path: "github.com/jywlabs/hal/internal/credentialsource", reason: "raw secret implementation"},
		{path: "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy", reason: "network implementation"},
		{path: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", reason: "cloud SDK"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := forbiddenCredentialProxyCatalogImport(tt.path); !strings.Contains(got, tt.reason) {
				t.Fatalf("forbiddenCredentialProxyCatalogImport(%q) = %q, want reason containing %q", tt.path, got, tt.reason)
			}
		})
	}

	for _, allowed := range []string{
		"encoding",
		"encoding/json",
		"errors",
		"fmt",
		"sort",
		"strings",
		"time",
		"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute",
	} {
		if got := forbiddenCredentialProxyCatalogImport(allowed); got != "" {
			t.Fatalf("forbiddenCredentialProxyCatalogImport(%q) = %q, want allowed", allowed, got)
		}
	}
}

func TestL8CredentialProxyCatalogProductionSourceHasNoLiveOrFixtureBehavior(t *testing.T) {
	for _, path := range credentialProxyCatalogProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		text := string(source)
		for _, marker := range credentialProxyCatalogForbiddenSourceMarkers() {
			if strings.Contains(text, marker) {
				t.Errorf("production credential catalog file %s contains forbidden marker %q", path, marker)
			}
		}
		for _, endpointMarker := range []string{
			".example.com",
			".example.test",
			".invalid",
			".azure.com",
			".cloud",
			"127.0.0.1",
			"localhost",
			"BEGIN CERTIFICATE",
		} {
			if strings.Contains(text, endpointMarker) {
				t.Errorf("production credential catalog file %s contains endpoint/TLS fixture marker %q; fixtures belong in _test.go", path, endpointMarker)
			}
		}
	}
}

func TestL8CredentialProxyCatalogMarshalMethodsOnlyDenyLiveTypes(t *testing.T) {
	liveDenialReceivers := map[string]bool{
		"ServiceDefinition":      true,
		"SealedInvocationPolicy": true,
		"SealedTLSPolicy":        true,
		"StaticServiceCatalog":   true,
	}
	for _, path := range credentialProxyCatalogProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 {
				continue
			}
			receiver := catalogReceiverTypeName(function.Recv.List[0].Type)
			switch function.Name.Name {
			case "MarshalJSON":
				if !liveDenialReceivers[receiver] && receiver != "CatalogServiceReference" {
					t.Errorf("production catalog file %s defines %s on unapproved receiver %s", path, function.Name.Name, receiver)
				}
			case "MarshalText":
				if !liveDenialReceivers[receiver] {
					t.Errorf("production catalog file %s defines %s on unapproved receiver %s", path, function.Name.Name, receiver)
				}
			case "UnmarshalJSON", "UnmarshalText", "GobEncode", "GobDecode", "MarshalYAML", "UnmarshalYAML":
				t.Errorf("production catalog file %s defines forbidden durable codec method %s on %s", path, function.Name.Name, receiver)
			}
		}
	}
}

func TestL8CredentialProxyCatalogSourceGuardCoversRequiredLiveMarkers(t *testing.T) {
	fixture := strings.Join(credentialProxyCatalogForbiddenSourceMarkers(), "\n")
	for _, marker := range []string{
		"net.Listen(",
		"net.Dial(",
		"http.Client",
		"tls.Dial(",
		"exec.Command(",
		"os.Getenv(",
		"Secret []byte",
		"RawSecret",
		"ResolvedRunSecret",
	} {
		if !strings.Contains(fixture, marker) {
			t.Fatalf("catalog source guard fixture does not cover %q", marker)
		}
	}
}

func credentialProxyCatalogProductionFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob("catalog*.go")
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
		t.Fatal("credentialproxy has no production files; D1 static catalog implementation is missing")
	}
	return paths
}

func credentialProxyCatalogForbiddenSourceMarkers() []string {
	return []string{
		"net.Listen(",
		"net.Dial(",
		"net.Dialer",
		"http.Client",
		"http.Server",
		"httputil.ReverseProxy",
		"tls.Dial(",
		"InsecureSkipVerify",
		"exec.Command(",
		"os.Getenv(",
		"os.LookupEnv(",
		"Secret []byte",
		"Secret string",
		"RawSecret",
		"SecretValue",
		"ResolvedRunSecret",
		"LiveSecretSource",
		"NewL8Fixture",
		"newL8Fixture",
		"L8FixtureRegistry",
		"l8FixtureRegistry",
		"ProjectOverrides",
		"ProjectOverride",
		"ServiceOverride",
		"CatalogOwnerProject",
		"AzureOpenAIResponsesV1SealedInput",
	}
}

func forbiddenCredentialProxyCatalogImport(importPath string) string {
	switch importPath {
	case "net", "net/http", "net/url", "net/http/httputil", "crypto/tls":
		return "network implementation"
	case "os", "os/exec", "syscall", "plugin", "path/filepath":
		return "host secret or process implementation"
	}
	if strings.HasPrefix(importPath, "golang.org/x/sys") {
		return "host secret or process implementation"
	}
	if importPath == "github.com/jywlabs/hal/cmd" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker") ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/compound") {
		return "orchestration"
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/engine") {
		return "consumer implementation"
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialsource") ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialmemory") {
		return "raw secret implementation"
	}
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/applicationroute" {
		return ""
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime") ||
		strings.HasPrefix(importPath, "golang.org/x/net") {
		return "network implementation"
	}
	lower := strings.ToLower(importPath)
	if strings.Contains(lower, "azure-sdk") || strings.Contains(lower, "aws-sdk") || strings.Contains(lower, "google.golang.org/api") {
		return "cloud SDK"
	}
	return ""
}

func catalogReceiverTypeName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return catalogReceiverTypeName(value.X)
	default:
		return ""
	}
}
