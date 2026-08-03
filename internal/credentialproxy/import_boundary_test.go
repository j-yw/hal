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
	"unicode"
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

func TestL8CredentialProxyCatalogProductionSourceHasNoLiveBehavior(t *testing.T) {
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
	}
}

func TestL8CredentialProxyPackageProductionSourceHasNoFixtureOrOverrideMaterial(t *testing.T) {
	for _, path := range credentialProxyProductionFiles(t) {
		if segment := credentialProxyTestOnlyPathSegment(path); segment != "" {
			t.Errorf("production credentialproxy file %s is hidden under test-only directory segment %q", path, segment)
		}
		if filename := credentialProxyTestOnlyProductionFilename(path); filename != "" {
			t.Errorf("production credentialproxy filename %q describes test-only fixture material; fixtures belong in _test.go", filename)
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		text := string(source)
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
				t.Errorf("production credentialproxy file %s contains endpoint/TLS fixture marker %q; fixtures belong in _test.go", path, endpointMarker)
			}
		}
		for _, overrideMarker := range []string{
			"ProjectOverrides",
			"ProjectOverride",
			"ServiceOverride",
			"CatalogOwnerProject",
			"TemplateOverride",
			"RequestOverride",
		} {
			if strings.Contains(text, overrideMarker) {
				t.Errorf("production credentialproxy file %s contains project/template/request override marker %q", path, overrideMarker)
			}
		}
		fixtureIdentifier, err := credentialProxyProductionFixtureIdentifier(path, source)
		if err != nil {
			t.Fatalf("inspect fixture identifiers in %s: %v", path, err)
		}
		if fixtureIdentifier != "" {
			t.Errorf("production credentialproxy file %s declares or references test-only fixture identifier %q", path, fixtureIdentifier)
		}
	}
}

func TestL8CredentialProxyPackageFixtureGuardRejectsSemanticBypassesWithoutSubstringFalsePositives(t *testing.T) {
	for _, path := range []string{
		"fixture/catalog.go",
		"fixtures/catalog.go",
		"live/azure_fixture_catalog/catalog.go",
		"live/AzureTestRegistry/catalog.go",
		"live/newAzureFixtureEndpoint/catalog.go",
		"live/testfixture/catalog.go",
		"live/testfixtures/catalog.go",
		"live/testdata/catalog.go",
		"live/testutil/catalog.go",
		"live/testutils/catalog.go",
		"live/testonly/catalog.go",
		"live/fake/catalog.go",
		"live/fakes/catalog.go",
		"live/mock/catalog.go",
		"live/mocks/catalog.go",
	} {
		if got := credentialProxyTestOnlyPathSegment(path); got == "" {
			t.Errorf("credentialProxyTestOnlyPathSegment(%q) = empty, want exact test-only directory rejection", path)
		}
	}
	for _, path := range []string{
		"fixturepolicy/catalog.go",
		"live/fakeproof/catalog.go",
		"live/mockpolicy/catalog.go",
		"live/contest_registry/catalog.go",
		"live/latest_service_catalog/catalog.go",
		"live/catalog_fixture_policy.go",
		"live/catalog.go",
	} {
		if got := credentialProxyTestOnlyPathSegment(path); got != "" {
			t.Errorf("credentialProxyTestOnlyPathSegment(%q) = %q, want legitimate production path allowed", path, got)
		}
	}

	for _, filename := range []string{
		"fixture.go",
		"fixture_catalog.go",
		"azure_fixture_metadata.go",
		"azure_test_registry.go",
		"new_fixture_endpoint.go",
		"mock_tls_authority.go",
	} {
		if got := credentialProxyTestOnlyProductionFilename(filepath.Join("live", filename)); got == "" {
			t.Errorf("credentialProxyTestOnlyProductionFilename(%q) = empty, want compound filename rejection", filename)
		}
	}
	for _, filename := range []string{
		"fixture_policy.go",
		"catalog_fixture_policy.go",
		"fixture_documentation.go",
		"azure_openai_responses.go",
		"service_catalog.go",
		"application_route.go",
		"fakeproof.go",
	} {
		if got := credentialProxyTestOnlyProductionFilename(filepath.Join("live", filename)); got != "" {
			t.Errorf("credentialProxyTestOnlyProductionFilename(%q) = %q, want legitimate production filename allowed", filename, got)
		}
	}
	for _, source := range []string{
		"package live\nfunc fixture () {}\n",
		"package live\nfunc NewFixture () {}\n",
		"package live\ntype FixtureRegistry struct{}\n",
		"package live\nvar newTestCatalog = func() {}\n",
		"package live\ntype NewAzureFixtureCatalog struct{}\n",
		"package live\ntype AzureFixtureMetadata struct{}\n",
		"package live\nfunc newFixtureEndpoint() {}\n",
		"package live\ntype AzureTestRegistry struct{}\n",
		"package live\ntype mockTLSAuthority struct{}\n",
		"package live\ntype FixturePolicyCatalog struct{}\n",
	} {
		if got, err := credentialProxyProductionFixtureIdentifier("live.go", []byte(source)); err != nil {
			t.Fatalf("credentialProxyProductionFixtureIdentifier() error: %v", err)
		} else if got == "" {
			t.Errorf("credentialProxyProductionFixtureIdentifier(%q) = empty, want semantic fixture identifier rejection", source)
		}
	}
	allowedSource := `package live
// NewAzureFixtureCatalog is test-only and unavailable here.
type FixturePolicy struct{}
type CatalogFixturePolicy struct{}
type AzureOpenAIResponsesV1Definition struct{}
type StaticServiceCatalog struct{}
type ContestRegistry struct{}
type LatestServiceCatalog struct{}
type MockingbirdPolicy struct{}
const fixtureDocumentation = "NewFixture"
const fakeproof = "documentation"
`
	if got, err := credentialProxyProductionFixtureIdentifier("live.go", []byte(allowedSource)); err != nil {
		t.Fatalf("credentialProxyProductionFixtureIdentifier(allowed) error: %v", err)
	} else if got != "" {
		t.Errorf("credentialProxyProductionFixtureIdentifier(allowed) = %q, want comments and documentation strings allowed", got)
	}

	for name, want := range map[string][]string{
		"NewAzureFixtureCatalog": {"new", "azure", "fixture", "catalog"},
		"newFixtureEndpoint":     {"new", "fixture", "endpoint"},
		"AzureTestRegistry":      {"azure", "test", "registry"},
		"fixture_catalog.go":     {"fixture", "catalog", "go"},
		"TLSTestAuthority":       {"tls", "test", "authority"},
	} {
		if got := credentialProxySemanticTokens(name); !equalCredentialProxyTokens(got, want) {
			t.Errorf("credentialProxySemanticTokens(%q) = %#v, want %#v", name, got, want)
		}
	}
}

func TestL8CredentialProxyPackageProductionFileDiscoveryIsRecursive(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "live", "provider")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	rootProduction := filepath.Join(root, "catalog.go")
	nestedProduction := filepath.Join(nested, "route.go")
	nestedTest := filepath.Join(nested, "route_test.go")
	for path, source := range map[string]string{
		rootProduction:   "package credentialproxy\n",
		nestedProduction: "package provider\n",
		nestedTest:       "package provider\n",
	} {
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error: %v", path, err)
		}
	}

	paths, err := credentialProxyProductionFilesUnder(root)
	if err != nil {
		t.Fatalf("credentialProxyProductionFilesUnder() error: %v", err)
	}
	want := map[string]bool{
		filepath.Clean(rootProduction):   true,
		filepath.Clean(nestedProduction): true,
	}
	if len(paths) != len(want) {
		t.Fatalf("recursive production files = %#v, want exactly root and nested production files", paths)
	}
	for _, path := range paths {
		if !want[path] {
			t.Errorf("recursive production files contain unexpected path %s", path)
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

func credentialProxyProductionFiles(t *testing.T) []string {
	t.Helper()
	paths, err := credentialProxyProductionFilesUnder(".")
	if err != nil {
		t.Fatalf("WalkDir() error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("credentialproxy has no production files; D1 implementation is missing")
	}
	return paths
}

func credentialProxyProductionFilesUnder(root string) ([]string, error) {
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		paths = append(paths, filepath.Clean(path))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func credentialProxyTestOnlyPathSegment(path string) string {
	parts := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	if len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	for _, part := range parts {
		if credentialProxyTestOnlySemanticName(part) != "" {
			return part
		}
	}
	return ""
}

func credentialProxyTestOnlyProductionFilename(path string) string {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	if credentialProxyTestOnlySemanticName(name) != "" {
		return filepath.Base(path)
	}
	return ""
}

func credentialProxyProductionFixtureIdentifier(path string, source []byte) (string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		return "", err
	}
	var found string
	ast.Inspect(parsed, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && credentialProxyTestOnlySemanticName(identifier.Name) != "" {
			found = identifier.Name
			return false
		}
		return found == ""
	})
	return found, nil
}

func credentialProxyTestOnlySemanticName(name string) string {
	tokens := credentialProxySemanticTokens(name)
	if len(tokens) == 0 {
		return ""
	}
	exact := strings.Join(tokens, "")
	switch exact {
	case "fixture", "fixtures", "testfixture", "testfixtures", "testdata", "testutil", "testutils", "testonly", "fake", "fakes", "mock", "mocks":
		return exact
	}

	var testOnlyToken string
	for index, token := range tokens {
		switch token {
		case "fixture":
			// FixturePolicy and FixtureDocumentation are legitimate production
			// vocabulary. Requiring the suffix to end the identifier prevents it
			// from exempting names such as FixturePolicyCatalog.
			if index+1 == len(tokens)-1 && (tokens[index+1] == "policy" || tokens[index+1] == "documentation") {
				continue
			}
			testOnlyToken = token
		case "fixtures", "test", "tests", "fake", "fakes", "mock", "mocks":
			testOnlyToken = token
		}
	}
	return testOnlyToken
}

func credentialProxySemanticTokens(name string) []string {
	runes := []rune(name)
	tokens := make([]string, 0)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			tokens = append(tokens, strings.ToLower(string(runes[start:end])))
		}
		start = -1
	}
	for index, current := range runes {
		if !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			flush(index)
			continue
		}
		if start < 0 {
			start = index
			continue
		}
		previous := runes[index-1]
		nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
		if unicode.IsUpper(current) && (unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextIsLower) {
			flush(index)
			start = index
		}
	}
	flush(len(runes))
	return tokens
}

func equalCredentialProxyTokens(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
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
