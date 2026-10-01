package cmd

import (
	"go/ast"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestUS004PureCredentialEnvironmentReadGuardRejectsFixtures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "getenv credential",
			source: `package fixture; import "os"; func test() { _ = os.Getenv("GITHUB_TOKEN") }`,
			want:   "os.Getenv",
		},
		{
			name:   "lookup credential",
			source: `package fixture; import "os"; func test() { _, _ = os.LookupEnv("NPM_TOKEN") }`,
			want:   "os.LookupEnv",
		},
		{
			name:   "enumerate environment",
			source: `package fixture; import "os"; func test() { _ = os.Environ() }`,
			want:   "os.Environ",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file := phase50ParseGoSource(t, tt.name+".go", tt.source)
			message := us004CredentialEnvironmentReadBoundaryMessage(tt.name+".go", file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("credential environment guard message = %q, want marker %q", message, tt.want)
			}
			phase50AssertGuardMessageRedactionSafe(t, message)
		})
	}
}

func TestUS004PureLiveE2EPackagesDoNotReadCredentialEnvironmentValues(t *testing.T) {
	for _, path := range us004PureLiveE2EProductionFiles(t) {
		source := phase50ReadFile(t, path)
		file := phase50ParseGoSource(t, path, source)
		if message := us004CredentialEnvironmentReadBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func phase50AssertGuardMessageRedactionSafe(t *testing.T, message string) {
	t.Helper()
	for _, forbidden := range []string{
		"secret-live-value",
		"secret-value",
		"/Users/alice",
		"/tmp/private.sock",
		"private.sock",
		"provider.internal.example.com",
		"https://",
		"unix://",
		"token=secret",
		"apiKey",
		"providerConfig",
		"--api-sock",
		"iptables",
		"proxy.internal.example.com",
	} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("Phase 50 guard message leaked unsafe fragment %q: %s", forbidden, message)
		}
	}
}

func us004CredentialEnvironmentReadBoundaryMessage(fileName string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := phase50CallSelectorName(call.Fun)
		switch selector {
		case "os.Getenv", "os.LookupEnv", "os.Environ":
			message = us004DefaultHarnessGuardMessage(fileName, "process environment credential read", selector)
		}
		return message == ""
	})
	return message
}

func us004DefaultHarnessGuardMessage(fileName, category, marker string) string {
	return "US-004 default live E2E harness guard: " + phase50SafeDisplayPath(fileName) + " contains " + category + " marker " + strconv.Quote(marker)
}

func us004ProductionGoFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir(%s) error: %v", root, err)
	}
	return paths
}

func us004PureLiveE2EProductionFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, root := range []string{
		filepath.Join("..", "internal", "credentialdelivery"),
		filepath.Join("..", "internal", "sandboxtemplate"),
	} {
		paths = append(paths, us004ProductionGoFilesUnder(t, root)...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("US-004 pure package guard matched no production files")
	}
	return paths
}
