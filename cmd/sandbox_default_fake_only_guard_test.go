package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPhase19DefaultTestsAvoidPodmanDaemonsAndWorkerIntegrationEnv(t *testing.T) {
	for _, path := range phase19GoTestFiles(t, "..") {
		source := phase19ReadFile(t, path)
		rel := phase19RelativePath(t, "..", path)
		if rel == "cmd/sandbox_default_fake_only_guard_test.go" {
			continue
		}
		hasPodmanTag := phase19HasBuildTag(source, "podman_integration")
		hasWorkerTag := phase19HasBuildTag(source, "worker_integration")

		if phase19UsesRealPodman(source) && !hasPodmanTag {
			t.Fatalf("%s uses real Podman integration hooks without the podman_integration build tag", rel)
		}
		if phase19RequiresWorkerIntegrationEnv(source) && !hasWorkerTag {
			t.Fatalf("%s requires HAL_WORKER_INTEGRATION_* environment without the worker_integration build tag", rel)
		}
		if hasWorkerTag {
			continue
		}
		if strings.HasPrefix(rel, "internal/sandboxworker/") {
			continue
		}
		for _, forbidden := range []string{
			"sandboxworker.NewServer(",
			`net.Listen("unix"`,
			`Listen(ctx, "unix"`,
			"newSandboxdCommand(defaultSandboxdDeps())",
			"newTestSandboxdCommand(defaultSandboxdDeps())",
			"runSandboxdCommand(",
			"sandboxdCmd.Execute",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s contains %q; default tests outside internal/sandboxworker must not bind worker sockets or start sandboxd with production daemon deps", rel, forbidden)
			}
		}
	}
}

func TestPhase19SandboxHelpKeepsWorkerRootlessRoutingExplicit(t *testing.T) {
	root := Root()
	for _, path := range [][]string{
		{"run"},
		{"auto"},
		{"factory", "run"},
	} {
		cmd, err := commandAtPath(root, path...)
		if err != nil {
			t.Fatalf("command path %q missing: %v", strings.Join(path, " "), err)
		}
		text := strings.Join([]string{cmd.Long, cmd.Example}, "\n")
		lower := strings.ToLower(text)
		for _, forbidden := range []string{
			"rootless podman by default",
			"rootless worker by default",
			"worker routing by default",
			"starts sandboxd automatically",
			"starts the worker daemon automatically",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("command %q help implies default worker/rootless routing with %q:\n%s", commandPathLabel(cmd), forbidden, text)
			}
		}
		for _, line := range strings.Split(text, "\n") {
			if !strings.Contains(line, "rootless_podman") {
				continue
			}
			lineLower := strings.ToLower(line)
			if !strings.Contains(line, "--sandbox-host") && !strings.Contains(lineLower, "explicit") {
				t.Fatalf("command %q rootless_podman help line must show explicit target selection:\n%s", commandPathLabel(cmd), line)
			}
		}
	}
}

func TestPhase19WorkerLiveRefreshCallSitesStayScoped(t *testing.T) {
	callSites := phase19CmdProductionCallSiteFiles(t,
		"querySandboxHostWorkerMetadata",
		"querySandboxRuntimeLiveMetadata",
		"sandboxWorkerRuntimeDriverFromTarget",
	)
	want := map[string][]string{
		"querySandboxHostWorkerMetadata":       {"sandbox_host.go"},
		"querySandboxRuntimeLiveMetadata":      {"sandbox_runtime.go"},
		"sandboxWorkerRuntimeDriverFromTarget": {"auto_sandbox.go", "factory_sandbox_executor.go", "run_sandbox.go"},
	}
	for name, wantFiles := range want {
		got := callSites[name]
		sort.Strings(got)
		sort.Strings(wantFiles)
		if strings.Join(got, ",") != strings.Join(wantFiles, ",") {
			t.Fatalf("%s call-site files = %v, want %v", name, got, wantFiles)
		}
	}
}

func TestPhase19SandboxRuntimeImportBoundaryGuardsCoverRuntimePackages(t *testing.T) {
	required := map[string][]string{
		"internal/sandboxexec/import_boundary_test.go": {
			"TestSandboxexecDoesNotImportCommandOrProviderLayers",
			"TestSandboxexecForbiddenImportListCoversRequiredBoundaries",
			"github.com/jywlabs/hal/internal/loop",
			"github.com/jywlabs/hal/internal/sandboxworker",
			"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman",
			"github.com/jywlabs/hal/internal/sandbox/provider",
		},
		"internal/sandboxworker/import_boundary_test.go": {
			"TestSandboxworkerImportsStayCommandAgnostic",
			"TestSandboxworkerImportBoundaryAllowsRuntimeContractsOnly",
			"github.com/jywlabs/hal/internal/sandboxruntime",
			"non-standard-library dependency",
		},
		"internal/sandboxruntime/rootlesspodman/import_boundary_test.go": {
			"TestRootlessPodmanImportsStayCommandAgnostic",
			"TestRootlessPodmanForbiddenImportListCoversCommandCouplingSurfaces",
			"github.com/jywlabs/hal/internal/sandboxworker",
			"github.com/jywlabs/hal/internal/sandboxexecution",
			"github.com/jywlabs/hal/internal/sandboxtarget",
			"github.com/jywlabs/hal/internal/sandbox/provider",
		},
	}
	for path, markers := range required {
		source := phase19ReadFile(t, filepath.Join("..", path))
		for _, marker := range markers {
			if !strings.Contains(source, marker) {
				t.Fatalf("%s does not cover required import-boundary marker %q", path, marker)
			}
		}
	}
}

func phase19GoTestFiles(t *testing.T, repoRoot string) []string {
	t.Helper()
	var files []string
	for _, root := range []string{"cmd", "internal"} {
		walkRoot := filepath.Join(repoRoot, root)
		if err := filepath.WalkDir(walkRoot, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		}); err != nil {
			t.Fatalf("WalkDir(%s) error: %v", walkRoot, err)
		}
	}
	sort.Strings(files)
	return files
}

func phase19ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase19RelativePath(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("Rel(%s, %s) error: %v", root, path, err)
	}
	return filepath.ToSlash(rel)
}

func phase19HasBuildTag(source, tag string) bool {
	header := phase19SourceHeader(source)
	return strings.Contains(header, tag)
}

func phase19SourceHeader(source string) string {
	lines := strings.Split(source, "\n")
	var header []string
	for _, line := range lines {
		if strings.HasPrefix(line, "package ") {
			break
		}
		header = append(header, line)
	}
	return strings.Join(header, "\n")
}

func phase19UsesRealPodman(source string) bool {
	for _, marker := range []string{
		"rootlesspodman.DefaultCommandRunner{}",
		"HAL_PODMAN_TEST_IMAGE",
		"podman image exists",
		"podmanIntegrationExecutable",
	} {
		if strings.Contains(source, marker) {
			return true
		}
	}
	return false
}

func phase19RequiresWorkerIntegrationEnv(source string) bool {
	if !strings.Contains(source, "os.Getenv") && !strings.Contains(source, "os.LookupEnv") {
		return false
	}
	return strings.Contains(source, "HAL_WORKER_INTEGRATION_") ||
		strings.Contains(source, "workerIntegrationEndpointEnv") ||
		strings.Contains(source, "workerIntegrationHostNameEnv") ||
		strings.Contains(source, "workerIntegrationRuntimeDriverEnv") ||
		strings.Contains(source, "workerIntegrationImageEnv")
}

func phase19CmdProductionCallSiteFiles(t *testing.T, names ...string) map[string][]string {
	t.Helper()
	wanted := make(map[string]bool, len(names))
	callSites := make(map[string]map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
		callSites[name] = make(map[string]bool)
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(*.go) error: %v", err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := phase19CallName(call.Fun)
			if wanted[name] {
				callSites[name][filepath.Base(path)] = true
			}
			return true
		})
	}

	result := make(map[string][]string, len(callSites))
	for name, files := range callSites {
		for file := range files {
			result[name] = append(result[name], file)
		}
		sort.Strings(result[name])
	}
	return result
}

func phase19CallName(expr ast.Expr) string {
	switch fn := expr.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
	}
}
