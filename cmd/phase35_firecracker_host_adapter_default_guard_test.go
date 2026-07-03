package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestPhase35DefaultCLIPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter(t *testing.T) {
	for _, path := range phase35DefaultCLIProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase35AssertNoFirecrackerHostAdapterWiring(t, path)
		})
	}
}

func TestPhase35FactoryPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter(t *testing.T) {
	for _, path := range phase35FactoryProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase35AssertNoFirecrackerHostAdapterWiring(t, path)
		})
	}
}

func TestPhase35SandboxexecPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter(t *testing.T) {
	for _, path := range phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec")) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase35AssertNoFirecrackerHostAdapterWiring(t, path)
		})
	}
}

func TestPhase35WorkerPathsDoNotConstructSelectOrInjectFirecrackerHostAdapter(t *testing.T) {
	for _, path := range phase35WorkerProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase35AssertNoFirecrackerHostAdapterWiring(t, path)
		})
	}
}

func TestPhase35DefaultHostAdapterGuardCoversRequiredSurfaces(t *testing.T) {
	all := append([]string{}, phase35DefaultCLIProductionFiles(t)...)
	all = append(all, phase35FactoryProductionFiles(t)...)
	all = append(all, phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec"))...)
	all = append(all, phase35WorkerProductionFiles(t)...)

	covered := make(map[string]bool, len(all))
	for _, path := range all {
		covered[filepath.ToSlash(filepath.Clean(path))] = true
	}
	for _, want := range []string{
		"run.go",
		"run_sandbox.go",
		"auto.go",
		"auto_sandbox.go",
		"factory.go",
		"factory_sandbox_executor.go",
		"sandbox_runtime_compat.go",
		"sandbox_worker_runtime.go",
		"sandboxd.go",
		"../internal/factory/types.go",
		"../internal/factory/store.go",
		"../internal/sandboxexec/executor.go",
		"../internal/sandboxworker/adapter.go",
		"../internal/sandboxworker/service.go",
		"../internal/sandboxworker/types.go",
	} {
		clean := filepath.ToSlash(filepath.Clean(want))
		if !covered[clean] {
			t.Fatalf("Phase 35 default host adapter guard does not cover %s", want)
		}
	}
}

func TestPhase35DefaultHostAdapterGuardRejectsHostAdapterFixtures(t *testing.T) {
	importFixtures := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "Firecracker host adapter package",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost",
			want:       "Firecracker host adapter package",
		},
		{
			name:       "Firecracker host adapter subpackage",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/internaltest",
			want:       "Firecracker host adapter package",
		},
	}
	for _, tt := range importFixtures {
		t.Run(tt.name, func(t *testing.T) {
			message := phase35FirecrackerHostImportBoundaryMessage("fixture.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}

	sourceFixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "host adapter constructor",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _ = firecrackerhost.NewAdapter() }`,
			want:   "Firecracker host adapter construction",
		},
		{
			name:   "aliased process runner injection option",
			source: `package cmd; import fc "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath(runner fc.ProcessRunner) { _ = fc.WithProcessRunner(runner) }`,
			want:   "Firecracker host adapter injection",
		},
		{
			name:   "process lifecycle manager construction",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath(runner firecrackerhost.HostProcessRunner) { _ = firecrackerhost.NewProcessLifecycleManager(runner) }`,
			want:   "Firecracker host process lifecycle construction",
		},
		{
			name:   "real process runner construction",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _ = firecrackerhost.NewOSExecProcessRunner() }`,
			want:   "Firecracker host process runner construction",
		},
		{
			name:   "host adapter injected into backend options",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _ = BackendOptions{ProcessAdapter: firecrackerhost.NewAdapter()} }`,
			want:   "Firecracker live boot options",
		},
		{
			name:   "host adapter selection literal",
			source: `package cmd; func defaultPath() { _ = "firecrackerhost" }`,
			want:   "Firecracker host adapter selection",
		},
	}
	for _, tt := range sourceFixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := phase35FirecrackerHostSourceBoundaryMessage(tt.name+".go", tt.source, file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}

	allowedSource := `package cmd; func defaultPath() { _ = NewAdapter() }`
	file, err := parser.ParseFile(token.NewFileSet(), "allowed.go", allowedSource, 0)
	if err != nil {
		t.Fatalf("ParseFile allowed fixture error: %v", err)
	}
	if message := phase35FirecrackerHostSourceBoundaryMessage("allowed.go", allowedSource, file); message != "" {
		t.Fatalf("allowed local adapter fixture failed guard: %s", message)
	}
}

func phase35AssertNoFirecrackerHostAdapterWiring(t *testing.T, path string) {
	t.Helper()

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("Unquote import path %s in %s: %v", imported.Path.Value, path, err)
		}
		if message := phase35FirecrackerHostImportBoundaryMessage(path, importPath); message != "" {
			t.Fatal(message)
		}
	}
	if message := phase35FirecrackerHostSourceBoundaryMessage(path, string(source), file); message != "" {
		t.Fatal(message)
	}
}

func phase35DefaultCLIProductionFiles(t *testing.T) []string {
	t.Helper()
	return phase35ProductionFilesInDirs(t, ".")
}

func phase35FactoryProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{
		"factory.go",
		"factory_sandbox_executor.go",
	}
	paths = append(paths, phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "factory"))...)
	sort.Strings(paths)
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error: %v", path, err)
		}
	}
	return paths
}

func phase35WorkerProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{"sandbox_worker_runtime.go"}
	paths = append(paths, phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxworker"))...)
	sort.Strings(paths)
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error: %v", path, err)
		}
	}
	return paths
}

func phase35ProductionFilesInDirs(t *testing.T, dirs ...string) []string {
	t.Helper()

	var paths []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir(%s) error: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("Phase 35 default host adapter guard matched no production files in %s", strings.Join(dirs, ", "))
	}
	return paths
}

func phase35FirecrackerHostImportBoundaryMessage(fileName, importPath string) string {
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/") {
		return phase35DefaultHostAdapterBoundaryMessage(fileName, "imports Firecracker host adapter package "+strconv.Quote(importPath))
	}
	return ""
}

func phase35FirecrackerHostSourceBoundaryMessage(fileName, source string, file *ast.File) string {
	if message := phase34DefaultFirecrackerLiveBootBoundaryMessage(fileName, source, file); message != "" {
		return phase35DefaultHostAdapterBoundaryMessage(fileName, phase34LegacyFirecrackerBoundaryDetail(fileName, message))
	}

	bindings := phase35FirecrackerHostImportBindings(file)
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		switch typed := node.(type) {
		case *ast.CallExpr:
			if label := phase35FirecrackerHostCallLabel(typed, bindings); label != "" {
				selector := phase35FirecrackerHostExprName(typed.Fun)
				message = phase35DefaultHostAdapterBoundaryMessage(fileName, label+" via "+selector)
			}
		case *ast.CompositeLit:
			if label := phase35FirecrackerHostCompositeLabel(typed, bindings); label != "" {
				message = phase35DefaultHostAdapterBoundaryMessage(fileName, label+" in "+phase35FirecrackerHostExprName(typed.Type))
			}
		case *ast.BasicLit:
			if typed.Kind == token.STRING && phase35FirecrackerHostSelectionLiteral(typed.Value) {
				message = phase35DefaultHostAdapterBoundaryMessage(fileName, "Firecracker host adapter selection literal")
			}
		}
		return message == ""
	})
	return message
}

type phase35FirecrackerHostImportBinding struct {
	aliases map[string]bool
	dot     bool
}

func phase35FirecrackerHostImportBindings(file *ast.File) phase35FirecrackerHostImportBinding {
	binding := phase35FirecrackerHostImportBinding{aliases: map[string]bool{}}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if importPath != "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost" {
			continue
		}
		name := "firecrackerhost"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		switch name {
		case "_":
		case ".":
			binding.dot = true
		default:
			binding.aliases[name] = true
		}
	}
	return binding
}

func phase35FirecrackerHostCallLabel(call *ast.CallExpr, binding phase35FirecrackerHostImportBinding) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if ok {
		receiver, ok := selector.X.(*ast.Ident)
		if ok && binding.aliases[receiver.Name] {
			return phase35FirecrackerHostMemberLabel(selector.Sel.Name)
		}
	}
	if binding.dot {
		if ident, ok := call.Fun.(*ast.Ident); ok {
			return phase35FirecrackerHostMemberLabel(ident.Name)
		}
	}
	return ""
}

func phase35FirecrackerHostCompositeLabel(lit *ast.CompositeLit, binding phase35FirecrackerHostImportBinding) string {
	switch typed := lit.Type.(type) {
	case *ast.SelectorExpr:
		receiver, ok := typed.X.(*ast.Ident)
		if ok && binding.aliases[receiver.Name] {
			return phase35FirecrackerHostMemberLabel(typed.Sel.Name)
		}
	case *ast.Ident:
		if binding.dot {
			return phase35FirecrackerHostMemberLabel(typed.Name)
		}
	}
	return ""
}

func phase35FirecrackerHostMemberLabel(name string) string {
	switch name {
	case "NewAdapter", "Adapter":
		return "Firecracker host adapter construction"
	case "WithProcessRunner", "WithBootAcceptancePoller", "WithClock", "WithSleeper", "WithBootAcceptanceTimeout", "WithBootAcceptancePollInterval", "WithLiveProcessCleanup":
		return "Firecracker host adapter injection"
	case "NewProcessLifecycleManager", "ProcessLifecycleManager":
		return "Firecracker host process lifecycle construction"
	case "NewOSExecProcessRunner", "OSExecProcessRunner":
		return "Firecracker host process runner construction"
	default:
		return ""
	}
}

func phase35FirecrackerHostSelectionLiteral(literal string) bool {
	value, err := strconv.Unquote(literal)
	if err != nil {
		return false
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(value, "/") || strings.Contains(value, ".") {
		return false
	}
	for _, marker := range []string{"firecrackerhost", "firecracker-host", "firecracker_host"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func phase35FirecrackerHostExprName(expr ast.Expr) string {
	if name := phase33DefaultFirecrackerExprName(expr); name != "" {
		return name
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return "Firecracker host adapter expression"
}

func phase35DefaultHostAdapterBoundaryMessage(fileName, detail string) string {
	return phase33DefaultGuardDisplayPathNoFatal(fileName) + " " + detail + "; Phase 35 default CLI, factory, sandboxexec, and worker paths must not construct, select, or inject the Firecracker host adapter"
}
