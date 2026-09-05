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

func TestPhase36DefaultCommandPathsDoNotImportOrConstructExplicitFirecrackerLiveDriver(t *testing.T) {
	for _, path := range phase35DefaultCLIProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase36AssertNoExplicitFirecrackerLiveDriverWiring(t, path)
		})
	}
}

func TestPhase36FactoryDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver(t *testing.T) {
	for _, path := range phase35FactoryProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase36AssertNoExplicitFirecrackerLiveDriverWiring(t, path)
		})
	}
}

func TestPhase36SandboxexecDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver(t *testing.T) {
	for _, path := range phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec")) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase36AssertNoExplicitFirecrackerLiveDriverWiring(t, path)
		})
	}
}

func TestPhase36WorkerDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver(t *testing.T) {
	for _, path := range phase35WorkerProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase36AssertNoExplicitFirecrackerLiveDriverWiring(t, path)
		})
	}
}

func TestPhase36SchedulerDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver(t *testing.T) {
	for _, path := range phase36SchedulerDefaultProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase36AssertNoExplicitFirecrackerLiveDriverWiring(t, path)
		})
	}
}

func TestPhase36SandboxdDefaultsDoNotImportOrConstructExplicitFirecrackerLiveDriver(t *testing.T) {
	for _, path := range phase36SandboxdDefaultProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase36AssertNoExplicitFirecrackerLiveDriverWiring(t, path)
		})
	}
}

func TestPhase36FirecrackerExplicitLiveDriverGuardCoversRequiredSurfaces(t *testing.T) {
	all := append([]string{}, phase35DefaultCLIProductionFiles(t)...)
	all = append(all, phase35FactoryProductionFiles(t)...)
	all = append(all, phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec"))...)
	all = append(all, phase35WorkerProductionFiles(t)...)
	all = append(all, phase36SchedulerDefaultProductionFiles(t)...)
	all = append(all, phase36SandboxdDefaultProductionFiles(t)...)

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
		"sandbox_scheduler_lease.go",
		"sandboxd.go",
		"../internal/factory/types.go",
		"../internal/factory/store.go",
		"../internal/sandboxexec/executor.go",
		"../internal/sandboxworker/adapter.go",
		"../internal/sandboxworker/service.go",
		"../internal/sandboxworker/types.go",
		"../internal/sandboxtarget/scheduler_candidates.go",
		"../internal/sandboxtarget/scheduler_types.go",
		"../internal/sandboxtarget/select.go",
	} {
		clean := filepath.ToSlash(filepath.Clean(want))
		if !covered[clean] {
			t.Fatalf("Phase 36 explicit Firecracker live driver guard does not cover %s", want)
		}
	}
}

func TestPhase36ExplicitSandboxdFirecrackerLiveDriverPathAllowsOnlyExplicitLiveDriver(t *testing.T) {
	_, file := phase39ReadExplicitSandboxdFirecrackerLiveDriver(t)
	if !phase39ImportsFirecrackerHost(file) {
		t.Fatalf("%s does not import %s", phase39ExplicitSandboxdFirecrackerLiveDriverPath, phase39FirecrackerHostImportPath)
	}
	if message := phase36FirecrackerLiveDriverImportBoundaryMessage(phase39ExplicitSandboxdFirecrackerLiveDriverPath, phase39FirecrackerHostImportPath); message == "" {
		t.Fatalf("Phase 36 live-driver import guard did not reject %s outside the explicit sandboxd exception", phase39FirecrackerHostImportPath)
	}
	if message := phase36FirecrackerLiveDriverSourceBoundaryMessage(phase39ExplicitSandboxdFirecrackerLiveDriverPath, file); message == "" {
		t.Fatalf("Phase 36 live-driver source guard did not detect explicit sandboxd Firecracker live-driver construction")
	}
}

func TestPhase36FirecrackerExplicitLiveDriverGuardRejectsFixtures(t *testing.T) {
	importFixtures := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "Firecracker host live driver package",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost",
			want:       "Firecracker explicit live driver package",
		},
		{
			name:       "Firecracker host live driver subpackage",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/internaltest",
			want:       "Firecracker explicit live driver package",
		},
	}
	for _, tt := range importFixtures {
		t.Run(tt.name, func(t *testing.T) {
			message := phase36FirecrackerLiveDriverImportBoundaryMessage("fixture.go", tt.importPath)
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
			name:   "live driver constructor",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _, _ = firecrackerhost.NewLiveDriver(firecrackerhost.LiveDriverOptions{}) }`,
			want:   "Firecracker explicit live driver constructor",
		},
		{
			name:   "aliased live backend options constructor",
			source: `package cmd; import fc "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _, _ = fc.NewLiveBackendOptions(fc.LiveDriverOptions{}) }`,
			want:   "Firecracker explicit live backend options constructor",
		},
		{
			name:   "dot imported live driver constructor",
			source: `package cmd; import . "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _, _ = NewLiveDriver(LiveDriverOptions{}) }`,
			want:   "Firecracker explicit live driver constructor",
		},
		{
			name:   "live driver options literal",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _ = firecrackerhost.LiveDriverOptions{} }`,
			want:   "Firecracker explicit live driver options",
		},
	}
	for _, tt := range sourceFixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := phase36FirecrackerLiveDriverSourceBoundaryMessage(tt.name+".go", file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}

	allowedSource := `package cmd; func defaultPath() { _, _ = NewLiveDriver(localOptions{}) }`
	file, err := parser.ParseFile(token.NewFileSet(), "allowed.go", allowedSource, 0)
	if err != nil {
		t.Fatalf("ParseFile allowed fixture error: %v", err)
	}
	if message := phase36FirecrackerLiveDriverSourceBoundaryMessage("allowed.go", file); message != "" {
		t.Fatalf("allowed local constructor fixture failed guard: %s", message)
	}
}

func phase36AssertNoExplicitFirecrackerLiveDriverWiring(t *testing.T, path string) {
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
		if message := phase36FirecrackerLiveDriverImportBoundaryMessage(path, importPath); message != "" {
			t.Fatal(message)
		}
	}
	if message := phase36FirecrackerLiveDriverSourceBoundaryMessage(path, file); message != "" {
		t.Fatal(message)
	}
}

func phase36SchedulerDefaultProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{
		"sandbox_scheduler_lease.go",
		"sandbox_target_selection.go",
	}
	paths = append(paths, phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxtarget"))...)
	sort.Strings(paths)
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error: %v", path, err)
		}
	}
	return paths
}

func phase36SandboxdDefaultProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{"sandboxd.go"}
	sort.Strings(paths)
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error: %v", path, err)
		}
	}
	return paths
}

func phase36FirecrackerLiveDriverImportBoundaryMessage(fileName, importPath string) string {
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/") {
		return phase36DefaultLiveDriverBoundaryMessage(fileName, "imports Firecracker explicit live driver package "+strconv.Quote(importPath))
	}
	return ""
}

func phase36FirecrackerLiveDriverSourceBoundaryMessage(fileName string, file *ast.File) string {
	bindings := phase35FirecrackerHostImportBindings(file)
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		switch typed := node.(type) {
		case *ast.CallExpr:
			if label := phase36FirecrackerLiveDriverCallLabel(typed, bindings); label != "" {
				message = phase36DefaultLiveDriverBoundaryMessage(fileName, label+" via "+phase35FirecrackerHostExprName(typed.Fun))
			}
		case *ast.CompositeLit:
			if label := phase36FirecrackerLiveDriverCompositeLabel(typed, bindings); label != "" {
				message = phase36DefaultLiveDriverBoundaryMessage(fileName, label+" in "+phase35FirecrackerHostExprName(typed.Type))
			}
		case *ast.SelectorExpr:
			if label := phase36FirecrackerLiveDriverSelectorLabel(typed, bindings); label != "" {
				message = phase36DefaultLiveDriverBoundaryMessage(fileName, label+" reference "+phase35FirecrackerHostExprName(typed))
			}
		case *ast.Ident:
			if bindings.dot && typed.Name == "LiveDriverOptions" {
				message = phase36DefaultLiveDriverBoundaryMessage(fileName, "Firecracker explicit live driver options reference "+typed.Name)
			}
		}
		return message == ""
	})
	return message
}

func phase36FirecrackerLiveDriverCallLabel(call *ast.CallExpr, binding phase35FirecrackerHostImportBinding) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if ok {
		receiver, ok := selector.X.(*ast.Ident)
		if ok && binding.aliases[receiver.Name] {
			return phase36FirecrackerLiveDriverMemberLabel(selector.Sel.Name)
		}
	}
	if binding.dot {
		if ident, ok := call.Fun.(*ast.Ident); ok {
			return phase36FirecrackerLiveDriverMemberLabel(ident.Name)
		}
	}
	return ""
}

func phase36FirecrackerLiveDriverCompositeLabel(lit *ast.CompositeLit, binding phase35FirecrackerHostImportBinding) string {
	switch typed := lit.Type.(type) {
	case *ast.SelectorExpr:
		receiver, ok := typed.X.(*ast.Ident)
		if ok && binding.aliases[receiver.Name] {
			return phase36FirecrackerLiveDriverMemberLabel(typed.Sel.Name)
		}
	case *ast.Ident:
		if binding.dot {
			return phase36FirecrackerLiveDriverMemberLabel(typed.Name)
		}
	}
	return ""
}

func phase36FirecrackerLiveDriverSelectorLabel(selector *ast.SelectorExpr, binding phase35FirecrackerHostImportBinding) string {
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !binding.aliases[receiver.Name] {
		return ""
	}
	return phase36FirecrackerLiveDriverMemberLabel(selector.Sel.Name)
}

func phase36FirecrackerLiveDriverMemberLabel(name string) string {
	switch name {
	case "NewLiveDriver":
		return "Firecracker explicit live driver constructor"
	case "NewLiveBackendOptions":
		return "Firecracker explicit live backend options constructor"
	case "LiveDriverOptions":
		return "Firecracker explicit live driver options"
	default:
		return ""
	}
}

func phase36DefaultLiveDriverBoundaryMessage(fileName, detail string) string {
	return phase33DefaultGuardDisplayPathNoFatal(fileName) + " " + detail + "; Phase 36 default command, factory, sandboxexec, worker, scheduler, and sandboxd paths must not import or construct the explicit Firecracker live driver"
}
