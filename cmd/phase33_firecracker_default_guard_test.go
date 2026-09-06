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

func TestPhase33DefaultHalPathsDoNotImportFirecrackerLiveAdapter(t *testing.T) {
	for _, path := range phase33DefaultHalProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", path, err)
			}
			for _, imported := range file.Imports {
				importPath, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatalf("Unquote import path %s in %s: %v", imported.Path.Value, path, err)
				}
				if message := phase33DefaultFirecrackerImportBoundaryMessage(path, importPath); message != "" {
					t.Fatal(message)
				}
			}
		})
	}
}

func TestPhase33DefaultHalPathsDoNotConstructOrLaunchFirecracker(t *testing.T) {
	for _, path := range phase33DefaultHalProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s) error: %v", path, err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", path, err)
			}
			if message := phase33DefaultFirecrackerSourceBoundaryMessage(path, string(source), file); message != "" {
				t.Fatal(message)
			}
		})
	}
}

func TestPhase33DefaultFirecrackerGuardCoversRequiredPaths(t *testing.T) {
	paths := phase33DefaultHalProductionFiles(t)
	covered := make(map[string]bool, len(paths))
	for _, path := range paths {
		covered[filepath.ToSlash(filepath.Clean(path))] = true
	}
	for _, want := range []string{
		"run_sandbox.go",
		"auto_sandbox.go",
		"factory_sandbox_executor.go",
		"sandbox_runtime_compat.go",
		"sandbox_worker_runtime.go",
		"sandbox_scheduler_lease.go",
		"sandboxd.go",
		"../internal/sandboxtarget/scheduler_candidates.go",
		"../internal/sandboxtarget/scheduler_types.go",
		"../internal/factory/types.go",
		"../internal/factory/store.go",
		"../internal/sandboxexec/executor.go",
		"../internal/sandboxworker/service.go",
	} {
		clean := filepath.ToSlash(filepath.Clean(want))
		if !covered[clean] {
			t.Fatalf("Phase 33 default Firecracker guard does not cover %s", want)
		}
	}
}

func TestPhase33DefaultFirecrackerGuardRejectsLiveConstructionFixtures(t *testing.T) {
	importFixtures := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "internal Firecracker adapter package",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker",
			want:       "Firecracker adapter package",
		},
		{
			name:       "Firecracker SDK package",
			importPath: "github.com/firecracker-microvm/firecracker-go-sdk",
			want:       "Firecracker SDK package",
		},
	}
	for _, tt := range importFixtures {
		t.Run(tt.name, func(t *testing.T) {
			message := phase33DefaultFirecrackerImportBoundaryMessage("fixture.go", tt.importPath)
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
			name:   "Firecracker backend construction",
			source: `package cmd; func defaultPath() { _ = firecracker.NewBackend(options) }`,
			want:   "Firecracker backend construction",
		},
		{
			name:   "Firecracker process adapter construction",
			source: `package cmd; func defaultPath() { _ = firecracker.ProcessLaunchAdapter{Starter: starter} }`,
			want:   "Firecracker process adapter construction",
		},
		{
			name:   "explicit live start option",
			source: `package cmd; func defaultPath() { _ = BackendOptions{LiveStart: true} }`,
			want:   "Firecracker live-start option",
		},
		{
			name:   "literal Firecracker exec",
			source: `package cmd; import "os/exec"; func defaultPath() { _ = exec.Command("firecracker", "--api-sock", "sock") }`,
			want:   "Firecracker process launch",
		},
		{
			name:   "literal Firecracker command context",
			source: `package cmd; import "os/exec"; func defaultPath(ctx context.Context) { _ = exec.CommandContext(ctx, "/usr/bin/firecracker") }`,
			want:   "Firecracker process launch",
		},
	}
	for _, tt := range sourceFixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := phase33DefaultFirecrackerSourceBoundaryMessage(tt.name+".go", tt.source, file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}

	allowedSource := `package cmd; import "os/exec"; func defaultPath(ctx context.Context) { _ = exec.CommandContext(ctx, "git", "status") }`
	file, err := parser.ParseFile(token.NewFileSet(), "allowed.go", allowedSource, 0)
	if err != nil {
		t.Fatalf("ParseFile allowed fixture error: %v", err)
	}
	if message := phase33DefaultFirecrackerSourceBoundaryMessage("allowed.go", allowedSource, file); message != "" {
		t.Fatalf("allowed non-Firecracker process fixture failed guard: %s", message)
	}
}

func phase33DefaultHalProductionFiles(t *testing.T) []string {
	t.Helper()

	var paths []string
	for _, dir := range []string{
		".",
		filepath.Join("..", "internal", "factory"),
		filepath.Join("..", "internal", "sandboxexec"),
		filepath.Join("..", "internal", "sandboxtarget"),
		filepath.Join("..", "internal", "sandboxworker"),
	} {
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
		t.Fatal("Phase 33 default Firecracker guard matched no production files")
	}
	return paths
}

func phase33DefaultFirecrackerImportBoundaryMessage(fileName, importPath string) string {
	switch {
	case importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker/"):
		return phase33DefaultFirecrackerBoundaryMessage(fileName, "imports Firecracker adapter package "+strconv.Quote(importPath))
	case strings.HasPrefix(importPath, "github.com/firecracker-microvm"):
		return phase33DefaultFirecrackerBoundaryMessage(fileName, "imports Firecracker SDK package "+strconv.Quote(importPath))
	default:
		return ""
	}
}

func phase33DefaultFirecrackerSourceBoundaryMessage(fileName, source string, file *ast.File) string {
	for _, marker := range []struct {
		token string
		label string
	}{
		{token: "firecracker.NewBackend", label: "Firecracker backend construction"},
		{token: "firecracker.Backend{", label: "Firecracker backend construction"},
		{token: "firecracker.BackendOptions", label: "Firecracker backend construction"},
		{token: "firecracker.ProcessLaunchAdapter", label: "Firecracker process adapter construction"},
		{token: "firecracker.ProcessStarter", label: "Firecracker process adapter construction"},
		{token: "firecracker.ProcessRunnerStartRequest", label: "Firecracker process adapter construction"},
		{token: "firecracker.StartProcess", label: "Firecracker process launch"},
		{token: "LiveStart: true", label: "Firecracker live-start option"},
		{token: "github.com/firecracker-microvm", label: "Firecracker SDK package"},
	} {
		if strings.Contains(source, marker.token) {
			return phase33DefaultFirecrackerBoundaryMessage(fileName, marker.label+" marker "+strconv.Quote(marker.token))
		}
	}

	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if phase33DefaultFirecrackerLaunchCall(call) {
			selector := phase33DefaultFirecrackerCallSelectorName(call.Fun)
			message = phase33DefaultFirecrackerBoundaryMessage(fileName, "Firecracker process launch via "+selector+" with an executable literal")
			return false
		}
		return true
	})
	return message
}

func phase33DefaultFirecrackerLaunchCall(call *ast.CallExpr) bool {
	switch phase33DefaultFirecrackerCallSelectorName(call.Fun) {
	case "exec.Command", "exec.CommandContext", "os.StartProcess", "syscall.Exec":
		return phase33CallHasFirecrackerLiteralArg(call)
	default:
		return false
	}
}

func phase33CallHasFirecrackerLiteralArg(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(value), "firecracker") {
			return true
		}
	}
	return false
}

func phase33DefaultFirecrackerBoundaryMessage(fileName, detail string) string {
	return phase33DefaultGuardDisplayPathNoFatal(fileName) + " " + detail + "; Phase 33 default command, scheduler, factory, and sandboxd paths must stay planning-only and must not construct or launch Firecracker"
}

func phase33DefaultFirecrackerCallSelectorName(expr ast.Expr) string {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	receiver := phase33DefaultFirecrackerExprName(selector.X)
	if receiver == "" {
		return selector.Sel.Name
	}
	return receiver + "." + selector.Sel.Name
}

func phase33DefaultFirecrackerExprName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		parent := phase33DefaultFirecrackerExprName(typed.X)
		if parent == "" {
			return typed.Sel.Name
		}
		return parent + "." + typed.Sel.Name
	default:
		return ""
	}
}

func phase33DefaultGuardDisplayPath(t *testing.T, path string) string {
	t.Helper()
	return phase33DefaultGuardDisplayPathNoFatal(path)
}

func phase33DefaultGuardDisplayPathNoFatal(path string) string {
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "." {
		return "cmd"
	}
	if strings.HasPrefix(clean, "../") {
		return strings.TrimPrefix(clean, "../")
	}
	return filepath.ToSlash(filepath.Join("cmd", clean))
}
