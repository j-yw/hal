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

func TestPhase34DefaultPathsDoNotWireFirecrackerLiveBoot(t *testing.T) {
	for _, path := range phase34DefaultFirecrackerProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
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
				if message := phase33DefaultFirecrackerImportBoundaryMessage(path, importPath); message != "" {
					t.Fatal(message)
				}
			}
			if message := phase34DefaultFirecrackerLiveBootBoundaryMessage(path, string(source), file); message != "" {
				t.Fatal(message)
			}
		})
	}
}

func TestPhase34DefaultRunAutoFactoryPathsDoNotStartFirecracker(t *testing.T) {
	for _, path := range phase34DefaultRunAutoFactoryProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s) error: %v", path, err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", path, err)
			}
			if message := phase34DefaultFirecrackerLiveBootBoundaryMessage(path, string(source), file); message != "" {
				t.Fatal(message)
			}
		})
	}
}

func TestPhase34DefaultFirecrackerGuardCoversRequiredSurfaces(t *testing.T) {
	paths := phase34DefaultFirecrackerProductionFiles(t)
	covered := make(map[string]bool, len(paths))
	for _, path := range paths {
		covered[filepath.ToSlash(filepath.Clean(path))] = true
	}
	for _, want := range []string{
		"run_sandbox.go",
		"auto_sandbox.go",
		"factory.go",
		"factory_sandbox_executor.go",
		"sandbox_scheduler_lease.go",
		"sandbox_worker_runtime.go",
		"sandboxd.go",
		"../internal/factory/types.go",
		"../internal/factory/store.go",
		"../internal/sandboxexec/executor.go",
		"../internal/sandboxtarget/scheduler_candidates.go",
		"../internal/sandboxtarget/scheduler_types.go",
		"../internal/sandboxtarget/select.go",
		"../internal/sandboxworker/adapter.go",
		"../internal/sandboxworker/service.go",
		"../internal/sandboxworker/types.go",
	} {
		clean := filepath.ToSlash(filepath.Clean(want))
		if !covered[clean] {
			t.Fatalf("Phase 34 default Firecracker guard does not cover %s", want)
		}
	}
}

func TestPhase34DefaultFirecrackerGuardRejectsLiveBootFixtures(t *testing.T) {
	importFixtures := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "internal Firecracker live adapter package",
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
			phase34Message := phase34DefaultFirecrackerBoundaryMessage("fixture.go", phase34LegacyFirecrackerBoundaryDetail("fixture.go", message))
			if !strings.Contains(phase34Message, "Phase 34") || !strings.Contains(phase34Message, tt.want) {
				t.Fatalf("phase 34 boundary message = %q, want Phase 34 rejection for %q", phase34Message, tt.want)
			}
		})
	}

	sourceFixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "unqualified live start option",
			source: `package cmd; func defaultPath() { _ = BackendOptions{LiveStart: true} }`,
			want:   "Firecracker live-start option",
		},
		{
			name:   "boot acceptance waiter field",
			source: `package cmd; func defaultPath(waiter any) { _ = BackendOptions{BootAcceptanceWaiter: waiter} }`,
			want:   "Firecracker live boot options",
		},
		{
			name:   "live process manager field",
			source: `package cmd; func defaultPath(manager any) { _ = BackendOptions{LiveProcessManager: manager} }`,
			want:   "Firecracker live boot options",
		},
		{
			name:   "process launch adapter literal",
			source: `package cmd; func defaultPath(starter any) { _ = ProcessLaunchAdapter{Starter: starter} }`,
			want:   "Firecracker process adapter construction",
		},
		{
			name:   "process runner request literal",
			source: `package cmd; func defaultPath() { _ = ProcessRunnerStartRequest{Executable: "/usr/bin/firecracker"} }`,
			want:   "Firecracker process adapter construction",
		},
		{
			name:   "explicit start process helper",
			source: `package cmd; func defaultPath(ctx context.Context, adapter any, descriptor any) { _, _ = firecracker.StartProcess(ctx, adapter, descriptor) }`,
			want:   "Firecracker process launch",
		},
		{
			name:   "literal firecracker process command",
			source: `package cmd; import "os/exec"; func defaultPath() { _ = exec.Command("firecracker", "--api-sock", "/tmp/firecracker.sock") }`,
			want:   "Firecracker process launch",
		},
	}
	for _, tt := range sourceFixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := phase34DefaultFirecrackerLiveBootBoundaryMessage(tt.name+".go", tt.source, file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}

	allowedSource := `package cmd; func defaultPath() { _ = microvm.New() }`
	file, err := parser.ParseFile(token.NewFileSet(), "allowed.go", allowedSource, 0)
	if err != nil {
		t.Fatalf("ParseFile allowed fixture error: %v", err)
	}
	if message := phase34DefaultFirecrackerLiveBootBoundaryMessage("allowed.go", allowedSource, file); message != "" {
		t.Fatalf("allowed microVM compatibility fixture failed guard: %s", message)
	}
}

func phase34DefaultFirecrackerProductionFiles(t *testing.T) []string {
	t.Helper()

	paths := phase33DefaultHalProductionFiles(t)
	sort.Strings(paths)
	return paths
}

func phase34DefaultRunAutoFactoryProductionFiles(t *testing.T) []string {
	t.Helper()

	paths := []string{
		"run.go",
		"run_sandbox.go",
		"auto.go",
		"auto_sandbox.go",
		"factory.go",
		"factory_sandbox_executor.go",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("Stat(%s) error: %v", path, err)
		}
	}
	return paths
}

func phase34DefaultFirecrackerLiveBootBoundaryMessage(fileName, source string, file *ast.File) string {
	if message := phase33DefaultFirecrackerSourceBoundaryMessage(fileName, source, file); message != "" {
		return phase34DefaultFirecrackerBoundaryMessage(fileName, phase34LegacyFirecrackerBoundaryDetail(fileName, message))
	}
	for _, marker := range []struct {
		token string
		label string
	}{
		{token: "BackendOptions{", label: "Firecracker live boot options"},
		{token: "LiveStart:", label: "Firecracker live boot options"},
		{token: "BootAcceptanceWaiter:", label: "Firecracker live boot options"},
		{token: "LiveProcessManager:", label: "Firecracker live boot options"},
		{token: "ProcessAdapter:", label: "Firecracker process adapter construction"},
		{token: "ProcessLaunchAdapter{", label: "Firecracker process adapter construction"},
		{token: "ProcessRunnerStartRequest{", label: "Firecracker process adapter construction"},
		{token: "firecracker.StartProcess", label: "Firecracker process launch"},
		{token: "WaitForBootAcceptance(", label: "Firecracker boot acceptance wiring"},
		{token: "CleanupLiveProcess(", label: "Firecracker live process cleanup wiring"},
		{token: "StopLiveProcess(", label: "Firecracker live process cleanup wiring"},
		{token: "DeleteLiveProcess(", label: "Firecracker live process cleanup wiring"},
	} {
		if strings.Contains(source, marker.token) {
			return phase34DefaultFirecrackerBoundaryMessage(fileName, marker.label+" marker "+strconv.Quote(marker.token))
		}
	}

	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		switch typed := node.(type) {
		case *ast.CompositeLit:
			typeName := phase33DefaultFirecrackerExprName(typed.Type)
			switch {
			case strings.HasSuffix(typeName, "BackendOptions"):
				if phase34CompositeLiteralHasFirecrackerLiveField(typed) {
					message = phase34DefaultFirecrackerBoundaryMessage(fileName, "Firecracker live boot options in "+typeName)
				}
			case strings.HasSuffix(typeName, "ProcessLaunchAdapter"),
				strings.HasSuffix(typeName, "ProcessRunnerStartRequest"):
				message = phase34DefaultFirecrackerBoundaryMessage(fileName, "Firecracker process adapter construction in "+typeName)
			}
		case *ast.CallExpr:
			if phase33DefaultFirecrackerLaunchCall(typed) {
				selector := phase33DefaultFirecrackerCallSelectorName(typed.Fun)
				message = phase34DefaultFirecrackerBoundaryMessage(fileName, "Firecracker process launch via "+selector+" with an executable literal")
			}
		}
		return message == ""
	})
	return message
}

func phase34LegacyFirecrackerBoundaryDetail(fileName, message string) string {
	prefix := phase33DefaultGuardDisplayPathNoFatal(fileName) + " "
	detail := strings.TrimPrefix(message, prefix)
	if beforeSemicolon, _, ok := strings.Cut(detail, ";"); ok {
		detail = beforeSemicolon
	}
	return strings.TrimSpace(detail)
}

func phase34CompositeLiteralHasFirecrackerLiveField(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "LiveStart", "ProcessAdapter", "BootAcceptanceWaiter", "LiveProcessManager":
			return true
		}
	}
	return false
}

func phase34DefaultFirecrackerBoundaryMessage(fileName, detail string) string {
	return phase33DefaultGuardDisplayPathNoFatal(fileName) + " " + detail + "; Phase 34 default command, factory, scheduler, sandboxexec, sandboxd, and worker paths must not import live Firecracker adapter types, construct live boot options, or start Firecracker"
}
