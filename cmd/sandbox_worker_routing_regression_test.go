package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestWorkerRootlessFactorySandboxDefaultResolverBuildsClientDriver(t *testing.T) {
	deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("generic runtime resolver should not run for explicit worker-backed factory execution")
			return nil, nil
		},
	})

	selectedTarget := workerRootlessCachedSandbox("worker-rootless")
	driver, handled, err := deps.resolveFactorySandboxRuntimeDriver(factorySandboxExecutorRequest{
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
	}, sandboxRuntimeTargetFromState(selectedTarget), selectedTarget)
	if err != nil {
		t.Fatalf("resolveFactorySandboxRuntimeDriver() error = %v", err)
	}
	if !handled {
		t.Fatal("resolveFactorySandboxRuntimeDriver() handled = false, want true")
	}
	workerDriver, ok := driver.(*sandboxworker.ClientDriver)
	if !ok {
		t.Fatalf("driver type = %T, want *sandboxworker.ClientDriver", driver)
	}
	if workerDriver.ID() != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("driver ID = %q, want rootless_podman", workerDriver.ID())
	}
}

func TestWorkerMicroVMFactorySandboxDefaultResolverDoesNotFallbackToLocalDriver(t *testing.T) {
	deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("generic provider resolver should not run for selected worker microVM metadata")
			return nil, nil
		},
	})

	selectedTarget := workerMicroVMCachedSandbox("worker-microvm")
	driver, handled, err := deps.resolveFactorySandboxRuntimeDriver(factorySandboxExecutorRequest{
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverMicroVM,
	}, sandboxRuntimeTargetFromState(selectedTarget), selectedTarget)
	if err == nil {
		t.Fatal("resolveFactorySandboxRuntimeDriver() error = nil, want metadata-only microVM worker runtime to stay unsupported")
	}
	if !handled {
		t.Fatal("resolveFactorySandboxRuntimeDriver() handled = false, want worker route handled before generic local microVM resolver")
	}
	if driver != nil {
		t.Fatalf("driver = %#v, want nil for unsupported metadata-only microVM worker runtime", driver)
	}
	if !strings.Contains(err.Error(), `requested runtime "microvm" is not supported by worker-backed sandbox execution`) {
		t.Fatalf("error = %q, want worker-backed unsupported microVM runtime", err.Error())
	}
}

func TestWorkerMicroVMFactorySandboxResolverUsesInjectedWorkerHook(t *testing.T) {
	selectedTarget := workerMicroVMCachedSandbox("worker-microvm")
	var gotReq sandboxWorkerRuntimeRequest
	deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{
		resolveWorkerRuntime: func(req sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			gotReq = req
			return fakeRuntimeResolverDriver{id: sandboxruntime.DriverMicroVM}, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("generic provider resolver should not run for selected worker microVM metadata")
			return nil, nil
		},
	})

	driver, handled, err := deps.resolveFactorySandboxRuntimeDriver(factorySandboxExecutorRequest{
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverMicroVM,
	}, sandboxRuntimeTargetFromState(selectedTarget), selectedTarget)
	if err != nil {
		t.Fatalf("resolveFactorySandboxRuntimeDriver() error = %v", err)
	}
	if !handled {
		t.Fatal("resolveFactorySandboxRuntimeDriver() handled = false, want true for injected microVM worker hook")
	}
	if driver == nil || driver.ID() != sandboxruntime.DriverMicroVM {
		t.Fatalf("driver = %#v, want injected microVM worker driver", driver)
	}
	if gotReq.Host != selectedTarget.Host {
		t.Fatalf("worker hook host = %#v, want selected worker host", gotReq.Host)
	}
	if gotReq.Target.Runtime.Driver != sandboxruntime.DriverMicroVM {
		t.Fatalf("worker hook runtime = %#v, want microVM target metadata", gotReq.Target.Runtime)
	}
}

func TestWorkerExecutionRuntimeConstructionStaysCentralized(t *testing.T) {
	executionFiles := []string{
		"run_sandbox.go",
		"auto_sandbox.go",
		"factory_sandbox_executor.go",
	}
	for _, file := range executionFiles {
		t.Run(file, func(t *testing.T) {
			source, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("ReadFile(%s) error: %v", file, err)
			}
			if !strings.Contains(string(source), "sandboxWorkerRuntimeDriverFromTarget") {
				t.Fatalf("%s no longer routes default worker-backed execution through sandboxWorkerRuntimeDriverFromTarget", file)
			}
			if importsPackage(t, file, "github.com/jywlabs/hal/internal/sandboxworker") {
				t.Fatalf("%s imports sandboxworker directly; worker-backed runtime construction should stay in sandbox_worker_runtime.go", file)
			}
		})
	}

	callSites := sandboxWorkerClientDriverConstructorCallSites(t)
	if len(callSites) != 1 {
		t.Fatalf("sandboxworker.NewClientDriver call sites = %v, want exactly one shared resolver call site", callSites)
	}
	if callSites[0] != "sandbox_worker_runtime.go" {
		t.Fatalf("sandboxworker.NewClientDriver call site = %s, want sandbox_worker_runtime.go", callSites[0])
	}
}

func workerMicroVMCachedSandbox(name string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       name,
		Name:     name,
		Provider: "worker",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:                "worker-1",
			Name:              "worker one",
			Kind:              sandbox.SandboxHostKindWorker,
			Endpoint:          "unix:///tmp/private/worker-1.sock",
			SupportedRuntimes: []string{sandboxruntime.DriverMicroVM},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverMicroVM,
			RuntimeID:      "microvm-dev",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
		},
	}
}

func importsPackage(t *testing.T, path, importPath string) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	for _, imported := range file.Imports {
		value, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("Unquote import path %s in %s: %v", imported.Path.Value, path, err)
		}
		if value == importPath {
			return true
		}
	}
	return false
}

func sandboxWorkerClientDriverConstructorCallSites(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(*.go) error: %v", err)
	}
	var callSites []string
	for _, path := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		sandboxWorkerNames := sandboxWorkerImportNames(t, file, path)
		if len(sandboxWorkerNames) == 0 {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "NewClientDriver" {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || !sandboxWorkerNames[ident.Name] {
				return true
			}
			callSites = append(callSites, filepath.Base(path))
			return true
		})
	}
	return callSites
}

func sandboxWorkerImportNames(t *testing.T, file *ast.File, path string) map[string]bool {
	t.Helper()
	names := make(map[string]bool)
	for _, imported := range file.Imports {
		value, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("Unquote import path %s in %s: %v", imported.Path.Value, path, err)
		}
		if value != "github.com/jywlabs/hal/internal/sandboxworker" {
			continue
		}
		name := "sandboxworker"
		if imported.Name != nil {
			name = imported.Name.Name
		}
		names[name] = true
	}
	return names
}
