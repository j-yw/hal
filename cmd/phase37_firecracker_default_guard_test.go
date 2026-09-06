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
)

func TestPhase37DefaultCommandPathsDoNotWireFirecrackerGuestReadiness(t *testing.T) {
	for _, path := range phase35DefaultCLIProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase37AssertNoFirecrackerGuestReadinessWiring(t, path)
		})
	}
}

func TestPhase37FactoryDefaultsDoNotWireFirecrackerGuestReadiness(t *testing.T) {
	for _, path := range phase35FactoryProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase37AssertNoFirecrackerGuestReadinessWiring(t, path)
		})
	}
}

func TestPhase37SandboxexecDefaultsDoNotWireFirecrackerGuestReadiness(t *testing.T) {
	for _, path := range phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec")) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase37AssertNoFirecrackerGuestReadinessWiring(t, path)
		})
	}
}

func TestPhase37WorkerDefaultsDoNotWireFirecrackerGuestReadiness(t *testing.T) {
	for _, path := range phase35WorkerProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase37AssertNoFirecrackerGuestReadinessWiring(t, path)
		})
	}
}

func TestPhase37SchedulerDefaultsDoNotWireFirecrackerGuestReadiness(t *testing.T) {
	for _, path := range phase36SchedulerDefaultProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase37AssertNoFirecrackerGuestReadinessWiring(t, path)
		})
	}
}

func TestPhase37SandboxdDefaultsDoNotWireFirecrackerGuestReadiness(t *testing.T) {
	for _, path := range phase36SandboxdDefaultProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase37AssertNoFirecrackerGuestReadinessWiring(t, path)
		})
	}
}

func TestPhase37FirecrackerGuestReadinessGuardCoversRequiredDefaultSurfaces(t *testing.T) {
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
		"sandbox_target_selection.go",
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
			t.Fatalf("Phase 37 guest readiness default guard does not cover %s", want)
		}
	}
}

func TestPhase37ExplicitSandboxdFirecrackerLiveDriverPathAllowsConfiguredGuestReadiness(t *testing.T) {
	source, _ := phase39ReadExplicitSandboxdFirecrackerLiveDriver(t)
	for _, marker := range []string{
		"NewGuestAgentEndpointAdapters",
		"GuestReadinessProbe:",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("%s missing configured guest readiness marker %q", phase39ExplicitSandboxdFirecrackerLiveDriverPath, marker)
		}
	}
	for _, marker := range []string{
		"GuestReadinessWaiter",
		"WithGuestReadinessProbe",
		"WithGuestReadinessTimeout",
		"WithGuestReadinessPollInterval",
		"WaitForGuestReadiness",
		"ProbeGuestReadiness",
		"NewGuestReadinessRequest",
		"NewGuestReadinessResult",
		"RuntimeGuestReadinessMetadata",
		"GuestReadiness:",
	} {
		if strings.Contains(source, marker) {
			t.Fatalf("%s contains guest readiness marker %q outside endpoint-based live-driver wiring", phase39ExplicitSandboxdFirecrackerLiveDriverPath, marker)
		}
	}
}

func TestPhase37RunAutoFactoryDefaultsDoNotSelectFirecrackerRuntime(t *testing.T) {
	runReq, err := parseRunSandboxRequest(nil, runSandboxOptions{})
	if err != nil {
		t.Fatalf("parseRunSandboxRequest() error = %v", err)
	}
	if runReq.SandboxRuntime != "" {
		t.Fatalf("run sandbox default runtime = %q, want empty default", runReq.SandboxRuntime)
	}

	autoReq, err := parseAutoSandboxRequest(nil, autoSandboxOptions{})
	if err != nil {
		t.Fatalf("parseAutoSandboxRequest() error = %v", err)
	}
	if autoReq.SandboxRuntime != "" {
		t.Fatalf("auto sandbox default runtime = %q, want empty default", autoReq.SandboxRuntime)
	}

	factoryReq, err := parseFactoryRunRequestWithTarget([]string{".hal/prd-feature.md"}, "", "main", false, true, sandboxTargetFlagValues{}, "", false, "", false, false, false, "", false)
	if err != nil {
		t.Fatalf("parseFactoryRunRequestWithTarget() error = %v", err)
	}
	if factoryReq.SandboxRuntime != "" {
		t.Fatalf("factory sandbox default runtime = %q, want empty default", factoryReq.SandboxRuntime)
	}

	originalFactories := defaultSandboxRuntimeDriverFactories
	t.Cleanup(func() {
		defaultSandboxRuntimeDriverFactories = originalFactories
	})
	defaultSandboxRuntimeDriverFactories = func() sandboxRuntimeDriverFactories {
		return sandboxRuntimeDriverFactories{
			sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverSSHMachine}
			},
			rootlessPodman: func() sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverRootlessPodman}
			},
			microVM: func() sandboxruntime.Driver {
				t.Fatal("default run/auto/factory resolver selected Firecracker microVM without explicit runtime metadata")
				return nil
			},
		}
	}

	resolvers := []struct {
		name  string
		build func(func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error)
	}{
		{
			name: "run",
			build: func(resolveProvider func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				deps := normalizeRunSandboxDeps(runSandboxDeps{resolveProvider: resolveProvider})
				return deps.resolveRuntimeDriver
			},
		},
		{
			name: "auto",
			build: func(resolveProvider func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				deps := normalizeAutoSandboxDeps(autoSandboxDeps{resolveProvider: resolveProvider})
				return deps.resolveRuntimeDriver
			},
		},
		{
			name: "factory",
			build: func(resolveProvider func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{resolveProvider: resolveProvider})
				return deps.resolveRuntimeDriver
			},
		},
	}

	for _, resolver := range resolvers {
		t.Run(resolver.name, func(t *testing.T) {
			providerCalls := 0
			resolveProvider := func(providerName string) (sandbox.Provider, error) {
				providerCalls++
				if providerName != "test-provider" {
					t.Fatalf("providerName = %q, want test-provider", providerName)
				}
				return fakeFactorySandboxProvider{}, nil
			}
			driver, err := resolver.build(resolveProvider)(sandboxruntime.Target{Provider: "test-provider"})
			if err != nil {
				t.Fatalf("resolveRuntimeDriver() error = %v", err)
			}
			if driver == nil || driver.ID() != sandboxruntime.DriverSSHMachine {
				t.Fatalf("driver = %#v, want SSH-machine default", driver)
			}
			if providerCalls != 1 {
				t.Fatalf("resolveProvider calls = %d, want 1 for SSH-machine default", providerCalls)
			}
		})
	}
}

func TestPhase37FirecrackerGuestReadinessGuardRejectsFixtures(t *testing.T) {
	importFixtures := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "Firecracker backend package",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker",
			want:       "Firecracker backend package",
		},
		{
			name:       "Firecracker host guest readiness package",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost",
			want:       "Firecracker guest readiness host package",
		},
	}
	for _, tt := range importFixtures {
		t.Run(tt.name, func(t *testing.T) {
			message := phase37FirecrackerGuestReadinessImportBoundaryMessage("fixture.go", tt.importPath)
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
			name:   "backend guest readiness waiter option",
			source: `package cmd; func defaultPath(waiter any) { _ = BackendOptions{GuestReadinessWaiter: waiter} }`,
			want:   "Firecracker guest readiness backend option",
		},
		{
			name:   "live driver guest readiness probe option",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath(probe firecrackerhost.GuestReadinessProbe) { _ = firecrackerhost.LiveDriverOptions{GuestReadinessProbe: probe} }`,
			want:   "Firecracker guest readiness probe option",
		},
		{
			name:   "guest readiness probe injection",
			source: `package cmd; import fc "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath(probe fc.GuestReadinessProbe) { _ = fc.WithGuestReadinessProbe(probe) }`,
			want:   "Firecracker guest readiness probe injection",
		},
		{
			name:   "dot imported guest readiness timeout option",
			source: `package cmd; import . "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath() { _ = WithGuestReadinessTimeout(timeout) }`,
			want:   "Firecracker guest readiness polling option",
		},
		{
			name:   "guest readiness wait call",
			source: `package cmd; func defaultPath(waiter interface{ WaitForGuestReadiness(any, GuestReadinessRequest) (GuestReadinessResult, error) }) { _, _ = waiter.WaitForGuestReadiness(nil, GuestReadinessRequest{}) }`,
			want:   "Firecracker guest readiness wait",
		},
	}
	for _, tt := range sourceFixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := phase37FirecrackerGuestReadinessSourceBoundaryMessage(tt.name+".go", tt.source, file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}

	allowedSource := `package cmd; func defaultPath() { _ = sandboxRuntimeCapabilityReadinessFromWorkerPolicy }`
	file, err := parser.ParseFile(token.NewFileSet(), "allowed.go", allowedSource, 0)
	if err != nil {
		t.Fatalf("ParseFile allowed fixture error: %v", err)
	}
	if message := phase37FirecrackerGuestReadinessSourceBoundaryMessage("allowed.go", allowedSource, file); message != "" {
		t.Fatalf("allowed capability-readiness fixture failed guard: %s", message)
	}
}

func phase37AssertNoFirecrackerGuestReadinessWiring(t *testing.T, path string) {
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
		if message := phase37FirecrackerGuestReadinessImportBoundaryMessage(path, importPath); message != "" {
			t.Fatal(message)
		}
	}
	if message := phase37FirecrackerGuestReadinessSourceBoundaryMessage(path, string(source), file); message != "" {
		t.Fatal(message)
	}
}

func phase37FirecrackerGuestReadinessImportBoundaryMessage(fileName, importPath string) string {
	switch {
	case importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker/"):
		return phase37DefaultGuestReadinessBoundaryMessage(fileName, "imports Firecracker backend package "+strconv.Quote(importPath))
	case importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/"):
		return phase37DefaultGuestReadinessBoundaryMessage(fileName, "imports Firecracker guest readiness host package "+strconv.Quote(importPath))
	case strings.HasPrefix(importPath, "github.com/firecracker-microvm"):
		return phase37DefaultGuestReadinessBoundaryMessage(fileName, "imports Firecracker SDK package "+strconv.Quote(importPath))
	default:
		return ""
	}
}

func phase37FirecrackerGuestReadinessSourceBoundaryMessage(fileName, source string, file *ast.File) string {
	for _, marker := range []struct {
		token string
		label string
	}{
		{token: "GuestReadinessWaiter:", label: "Firecracker guest readiness backend option"},
		{token: "GuestReadinessProbe:", label: "Firecracker guest readiness probe option"},
		{token: "GuestTimeout:", label: "Firecracker guest readiness polling option"},
		{token: "GuestPollInterval:", label: "Firecracker guest readiness polling option"},
		{token: "WithGuestReadinessProbe(", label: "Firecracker guest readiness probe injection"},
		{token: "WithGuestReadinessTimeout(", label: "Firecracker guest readiness polling option"},
		{token: "WithGuestReadinessPollInterval(", label: "Firecracker guest readiness polling option"},
		{token: "WaitForGuestReadiness(", label: "Firecracker guest readiness wait"},
		{token: "ProbeGuestReadiness(", label: "Firecracker guest readiness probe call"},
		{token: "NewGuestReadinessRequest(", label: "Firecracker guest readiness request construction"},
		{token: "NewGuestReadinessResult(", label: "Firecracker guest readiness result construction"},
		{token: "RuntimeGuestReadinessMetadata{", label: "Firecracker guest readiness metadata construction"},
		{token: "GuestReadiness:", label: "Firecracker guest readiness metadata construction"},
	} {
		if strings.Contains(source, marker.token) {
			return phase37DefaultGuestReadinessBoundaryMessage(fileName, marker.label+" marker "+strconv.Quote(marker.token))
		}
	}

	if message := phase36FirecrackerLiveDriverSourceBoundaryMessage(fileName, file); message != "" {
		return phase37DefaultGuestReadinessBoundaryMessage(fileName, phase34LegacyFirecrackerBoundaryDetail(fileName, message))
	}
	if message := phase35FirecrackerHostSourceBoundaryMessage(fileName, source, file); message != "" {
		return phase37DefaultGuestReadinessBoundaryMessage(fileName, phase34LegacyFirecrackerBoundaryDetail(fileName, message))
	}

	firecrackerHost := phase35FirecrackerHostImportBindings(file)
	firecrackerBackend := phase37ImportBindings(file, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker")
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		switch typed := node.(type) {
		case *ast.CallExpr:
			if label := phase37GuestReadinessCallLabel(typed, firecrackerHost, firecrackerBackend); label != "" {
				message = phase37DefaultGuestReadinessBoundaryMessage(fileName, label+" via "+phase35FirecrackerHostExprName(typed.Fun))
			}
		case *ast.CompositeLit:
			if label := phase37GuestReadinessCompositeLabel(typed, firecrackerHost, firecrackerBackend); label != "" {
				message = phase37DefaultGuestReadinessBoundaryMessage(fileName, label+" in "+phase35FirecrackerHostExprName(typed.Type))
			}
			if label := phase37GuestReadinessCompositeFieldLabel(typed); label != "" {
				message = phase37DefaultGuestReadinessBoundaryMessage(fileName, label)
			}
		case *ast.SelectorExpr:
			if label := phase37GuestReadinessSelectorLabel(typed, firecrackerHost, firecrackerBackend); label != "" {
				message = phase37DefaultGuestReadinessBoundaryMessage(fileName, label+" reference "+phase35FirecrackerHostExprName(typed))
			}
		case *ast.Ident:
			if firecrackerHost.dot || firecrackerBackend.dot {
				if label := phase37GuestReadinessMemberLabel(typed.Name); label != "" {
					message = phase37DefaultGuestReadinessBoundaryMessage(fileName, label+" reference "+typed.Name)
				}
			}
		}
		return message == ""
	})
	return message
}

type phase37ImportBinding struct {
	aliases map[string]bool
	dot     bool
}

func phase37ImportBindings(file *ast.File, importPath string) phase37ImportBinding {
	binding := phase37ImportBinding{aliases: map[string]bool{}}
	for _, spec := range file.Imports {
		quoted, err := strconv.Unquote(spec.Path.Value)
		if err != nil || quoted != importPath {
			continue
		}
		name := filepath.Base(importPath)
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

func phase37GuestReadinessCallLabel(call *ast.CallExpr, host phase35FirecrackerHostImportBinding, backend phase37ImportBinding) string {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		if receiver, ok := selector.X.(*ast.Ident); ok {
			if host.aliases[receiver.Name] || backend.aliases[receiver.Name] {
				return phase37GuestReadinessMemberLabel(selector.Sel.Name)
			}
		}
	}
	if host.dot || backend.dot {
		if ident, ok := call.Fun.(*ast.Ident); ok {
			return phase37GuestReadinessMemberLabel(ident.Name)
		}
	}
	return ""
}

func phase37GuestReadinessCompositeLabel(lit *ast.CompositeLit, host phase35FirecrackerHostImportBinding, backend phase37ImportBinding) string {
	switch typed := lit.Type.(type) {
	case *ast.SelectorExpr:
		receiver, ok := typed.X.(*ast.Ident)
		if ok && (host.aliases[receiver.Name] || backend.aliases[receiver.Name]) {
			return phase37GuestReadinessMemberLabel(typed.Sel.Name)
		}
	case *ast.Ident:
		if host.dot || backend.dot {
			return phase37GuestReadinessMemberLabel(typed.Name)
		}
	}
	return ""
}

func phase37GuestReadinessCompositeFieldLabel(lit *ast.CompositeLit) string {
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
		case "GuestReadinessWaiter":
			return "Firecracker guest readiness backend option"
		case "GuestReadinessProbe":
			return "Firecracker guest readiness probe option"
		case "GuestTimeout", "GuestPollInterval":
			return "Firecracker guest readiness polling option"
		case "GuestReadiness":
			return "Firecracker guest readiness metadata construction"
		}
	}
	return ""
}

func phase37GuestReadinessSelectorLabel(selector *ast.SelectorExpr, host phase35FirecrackerHostImportBinding, backend phase37ImportBinding) string {
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || (!host.aliases[receiver.Name] && !backend.aliases[receiver.Name]) {
		return ""
	}
	return phase37GuestReadinessMemberLabel(selector.Sel.Name)
}

func phase37GuestReadinessMemberLabel(name string) string {
	switch name {
	case "GuestReadinessWaiter", "GuestReadinessRequest", "GuestReadinessResult":
		return "Firecracker guest readiness backend contract"
	case "NewGuestReadinessRequest":
		return "Firecracker guest readiness request construction"
	case "NewGuestReadinessResult":
		return "Firecracker guest readiness result construction"
	case "SanitizeGuestReadinessRequest", "SanitizeGuestReadinessResult":
		return "Firecracker guest readiness sanitization wiring"
	case "GuestReadinessProbe":
		return "Firecracker guest readiness probe option"
	case "WithGuestReadinessProbe":
		return "Firecracker guest readiness probe injection"
	case "WithGuestReadinessTimeout", "WithGuestReadinessPollInterval":
		return "Firecracker guest readiness polling option"
	case "WaitForGuestReadiness":
		return "Firecracker guest readiness wait"
	case "ProbeGuestReadiness":
		return "Firecracker guest readiness probe call"
	default:
		return ""
	}
}

func phase37DefaultGuestReadinessBoundaryMessage(fileName, detail string) string {
	return phase33DefaultGuardDisplayPathNoFatal(fileName) + " " + detail + "; Phase 37 default command, factory, sandboxexec, worker, scheduler, and sandboxd paths must not construct live Firecracker guest readiness wiring"
}
