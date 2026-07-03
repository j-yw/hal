package cmd

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxtarget"
)

func TestPhase38DefaultCommandPathsDoNotWireFirecrackerLiveGuestTransport(t *testing.T) {
	for _, path := range phase35DefaultCLIProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase38AssertNoFirecrackerLiveGuestTransportWiring(t, path)
		})
	}
}

func TestPhase38FactoryDefaultsDoNotWireFirecrackerLiveGuestTransport(t *testing.T) {
	for _, path := range phase35FactoryProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase38AssertNoFirecrackerLiveGuestTransportWiring(t, path)
		})
	}
}

func TestPhase38SandboxexecDefaultsDoNotWireFirecrackerLiveGuestTransport(t *testing.T) {
	for _, path := range phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec")) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase38AssertNoFirecrackerLiveGuestTransportWiring(t, path)
		})
	}
}

func TestPhase38WorkerDefaultsDoNotWireFirecrackerLiveGuestTransport(t *testing.T) {
	for _, path := range phase35WorkerProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase38AssertNoFirecrackerLiveGuestTransportWiring(t, path)
		})
	}
}

func TestPhase38SchedulerDefaultsDoNotWireFirecrackerLiveGuestTransport(t *testing.T) {
	for _, path := range phase36SchedulerDefaultProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase38AssertNoFirecrackerLiveGuestTransportWiring(t, path)
		})
	}
}

func TestPhase38SandboxdDefaultsDoNotWireFirecrackerLiveGuestTransport(t *testing.T) {
	for _, path := range phase36SandboxdDefaultProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase38AssertNoFirecrackerLiveGuestTransportWiring(t, path)
		})
	}
}

func TestPhase38FirecrackerLiveGuestTransportGuardCoversRequiredDefaultSurfaces(t *testing.T) {
	covered := make(map[string]bool)
	for _, path := range phase38DefaultFirecrackerGuestTransportProductionFiles(t) {
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
		"../internal/factory/store.go",
		"../internal/factory/types.go",
		"../internal/sandboxexec/executor.go",
		"../internal/sandboxworker/adapter.go",
		"../internal/sandboxworker/registry.go",
		"../internal/sandboxworker/service.go",
		"../internal/sandboxworker/types.go",
		"../internal/sandboxtarget/scheduler_candidates.go",
		"../internal/sandboxtarget/scheduler_capacity.go",
		"../internal/sandboxtarget/scheduler_types.go",
		"../internal/sandboxtarget/select.go",
	} {
		clean := filepath.ToSlash(filepath.Clean(want))
		if !covered[clean] {
			t.Fatalf("Phase 38 live guest transport default guard does not cover %s", want)
		}
	}
}

func TestPhase38RunAutoFactoryDefaultsDoNotSelectFirecrackerRuntimeOrGuestTransport(t *testing.T) {
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

	factoryReq, err := parseFactoryRunRequestWithTarget([]string{".hal/prd-feature.md"}, "", "main", false, true, sandboxTargetFlagValues{})
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
				t.Fatal("default resolver constructed microVM; Firecracker live guest transport must stay explicit")
				return nil
			},
		}
	}

	targets := []struct {
		name   string
		target sandboxruntime.Target
	}{
		{
			name: "missing runtime metadata",
			target: sandboxruntime.Target{
				Provider: "test-provider",
			},
		},
		{
			name: "blank runtime driver",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime:  sandboxruntime.RuntimeState{Driver: " \t\n "},
			},
		},
		{
			name: "firecracker-looking metadata without explicit driver",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime: sandboxruntime.RuntimeState{
					RuntimeID: "fc-cached-runtime",
					Metadata: &sandboxruntime.RuntimeMetadata{
						Backend:          "firecracker",
						CapabilityLabels: []string{"guest_transport"},
					},
				},
			},
		},
	}

	for _, resolver := range phase38DefaultRuntimeResolvers() {
		for _, tt := range targets {
			t.Run(resolver.name+"/"+tt.name, func(t *testing.T) {
				providerCalls := 0
				resolveProvider := func(providerName string) (sandbox.Provider, error) {
					providerCalls++
					if providerName != "test-provider" {
						t.Fatalf("providerName = %q, want test-provider", providerName)
					}
					return fakeFactorySandboxProvider{}, nil
				}

				driver, err := resolver.build(resolveProvider)(tt.target)
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
}

func TestPhase38SchedulerDefaultRequestDoesNotInferFirecrackerRuntime(t *testing.T) {
	now := time.Date(2026, 7, 3, 6, 30, 0, 0, time.UTC)
	result := sandboxtarget.Schedule(sandboxtarget.SchedulerRequest{
		Purpose: sandboxtarget.PurposeRun,
	}, sandboxtarget.CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "host-firecracker-capable",
					Name:              "a-firecracker-capable-worker",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandboxruntime.DriverMicroVM},
					Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
				},
				{
					ID:                "host-rootless",
					Name:              "b-rootless-worker",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
					Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
				},
			}, nil
		},
		ListLeases: func() ([]*sandbox.SandboxLease, error) { return nil, nil },
		Now:        func() time.Time { return now },
	})
	if !result.Selected() {
		t.Fatalf("Schedule() selected = false, rejection = %#v", result.Rejection)
	}
	if result.Selection.Runtime != nil {
		t.Fatalf("default scheduler selection Runtime = %#v, want nil until runtime or isolation is explicit", result.Selection.Runtime)
	}
	if result.Selection.Identity.RuntimeDriver != "" || result.Selection.Identity.RuntimeID != "" || result.Selection.Identity.IsolationLevel != "" {
		t.Fatalf("default scheduler identity inferred runtime metadata: %#v", result.Selection.Identity)
	}
}

func TestPhase38DefaultMicroVMAndSandboxdMetadataDoNotClaimLiveGuestTransport(t *testing.T) {
	driver := microvm.New()
	if driver == nil {
		t.Fatal("microvm.New() = nil, want backend-neutral default driver")
	}
	metadata := driver.Metadata()
	if metadata.BackendConfigured {
		t.Fatal("default microVM BackendConfigured = true, want false")
	}
	if metadata.UsesHostDockerSocket {
		t.Fatal("default microVM UsesHostDockerSocket = true, want false")
	}
	phase38AssertJSONOmitsGuestTransportClaims(t, "default microVM metadata", metadata)

	flags := defaultSandboxdFlags()
	if strings.Join(flags.drivers, ",") != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("default sandboxd drivers = %#v, want only rootless_podman", flags.drivers)
	}
	deps := defaultSandboxdDeps()
	if deps.newMicroVMDriver != nil {
		t.Fatal("default sandboxd newMicroVMDriver is configured; Firecracker live guest transport must remain opt-in")
	}
	if sandboxdDriverSupportedByDeps(sandboxruntime.DriverMicroVM, deps) {
		t.Fatal("default sandboxd reports microVM supported without an injected backend factory")
	}
}

func TestPhase38FirecrackerLiveGuestTransportGuardRejectsFixtures(t *testing.T) {
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
			name:       "Firecracker host package",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost",
			want:       "Firecracker guest readiness host package",
		},
		{
			name:       "Firecracker SDK package",
			importPath: "github.com/firecracker-microvm/firecracker-go-sdk",
			want:       "Firecracker SDK package",
		},
	}
	for _, tt := range importFixtures {
		t.Run(tt.name, func(t *testing.T) {
			message := phase38FirecrackerLiveGuestTransportImportBoundaryMessage("fixture.go", tt.importPath)
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
			name:   "backend guest transport option",
			source: `package cmd; func defaultPath(transport any) { _ = BackendOptions{GuestTransport: transport} }`,
			want:   "Firecracker live guest transport backend option",
		},
		{
			name:   "live driver guest transport option",
			source: `package cmd; import firecrackerhost "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath(transport any) { _ = firecrackerhost.LiveDriverOptions{GuestTransport: transport} }`,
			want:   "Firecracker live guest transport backend option",
		},
		{
			name:   "guest transport contract reference",
			source: `package cmd; import fc "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"; func defaultPath(transport fc.GuestTransport) { _ = transport }`,
			want:   "Firecracker live guest transport contract",
		},
		{
			name:   "guest exec request construction",
			source: `package cmd; import firecracker "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"; func defaultPath() { _ = firecracker.GuestExecRequest{} }`,
			want:   "Firecracker guest exec request construction",
		},
		{
			name:   "guest copy request construction",
			source: `package cmd; import . "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"; func defaultPath() { _ = GuestCopyRequest{} }`,
			want:   "Firecracker guest copy request construction",
		},
		{
			name:   "future guest transport injection helper",
			source: `package cmd; func defaultPath(transport any) { _ = WithGuestTransport(transport) }`,
			want:   "Firecracker live guest transport injection",
		},
		{
			name:   "older guest readiness still rejected",
			source: `package cmd; import fc "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"; func defaultPath(probe fc.GuestReadinessProbe) { _ = fc.WithGuestReadinessProbe(probe) }`,
			want:   "Firecracker guest readiness probe injection",
		},
	}
	for _, tt := range sourceFixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := phase38FirecrackerLiveGuestTransportSourceBoundaryMessage(tt.name+".go", tt.source, file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}

	allowedSource := `package cmd; type runtimeDriver interface { Exec(); CopyIn(); CopyOut() }; func defaultPath(driver runtimeDriver) { _ = driver }`
	file, err := parser.ParseFile(token.NewFileSet(), "allowed.go", allowedSource, 0)
	if err != nil {
		t.Fatalf("ParseFile allowed fixture error: %v", err)
	}
	if message := phase38FirecrackerLiveGuestTransportSourceBoundaryMessage("allowed.go", allowedSource, file); message != "" {
		t.Fatalf("allowed generic runtime transport fixture failed guard: %s", message)
	}
}

func phase38AssertNoFirecrackerLiveGuestTransportWiring(t *testing.T, path string) {
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
		if message := phase38FirecrackerLiveGuestTransportImportBoundaryMessage(path, importPath); message != "" {
			t.Fatal(message)
		}
	}
	if message := phase38FirecrackerLiveGuestTransportSourceBoundaryMessage(path, string(source), file); message != "" {
		t.Fatal(message)
	}
}

func phase38DefaultFirecrackerGuestTransportProductionFiles(t *testing.T) []string {
	t.Helper()

	all := append([]string{}, phase35DefaultCLIProductionFiles(t)...)
	all = append(all, phase35FactoryProductionFiles(t)...)
	all = append(all, phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec"))...)
	all = append(all, phase35WorkerProductionFiles(t)...)
	all = append(all, phase36SchedulerDefaultProductionFiles(t)...)
	all = append(all, phase36SandboxdDefaultProductionFiles(t)...)
	sort.Strings(all)
	return all
}

func phase38DefaultRuntimeResolvers() []struct {
	name  string
	build func(func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error)
} {
	return []struct {
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
}

func phase38FirecrackerLiveGuestTransportImportBoundaryMessage(fileName, importPath string) string {
	if message := phase37FirecrackerGuestReadinessImportBoundaryMessage(fileName, importPath); message != "" {
		return phase38DefaultGuestTransportBoundaryMessage(fileName, phase34LegacyFirecrackerBoundaryDetail(fileName, message))
	}
	return ""
}

func phase38FirecrackerLiveGuestTransportSourceBoundaryMessage(fileName, source string, file *ast.File) string {
	for _, marker := range []struct {
		token string
		label string
	}{
		{token: "WithGuestTransport(", label: "Firecracker live guest transport injection"},
		{token: "NewGuestTransport(", label: "Firecracker live guest transport construction"},
		{token: "GuestTransport:", label: "Firecracker live guest transport backend option"},
		{token: "GuestExecRequest", label: "Firecracker guest exec request construction"},
		{token: "GuestCopyRequest", label: "Firecracker guest copy request construction"},
		{token: "GuestTransport", label: "Firecracker live guest transport contract"},
	} {
		if strings.Contains(source, marker.token) {
			return phase38DefaultGuestTransportBoundaryMessage(fileName, marker.label+" marker "+strconv.Quote(marker.token))
		}
	}

	firecrackerBackend := phase37ImportBindings(file, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker")
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		switch typed := node.(type) {
		case *ast.CallExpr:
			if label := phase38GuestTransportCallLabel(typed, firecrackerBackend); label != "" {
				message = phase38DefaultGuestTransportBoundaryMessage(fileName, label+" via "+phase35FirecrackerHostExprName(typed.Fun))
			}
		case *ast.CompositeLit:
			if label := phase38GuestTransportCompositeLabel(typed, firecrackerBackend); label != "" {
				message = phase38DefaultGuestTransportBoundaryMessage(fileName, label+" in "+phase35FirecrackerHostExprName(typed.Type))
			}
			if label := phase38GuestTransportCompositeFieldLabel(typed); label != "" {
				message = phase38DefaultGuestTransportBoundaryMessage(fileName, label)
			}
		case *ast.SelectorExpr:
			if label := phase38GuestTransportSelectorLabel(typed, firecrackerBackend); label != "" {
				message = phase38DefaultGuestTransportBoundaryMessage(fileName, label+" reference "+phase35FirecrackerHostExprName(typed))
			}
		case *ast.Ident:
			if firecrackerBackend.dot {
				if label := phase38GuestTransportMemberLabel(typed.Name); label != "" {
					message = phase38DefaultGuestTransportBoundaryMessage(fileName, label+" reference "+typed.Name)
				}
			}
		}
		return message == ""
	})
	if message != "" {
		return message
	}
	if message := phase37FirecrackerGuestReadinessSourceBoundaryMessage(fileName, source, file); message != "" {
		return phase38DefaultGuestTransportBoundaryMessage(fileName, phase34LegacyFirecrackerBoundaryDetail(fileName, message))
	}
	return ""
}

func phase38GuestTransportCallLabel(call *ast.CallExpr, backend phase37ImportBinding) string {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		if receiver, ok := selector.X.(*ast.Ident); ok && backend.aliases[receiver.Name] {
			return phase38GuestTransportMemberLabel(selector.Sel.Name)
		}
	}
	if backend.dot {
		if ident, ok := call.Fun.(*ast.Ident); ok {
			return phase38GuestTransportMemberLabel(ident.Name)
		}
	}
	return ""
}

func phase38GuestTransportCompositeLabel(lit *ast.CompositeLit, backend phase37ImportBinding) string {
	switch typed := lit.Type.(type) {
	case *ast.SelectorExpr:
		receiver, ok := typed.X.(*ast.Ident)
		if ok && backend.aliases[receiver.Name] {
			return phase38GuestTransportMemberLabel(typed.Sel.Name)
		}
	case *ast.Ident:
		if backend.dot {
			return phase38GuestTransportMemberLabel(typed.Name)
		}
	}
	return ""
}

func phase38GuestTransportCompositeFieldLabel(lit *ast.CompositeLit) string {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if key.Name == "GuestTransport" {
			return "Firecracker live guest transport backend option"
		}
	}
	return ""
}

func phase38GuestTransportSelectorLabel(selector *ast.SelectorExpr, backend phase37ImportBinding) string {
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !backend.aliases[receiver.Name] {
		return ""
	}
	return phase38GuestTransportMemberLabel(selector.Sel.Name)
}

func phase38GuestTransportMemberLabel(name string) string {
	switch name {
	case "GuestTransport":
		return "Firecracker live guest transport contract"
	case "GuestExecRequest":
		return "Firecracker guest exec request construction"
	case "GuestCopyRequest":
		return "Firecracker guest copy request construction"
	case "WithGuestTransport":
		return "Firecracker live guest transport injection"
	case "NewGuestTransport":
		return "Firecracker live guest transport construction"
	default:
		return ""
	}
}

func phase38AssertJSONOmitsGuestTransportClaims(t *testing.T, label string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, marker := range []string{
		"guesttransport",
		"guest_transport",
		"guest transport",
		"liveguesttransport",
		"live_guest_transport",
		"guestexec",
		"guest_exec",
		"guestcopy",
		"guest_copy",
		"firecrackerhost",
		"credentialbroker",
		"credential_broker",
		"networkproxy",
		"network_proxy",
		"production_secure",
		"secure_by_default",
	} {
		if strings.Contains(publicText, marker) {
			t.Fatalf("%s claims unsupported Firecracker live guest transport marker %q in %s", label, marker, publicText)
		}
	}
}

func phase38DefaultGuestTransportBoundaryMessage(fileName, detail string) string {
	return phase33DefaultGuardDisplayPathNoFatal(fileName) + " " + detail + "; Phase 38 default command, factory, sandboxexec, worker, scheduler, and sandboxd paths must not construct or wire live Firecracker guest transport"
}
