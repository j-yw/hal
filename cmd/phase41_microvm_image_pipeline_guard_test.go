package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

func TestPhase41MicroVMAssetContractsAndResolverStayIsolatedFromRuntimeBoundaries(t *testing.T) {
	for _, path := range phase41AssetPipelineProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase41AssertAssetPipelineFileIsolated(t, path)
		})
	}
}

func TestPhase41DefaultHalPathsDoNotResolveAssetsOrLaunchFirecrackerImplicitly(t *testing.T) {
	for _, path := range phase41DefaultNoAssetPipelineProductionFiles(t) {
		t.Run(phase33DefaultGuardDisplayPath(t, path), func(t *testing.T) {
			phase41AssertDefaultPathAvoidsAssetResolverAndFirecrackerLaunch(t, path)
		})
	}
}

func TestPhase41DefaultFirecrackerAssetPipelineGuardCoversRequiredSurfaces(t *testing.T) {
	covered := map[string]bool{}
	for _, path := range phase41DefaultNoAssetPipelineProductionFiles(t) {
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
		"../internal/factory/store.go",
		"../internal/factory/types.go",
		"../internal/sandboxexec/executor.go",
		"../internal/sandboxworker/adapter.go",
		"../internal/sandboxworker/service.go",
		"../internal/sandboxworker/types.go",
		"../internal/sandboxtarget/scheduler_candidates.go",
		"../internal/sandboxtarget/scheduler_capacity.go",
		"../internal/sandboxtarget/scheduler_types.go",
		"../internal/sandboxtarget/select.go",
	} {
		clean := filepath.ToSlash(filepath.Clean(want))
		if !covered[clean] {
			t.Fatalf("Phase 41 Firecracker asset pipeline default guard does not cover %s", want)
		}
	}
}

func TestPhase41SandboxdFirecrackerAssetResolverStaysExplicitAndPreDriver(t *testing.T) {
	flags := defaultSandboxdFlags()
	if got := strings.Join(flags.drivers, ","); got != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("default sandboxd drivers = %q, want only %q", got, sandboxruntime.DriverRootlessPodman)
	}

	req := sandboxdRequest{
		Drivers: []string{sandboxruntime.DriverRootlessPodman},
	}
	if sandboxdRuntimeDriverDescriptors(req) != nil {
		t.Fatalf("rootless-only sandboxd runtime descriptors unexpectedly include microVM metadata")
	}

	cmdFiles := phase35ProductionFilesInDirs(t, ".")
	var resolverFiles []string
	for _, path := range cmdFiles {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if strings.Contains(string(source), "assets/localresolver") ||
			strings.Contains(string(source), "resolveSandboxdMicroVMLaunchAssets") ||
			strings.Contains(string(source), "localresolver.Resolve") {
			resolverFiles = append(resolverFiles, filepath.ToSlash(filepath.Clean(path)))
		}
	}
	sort.Strings(resolverFiles)
	if got, want := strings.Join(resolverFiles, ","), "sandboxd.go"; got != want {
		t.Fatalf("Phase 41 sandboxd resolver exception files = %q, want %q", got, want)
	}

	sourceBytes, err := os.ReadFile("sandboxd.go")
	if err != nil {
		t.Fatalf("ReadFile(sandboxd.go) error: %v", err)
	}
	source := string(sourceBytes)
	for _, want := range []string{
		`cmd.Flags().StringVar(&flags.microVM.kernelImagePath, "firecracker-kernel"`,
		`cmd.Flags().StringVar(&flags.microVM.rootfsImagePath, "firecracker-rootfs"`,
		`cmd.Flags().StringVar(&flags.microVM.initrdPath, "firecracker-initrd"`,
		"resolvedMicroVM, err := resolveSandboxdMicroVMLaunchAssets(req.MicroVM)",
		"req.MicroVM = resolvedMicroVM",
		"driver, err := deps.newMicroVMDriver(req.MicroVM)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("sandboxd.go missing explicit Phase 41 marker %q", want)
		}
	}
	resolveIndex := strings.Index(source, "resolvedMicroVM, err := resolveSandboxdMicroVMLaunchAssets(req.MicroVM)")
	assignIndex := strings.Index(source, "req.MicroVM = resolvedMicroVM")
	driverIndex := strings.Index(source, "driver, err := deps.newMicroVMDriver(req.MicroVM)")
	if resolveIndex < 0 || assignIndex < 0 || driverIndex < 0 || resolveIndex > assignIndex || assignIndex > driverIndex {
		t.Fatalf("sandboxd.go must resolve explicit Firecracker launch assets before microVM driver construction")
	}
}

func TestPhase41MicroVMImagePipelinePublicErrorsStayRedactionSafe(t *testing.T) {
	_, resolverErr := localresolver.Resolve(localresolver.ResolveRequest{
		ID:                 "phase41-redaction",
		LockedAtUnixMillis: 1783015200000,
		Assets: []localresolver.AssetRequest{
			{
				ID:   "kernel",
				Role: assets.AssetRoleKernel,
				Kind: assets.AssetKindKernelImage,
				Path: "https://assets.example.test:8443/vmlinux?token=ghp_secret",
			},
			{
				ID:   "rootfs",
				Role: assets.AssetRoleRootfs,
				Kind: assets.AssetKindRootfsImage,
				Path: "/Users/alice/private/rootfs.ext4",
			},
		},
	})
	if resolverErr == nil {
		t.Fatal("Resolve() error = nil, want unsafe path rejection")
	}
	var typedResolverErr *localresolver.Error
	if !errors.As(resolverErr, &typedResolverErr) {
		t.Fatalf("resolver error = %T, want *localresolver.Error", resolverErr)
	}
	if typedResolverErr.Code != localresolver.ErrorCodeUnsafePath || typedResolverErr.Role != assets.AssetRoleKernel {
		t.Fatalf("resolver error = %#v, want unsafe kernel path", typedResolverErr)
	}

	commandErr := sandboxdMicroVMLaunchAssetResolveError(resolverErr)
	validation := assets.ValidateAndNormalizeLaunchDescriptor(assets.LaunchDescriptor{
		ID:     "https://secret.example.test/descriptor?token=ghp_secret",
		Labels: []assets.SafeLabel{"firecracker", "password"},
		Assets: []assets.LaunchAsset{
			{
				ID:   "../kernel",
				Role: assets.AssetRoleKernel,
				Kind: assets.AssetKindKernelImage,
				Source: assets.AssetSource{
					Type: assets.SourceTypeLocalFile,
					HostPath: &assets.HostPathMetadata{
						Path: "/Users/alice/private/vmlinux",
						Role: assets.HostPathRoleResolvedLocalAsset,
					},
				},
				Lock: assets.LockMetadata{
					Digest: assets.DigestMetadata{
						Algorithm: assets.DigestAlgorithmSHA256,
						Value:     strings.Repeat("z", 64),
					},
				},
			},
		},
	})
	if validation.Valid {
		t.Fatal("ValidateAndNormalizeLaunchDescriptor() Valid = true, want invalid descriptor")
	}

	resolverJSON, err := json.Marshal(resolverErr)
	if err != nil {
		t.Fatalf("Marshal(resolverErr) error: %v", err)
	}
	validationJSON, err := json.Marshal(validation)
	if err != nil {
		t.Fatalf("Marshal(validation) error: %v", err)
	}
	publicText := strings.ToLower(resolverErr.Error() + " " + commandErr.Error() + " " + string(resolverJSON) + " " + string(validationJSON))
	for _, leaked := range []string{
		"https://",
		"assets.example.test",
		"secret.example.test",
		"8443",
		"token=ghp_secret",
		"ghp_secret",
		"/users/alice",
		"rootfs.ext4",
		"vmlinux",
		"../kernel",
		"password",
	} {
		if strings.Contains(publicText, strings.ToLower(leaked)) {
			t.Fatalf("Phase 41 public error or JSON leaked %q in %q", leaked, publicText)
		}
	}
	for _, want := range []string{"unsafe_path", "kernel", "--firecracker-kernel", "unsafe_id", "unsafe_label"} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("Phase 41 public error or JSON = %q, want safe marker %q", publicText, want)
		}
	}
}

func TestPhase41MicroVMImagePipelineGuardRejectsFixtures(t *testing.T) {
	importFixtures := []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra parsing"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory records"},
		{name: "worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker protocol"},
		{name: "Firecracker runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "runtime execution"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "runtime execution"},
	}
	for _, tt := range importFixtures {
		t.Run(tt.name, func(t *testing.T) {
			message := phase41AssetPipelineForbiddenImportMessage("fixture.go", tt.importPath)
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
		{name: "process launch", source: `package fixture; import "os/exec"; func f() { _ = exec.Command("firecracker") }`, want: "process launch"},
		{name: "network dial", source: `package fixture; import "net"; func f() { _, _ = net.Dial("tcp", "127.0.0.1:22") }`, want: "network dialer"},
		{name: "default local resolver", source: `package fixture; import localresolver "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"; func f(r localresolver.ResolveRequest) { _, _ = localresolver.Resolve(r) }`, want: "asset resolver"},
		{name: "launch descriptor", source: `package fixture; import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"; func f() { _ = assets.LaunchDescriptor{} }`, want: "launch descriptor construction"},
	}
	for _, tt := range sourceFixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := phase41DefaultPathForbiddenSourceMessage(tt.name+".go", tt.source, file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}
}

func phase41AssertAssetPipelineFileIsolated(t *testing.T, path string) {
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
		if message := phase41AssetPipelineForbiddenImportMessage(path, importPath); message != "" {
			t.Fatal(message)
		}
	}
	if message := phase41AssetPipelineForbiddenSourceMessage(path, file); message != "" {
		t.Fatal(message)
	}
}

func phase41AssertDefaultPathAvoidsAssetResolverAndFirecrackerLaunch(t *testing.T, path string) {
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
		if message := phase41DefaultPathForbiddenImportMessage(path, importPath); message != "" {
			t.Fatal(message)
		}
	}
	if message := phase41DefaultPathForbiddenSourceMessage(path, string(source), file); message != "" {
		t.Fatal(message)
	}
}

func phase41AssetPipelineProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := append([]string{},
		phase41ProductionFilesInDir(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets"))...,
	)
	paths = append(paths, phase41ProductionFilesInDir(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver"))...)
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("Phase 41 asset pipeline guard matched no production files")
	}
	return paths
}

func phase41DefaultNoAssetPipelineProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := append([]string{}, phase35DefaultCLIProductionFiles(t)...)
	paths = phase41WithoutSandboxdExplicitMicroVMFiles(paths)
	paths = append(paths, phase35FactoryProductionFiles(t)...)
	paths = append(paths, phase35ProductionFilesInDirs(t, filepath.Join("..", "internal", "sandboxexec"))...)
	paths = append(paths, phase35WorkerProductionFiles(t)...)
	paths = append(paths, phase36SchedulerDefaultProductionFiles(t)...)
	sort.Strings(paths)
	return paths
}

func phase41WithoutSandboxdExplicitMicroVMFiles(paths []string) []string {
	filtered := make([]string, 0, len(paths))
	for _, path := range paths {
		switch filepath.ToSlash(filepath.Clean(path)) {
		case "sandboxd.go", phase39ExplicitSandboxdFirecrackerLiveDriverPath:
			continue
		default:
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func phase41ProductionFilesInDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		paths = append(paths, filepath.Join(dir, name))
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("Phase 41 guard matched no production files in %s", dir)
	}
	return paths
}

func phase41AssetPipelineForbiddenImportMessage(fileName, importPath string) string {
	for _, forbidden := range phase41ForbiddenBoundaryImports() {
		if forbidden.match(importPath) {
			return phase41BoundaryMessage(fileName, "imports "+forbidden.label+" "+strconv.Quote(importPath))
		}
	}
	return ""
}

func phase41DefaultPathForbiddenImportMessage(fileName, importPath string) string {
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/") {
		return phase41DefaultBoundaryMessage(fileName, "imports microVM asset pipeline package "+strconv.Quote(importPath))
	}
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker/") ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/") {
		return phase41DefaultBoundaryMessage(fileName, "imports Firecracker execution package "+strconv.Quote(importPath))
	}
	if strings.HasPrefix(importPath, "github.com/firecracker-microvm") {
		return phase41DefaultBoundaryMessage(fileName, "imports Firecracker SDK package "+strconv.Quote(importPath))
	}
	return ""
}

func phase41AssetPipelineForbiddenSourceMessage(fileName string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := phase41CallSelectorName(call.Fun)
		switch selector {
		case "exec.Command", "exec.CommandContext", "os.StartProcess", "syscall.Exec":
			message = phase41BoundaryMessage(fileName, "calls "+selector+" (process launch)")
		case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
			message = phase41BoundaryMessage(fileName, "calls "+selector+" (network dialer or listener)")
		case "http.Get", "http.Post", "http.ListenAndServe", "http.ListenAndServeTLS":
			message = phase41BoundaryMessage(fileName, "calls "+selector+" (HTTP client or server)")
		case "grpc.Dial", "grpc.DialContext", "grpc.NewClient":
			message = phase41BoundaryMessage(fileName, "calls "+selector+" (gRPC client)")
		}
		return message == ""
	})
	return message
}

func phase41DefaultPathForbiddenSourceMessage(fileName, source string, file *ast.File) string {
	for _, marker := range []struct {
		token string
		label string
	}{
		{token: "localresolver.Resolve", label: "asset resolver call"},
		{token: "resolveSandboxdMicroVMLaunchAssets", label: "asset resolver helper"},
		{token: "assets.LaunchDescriptor", label: "launch descriptor construction"},
		{token: "LaunchDescriptor:", label: "launch descriptor field"},
		{token: "assets.AssetRoleKernel", label: "launch asset role construction"},
		{token: "assets.AssetRoleRootfs", label: "launch asset role construction"},
		{token: "firecracker.NewBackend", label: "Firecracker backend construction"},
		{token: "firecrackerhost.NewLiveDriver", label: "Firecracker live driver construction"},
		{token: "LiveStart: true", label: "Firecracker live-start option"},
		{token: "ProcessLaunchAdapter", label: "Firecracker process adapter construction"},
		{token: "net.Dial(", label: "network dialer"},
	} {
		if strings.Contains(source, marker.token) {
			return phase41DefaultBoundaryMessage(fileName, marker.label+" marker "+strconv.Quote(marker.token))
		}
	}
	if message := phase33DefaultFirecrackerSourceBoundaryMessage(fileName, source, file); message != "" {
		return phase41DefaultBoundaryMessage(fileName, phase34LegacyFirecrackerBoundaryDetail(fileName, message))
	}
	return ""
}

func phase41ForbiddenBoundaryImports() []phase41ForbiddenImport {
	return []phase41ForbiddenImport{
		{label: "Cobra parsing package", match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		}},
		{label: "command package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/cmd")},
		{label: "factory records package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
		{label: "worker protocol package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
		{label: "runtime execution package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
		{label: "runtime execution record package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
		{label: "runtime execution package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker")},
		{label: "runtime execution package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost")},
		{label: "runtime execution package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
		{label: "runtime execution package", match: phase41ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")},
		{label: "runtime execution process package", match: func(importPath string) bool { return importPath == "os/exec" }},
		{label: "network package", match: func(importPath string) bool {
			return importPath == "net" ||
				importPath == "net/http" ||
				importPath == "net/http/httptest" ||
				importPath == "net/http/httputil" ||
				importPath == "net/rpc" ||
				strings.HasPrefix(importPath, "net/http/") ||
				strings.HasPrefix(importPath, "google.golang.org/grpc")
		}},
		{label: "runtime execution Docker or Podman package", match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/containers/podman") ||
				strings.HasPrefix(importPath, "github.com/containers/image") ||
				strings.HasPrefix(importPath, "github.com/containers/storage") ||
				strings.HasPrefix(importPath, "github.com/containers/buildah")
		}},
		{label: "runtime execution Firecracker SDK package", match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.HasPrefix(importPath, "github.com/firecracker-microvm") ||
				strings.Contains(lower, "cloud-hypervisor") ||
				strings.Contains(lower, "cloudhypervisor") ||
				strings.Contains(lower, "libvirt") ||
				strings.Contains(lower, "qemu") ||
				strings.Contains(lower, "kvm")
		}},
		{label: "cloud SDK package", match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/digitalocean/godo") ||
				strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go") ||
				strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2") ||
				strings.HasPrefix(importPath, "github.com/Azure/azure-sdk-for-go") ||
				strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go") ||
				strings.HasPrefix(importPath, "cloud.google.com/go") ||
				strings.HasPrefix(importPath, "google.golang.org/api")
		}},
	}
}

func phase41CallSelectorName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.SelectorExpr:
		parent := phase41CallSelectorName(typed.X)
		if parent == "" {
			return typed.Sel.Name
		}
		return parent + "." + typed.Sel.Name
	case *ast.Ident:
		return typed.Name
	default:
		return ""
	}
}

func phase41ModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func phase41BoundaryMessage(fileName, detail string) string {
	return fmt.Sprintf("%s %s; Phase 41 asset contracts and resolver must stay isolated from runtime execution, worker protocol, Cobra parsing, and factory records", phase33DefaultGuardDisplayPathNoFatal(fileName), detail)
}

func phase41DefaultBoundaryMessage(fileName, detail string) string {
	return fmt.Sprintf("%s %s; Phase 41 default command, factory, scheduler, and worker paths must not resolve Firecracker launch assets or launch Firecracker implicitly", phase33DefaultGuardDisplayPathNoFatal(fileName), detail)
}

type phase41ForbiddenImport struct {
	label string
	match func(string) bool
}
