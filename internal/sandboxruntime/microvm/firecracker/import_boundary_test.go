package firecracker

import (
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
)

const firecrackerPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"

var forbiddenFirecrackerProductionImports = []firecrackerForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory record package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "PRD package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "command-specific compound package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "command-specific loop package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{
		name: "Docker or Podman package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/containers/podman") ||
				strings.HasPrefix(importPath, "github.com/containers/image") ||
				strings.HasPrefix(importPath, "github.com/containers/storage") ||
				strings.HasPrefix(importPath, "github.com/containers/buildah")
		},
	},
	{
		name: "cloud SDK package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/digitalocean/godo") ||
				strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go") ||
				strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2") ||
				strings.HasPrefix(importPath, "github.com/Azure/azure-sdk-for-go") ||
				strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go") ||
				strings.HasPrefix(importPath, "github.com/linode/linodego") ||
				strings.HasPrefix(importPath, "github.com/vultr/govultr") ||
				strings.HasPrefix(importPath, "cloud.google.com/go") ||
				strings.HasPrefix(importPath, "google.golang.org/api")
		},
	},
	{
		name: "Firecracker SDK package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/firecracker-microvm")
		},
	},
	{
		name: "KVM access package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return importPath == "syscall" ||
				strings.HasPrefix(importPath, "golang.org/x/sys") ||
				strings.Contains(lower, "/kvm") ||
				strings.Contains(lower, "kvm")
		},
	},
	{
		name: "network listener package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/http/httputil", "net/rpc":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc")
			}
		},
	},
	{
		name: "process-starting package",
		match: func(importPath string) bool {
			return importPath == "os/exec" ||
				strings.HasPrefix(importPath, "github.com/creack/pty")
		},
	},
}

func TestFirecrackerPackageDeclaresExpectedFoundationExports(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	allowedExportedNames := map[string]bool{
		"BackendConfig":                  true,
		"BackendConfigFromMicroVMConfig": true,
		"BackendID":                      true,
		"BootSourcePayload":              true,
		"DefaultConfigPath":              true,
		"ConfigOperation":                true,
		"DefaultAPISocketPath":           true,
		"DefaultLogPath":                 true,
		"DefaultMetricsPath":             true,
		"DefaultRuntimeID":               true,
		"DefaultStateDir":                true,
		"GuestWorkDirMetadata":           true,
		"MachineConfigPayload":           true,
		"PathPlan":                       true,
		"PathPlanRequest":                true,
		"PathPlanningOperation":          true,
		"PayloadRenderingOperation":      true,
		"PlanPaths":                      true,
		"RenderBootSourcePayload":        true,
		"RenderMachineConfigPayload":     true,
		"RenderRootDrivePayload":         true,
		"RootDrivePayload":               true,
	}
	seenExportedNames := map[string]bool{}

	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if file.Name.Name != "firecracker" {
			t.Fatalf("%s package name = %q, want firecracker", path, file.Name.Name)
		}
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				if typed.Recv == nil && ast.IsExported(typed.Name.Name) {
					seenExportedNames[typed.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(spec.Name.Name) {
							seenExportedNames[spec.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if ast.IsExported(name.Name) {
								seenExportedNames[name.Name] = true
							}
						}
					}
				}
			}
		}
	}

	for name := range seenExportedNames {
		if !allowedExportedNames[name] {
			t.Fatalf("unexpected exported Firecracker namespace %q; Phase 32 foundation should expose only namespace, US-002 config contracts, US-003 path planning contracts, and US-004 payload contracts", name)
		}
	}
	for name := range allowedExportedNames {
		if !seenExportedNames[name] {
			t.Fatalf("missing exported Firecracker namespace %q", name)
		}
	}
}

func TestFirecrackerPackageCommentDocumentsFutureBoundary(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	var docs []string
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if file.Doc != nil {
			docs = append(docs, file.Doc.Text())
		}
	}
	text := strings.Join(docs, "\n")
	for _, want := range []string{
		"Package firecracker",
		"config mapping",
		"payload rendering",
		"command planning",
		"backend behavior",
		"backend-neutral microvm code",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Firecracker package comments missing %q in %q", want, text)
		}
	}
}

func TestFirecrackerProductionImportBoundaries(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := firecrackerProductionImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestFirecrackerForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "cmd package", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory records", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory record package"},
		{name: "PRD logic", importPath: "github.com/jywlabs/hal/internal/prd", want: "PRD package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman package"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "Firecracker SDK package"},
		{name: "KVM access", importPath: "golang.org/x/sys/unix", want: "KVM access package"},
		{name: "network listener", importPath: "net", want: "network listener package"},
		{name: "HTTP listener", importPath: "net/http", want: "network listener package"},
		{name: "process starting", importPath: "os/exec", want: "process-starting package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := firecrackerProductionImportBoundaryMessage("doc.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestFirecrackerProductionSourceOmitsLiveBackendOperations(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := firecrackerProductionCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if strings.Contains(string(source), "/dev/kvm") {
			t.Fatalf("%s references /dev/kvm; KVM access belongs behind a later explicit Firecracker adapter boundary", path)
		}
	}
}

func firecrackerProductionBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(*.go) error: %v", err)
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no Firecracker production files matched import-boundary guard")
	}
	return out
}

func firecrackerProductionImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := firecrackerForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", firecrackerPackagePath, fileName, forbidden.name, importPath)
	}
	if firecrackerAllowedProductionImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; Firecracker backend code may only depend on standard library and approved microVM contracts until an explicit adapter boundary is added", firecrackerPackagePath, fileName, importPath)
}

func firecrackerForbiddenImportFor(importPath string) *firecrackerForbiddenImport {
	for i := range forbiddenFirecrackerProductionImports {
		if forbiddenFirecrackerProductionImports[i].match(importPath) {
			return &forbiddenFirecrackerProductionImports[i]
		}
	}
	return nil
}

func firecrackerAllowedProductionImport(importPath string) bool {
	return firecrackerIsStandardLibraryImport(importPath) ||
		importPath == "github.com/jywlabs/hal/internal/sandbox" ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime" ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm"
}

func firecrackerIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func firecrackerModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func firecrackerProductionCallBoundaryMessage(fileName string, file *ast.File) string {
	return firecrackerFirstForbiddenCall(file, func(selector string) string {
		switch selector {
		case "exec.Command", "exec.CommandContext":
			return "process launch"
		case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
			return "network socket"
		case "http.Get", "http.Head", "http.Post", "http.PostForm", "http.ListenAndServe", "http.ListenAndServeTLS":
			return "HTTP client or server"
		case "grpc.Dial", "grpc.DialContext", "grpc.NewClient":
			return "gRPC client"
		case "firecracker.NewMachine":
			return "Firecracker SDK"
		default:
			return ""
		}
	}, func(selector, reason string) string {
		return fmt.Sprintf("%s calls %s (%s); live Firecracker behavior belongs behind a later explicit adapter boundary", fileName, selector, reason)
	})
}

func firecrackerFirstForbiddenCall(file *ast.File, classify func(string) string, format func(string, string) string) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := firecrackerCallSelectorName(call.Fun)
		if selector == "" {
			return true
		}
		if reason := classify(selector); reason != "" {
			message = format(selector, reason)
			return false
		}
		return true
	})
	return message
}

func firecrackerCallSelectorName(expr ast.Expr) string {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	receiver := firecrackerExprName(selector.X)
	if receiver == "" {
		return selector.Sel.Name
	}
	return receiver + "." + selector.Sel.Name
}

func firecrackerExprName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		parent := firecrackerExprName(typed.X)
		if parent == "" {
			return typed.Sel.Name
		}
		return parent + "." + typed.Sel.Name
	default:
		return ""
	}
}

type firecrackerForbiddenImport struct {
	name  string
	match func(string) bool
}
