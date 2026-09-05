package firecrackerhost

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

func TestOSExecImportIsConfinedToRealProcessRunner(t *testing.T) {
	paths := firecrackerHostProductionFiles(t)
	allowed := map[string]bool{
		"real_process_runner.go":               false,
		"jailer_namespace_runner_linux.go":     false,
		"jailer_namespace_runner_other.go":     false,
		"l8_runtime_owner_executable_linux.go": false,
	}

	for _, path := range paths {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s imports) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if importPath != "os/exec" {
				continue
			}
			if _, ok := allowed[path]; !ok {
				t.Fatalf("%s imports os/exec; Firecracker process launch must stay in an exact reviewed owner", path)
			}
			allowed[path] = true
		}
	}

	for path, found := range allowed {
		if !found {
			t.Fatalf("%s does not import os/exec; an exact Firecracker launch owner disappeared", path)
		}
	}
}

func TestFirecrackerOSExecLaunchIsConfinedToHostAdapterPackage(t *testing.T) {
	repoRoot := firecrackerHostRepoRoot(t)
	hostRel := filepath.ToSlash(filepath.Join("internal", "sandboxruntime", "microvm", "firecrackerhost"))

	var checked []string
	err := filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".hal", "vendor", "node_modules":
				return filepath.SkipDir
			}
			if strings.HasPrefix(entry.Name(), ".") && path != repoRoot {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "" || strings.HasPrefix(rel, hostRel+"/") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("ParseFile(%s) error: %w", rel, err)
		}
		checked = append(checked, rel)
		if message := firecrackerHostForbiddenLaunchMessage(rel, file); message != "" {
			return fmt.Errorf("%s", message)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked) == 0 {
		t.Fatal("Firecracker launch boundary checked no production files outside firecrackerhost")
	}
}

func TestFirecrackerOSExecLaunchBoundaryRejectsFixtures(t *testing.T) {
	fixtures := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "exec command",
			source: `package fixture; import "os/exec"; func run() { _ = exec.Command("firecracker", "--api-sock", "sock") }`,
			want:   "exec.Command",
		},
		{
			name:   "aliased exec command context",
			source: `package fixture; import runner "os/exec"; func run(ctx context.Context) { _ = runner.CommandContext(ctx, "/usr/bin/firecracker") }`,
			want:   "runner.CommandContext",
		},
		{
			name:   "shell launch",
			source: `package fixture; import "os/exec"; func run(ctx context.Context) { _ = exec.CommandContext(ctx, "sh", "-c", "firecracker --api-sock sock") }`,
			want:   "exec.CommandContext",
		},
		{
			name:   "os start process",
			source: `package fixture; import "os"; func run() { _, _ = os.StartProcess("firecracker", []string{"firecracker"}, nil) }`,
			want:   "os.StartProcess",
		},
	}

	for _, tt := range fixtures {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile(fixture) error: %v", err)
			}
			message := firecrackerHostForbiddenLaunchMessage(tt.name+".go", file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want forbidden selector %q", message, tt.want)
			}
		})
	}

	allowed := `package fixture; import "os/exec"; func run(ctx context.Context) { _ = exec.CommandContext(ctx, "git", "status") }`
	file, err := parser.ParseFile(token.NewFileSet(), "allowed.go", allowed, 0)
	if err != nil {
		t.Fatalf("ParseFile(allowed) error: %v", err)
	}
	if message := firecrackerHostForbiddenLaunchMessage("allowed.go", file); message != "" {
		t.Fatalf("allowed non-Firecracker exec fixture failed boundary: %s", message)
	}
}

func TestFirecrackerHostLiveTestStaysOptIn(t *testing.T) {
	source, err := os.ReadFile("real_process_runner_live_test.go")
	if err != nil {
		t.Fatalf("ReadFile(real_process_runner_live_test.go) error: %v", err)
	}
	text := string(source)
	for _, want := range []string{
		"//go:build firecracker_live",
		"HAL_FIRECRACKER_LIVE",
		"HAL_FIRECRACKER_LIVE_FIRECRACKER",
		"t.Skip",
		"NewOSExecProcessRunner",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("real_process_runner_live_test.go missing %q", want)
		}
	}
}

func firecrackerHostProductionFiles(t *testing.T) []string {
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
		t.Fatal("no firecrackerhost production files matched")
	}
	return out
}

func firecrackerHostRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	root, err := filepath.Abs(filepath.Join(wd, "../../../.."))
	if err != nil {
		t.Fatalf("Abs(repo root) error: %v", err)
	}
	return root
}

func firecrackerHostForbiddenLaunchMessage(fileName string, file *ast.File) string {
	bindings := firecrackerHostImportBindings(file)
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || !firecrackerHostCallHasFirecrackerLiteralArg(call) {
			return true
		}
		if selector := firecrackerHostForbiddenLaunchSelector(call, bindings); selector != "" {
			message = fmt.Sprintf("%s calls %s with a Firecracker executable literal; real Firecracker os/exec launch belongs only in internal/sandboxruntime/microvm/firecrackerhost", fileName, selector)
			return false
		}
		return true
	})
	return message
}

type firecrackerHostImportBinding struct {
	aliases map[string]bool
	dot     bool
}

func firecrackerHostImportBindings(file *ast.File) map[string]firecrackerHostImportBinding {
	bindings := map[string]firecrackerHostImportBinding{
		"os/exec": {aliases: map[string]bool{}},
		"os":      {aliases: map[string]bool{}},
		"syscall": {aliases: map[string]bool{}},
	}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		binding, ok := bindings[importPath]
		if !ok {
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
		bindings[importPath] = binding
	}
	return bindings
}

func firecrackerHostForbiddenLaunchSelector(call *ast.CallExpr, bindings map[string]firecrackerHostImportBinding) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		ident, ok := fun.X.(*ast.Ident)
		if !ok {
			return ""
		}
		name := ident.Name
		switch {
		case bindings["os/exec"].aliases[name] && (fun.Sel.Name == "Command" || fun.Sel.Name == "CommandContext"):
			return name + "." + fun.Sel.Name
		case bindings["os"].aliases[name] && fun.Sel.Name == "StartProcess":
			return name + "." + fun.Sel.Name
		case bindings["syscall"].aliases[name] && fun.Sel.Name == "Exec":
			return name + "." + fun.Sel.Name
		default:
			return ""
		}
	case *ast.Ident:
		switch {
		case bindings["os/exec"].dot && (fun.Name == "Command" || fun.Name == "CommandContext"):
			return fun.Name
		case bindings["os"].dot && fun.Name == "StartProcess":
			return fun.Name
		case bindings["syscall"].dot && fun.Name == "Exec":
			return fun.Name
		default:
			return ""
		}
	default:
		return ""
	}
}

func firecrackerHostCallHasFirecrackerLiteralArg(call *ast.CallExpr) bool {
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
