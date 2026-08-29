package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const l8D7GuestProcessEntrypointsDoc = "sandbox-runtime-v2-l8-d7-guest-process-entrypoints.md"

func TestL8D7GuestProcessEntrypointsVerificationContract(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7GuestProcessEntrypointsDoc))
	for _, required := range []string{
		"default-off",
		"no independently testable policy",
		"missing/extra/typed-nil",
		"never install a default SSH extension",
		"`l8composition.NewHelper` is called only inside",
		"`cmd/hal-guest-credential-helper`",
		"`cmd/hal-guest-mount-monitor`",
		"`cmd/hal-guest-workload-shim`",
		"per-job mount owner",
		"one-shot workload transition",
		"rolebootstrap",
		"fail closed without",
		"live sockets",
		"bind",
		"listen",
		"dial",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"D7 prepared-Linux acceptance remains unaccepted",
		"D7 live stub fatals",
		"HL8E remain unissued",
		"no sandboxd, `hal run`,",
		"`hal auto`, or factory command-path wiring",
		"go test ./cmd/hal-guest-credential-helper ./cmd/hal-guest-mount-monitor ./cmd/hal-guest-workload-shim -count=1",
		"go test ./cmd -run '^TestL8D7GuestProcessEntrypoints' -count=1",
		"go vet ./cmd/hal-guest-credential-helper ./cmd/hal-guest-mount-monitor ./cmd/hal-guest-workload-shim ./cmd",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
		"does not synthesize success",
		"exit 127",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("D7 guest process entrypoints document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"D7 prepared-Linux acceptance is complete",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("D7 guest process entrypoints document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D7GuestProcessEntrypointsNewHelperOwnership(t *testing.T) {
	root := filepath.Clean("..")
	set := token.NewFileSet()
	callers := []string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		normalized := filepath.ToSlash(rel)
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "NewHelper" {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || ident.Name != "l8composition" {
				return true
			}
			callers = append(callers, normalized)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(callers) != 1 || callers[0] != "cmd/hal-guest-credential-helper/run.go" {
		t.Fatalf("l8composition.NewHelper callers = %v, want [cmd/hal-guest-credential-helper/run.go]", callers)
	}
}

func TestL8D7GuestProcessEntrypointsNewHelperOwnershipRejectsAliasedReferences(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{
			name:   "direct call",
			source: `package fixture; import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"; func run(options l8composition.HelperOptions) { _, _, _ = l8composition.NewHelper(options) }`,
		},
		{
			name:   "aliased call",
			source: `package fixture; import composition "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"; func run(options composition.HelperOptions) { _, _, _ = composition.NewHelper(options) }`,
		},
		{
			name:   "aliased method value",
			source: `package fixture; import composition "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"; var retained = composition.NewHelper`,
		},
		{
			name:   "dot imported call",
			source: `package fixture; import . "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"; func run(options HelperOptions) { _, _, _ = NewHelper(options) }`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := l8D7GuestProcessEntrypointNewHelperReferences(t, test.source); got != 1 {
				t.Fatalf("NewHelper references = %d, want 1", got)
			}
		})
	}
}

func l8D7GuestProcessEntrypointNewHelperReferences(t *testing.T, source string) int {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "NewHelper" {
			return true
		}
		ident, ok := selector.X.(*ast.Ident)
		if ok && ident.Name == "l8composition" {
			count++
		}
		return true
	})
	return count
}

func TestL8D7GuestProcessEntrypointsRemainDefaultOff(t *testing.T) {
	targets := []string{
		"run.go", "run_sandbox.go", "auto.go", "auto_sandbox.go",
		"factory.go", "factory_sandbox_executor.go", "sandbox.go",
	}
	sandboxdFiles, err := filepath.Glob("sandboxd*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range sandboxdFiles {
		if !strings.HasSuffix(path, "_test.go") {
			targets = append(targets, path)
		}
	}
	for _, path := range targets {
		source := readL8CredentialDeliveryFile(t, path)
		for _, marker := range []string{
			"hal-guest-credential-helper",
			"hal-guest-mount-monitor",
			"hal-guest-workload-shim",
			"l8composition.NewHelper",
			"NewControllerMonitorState",
			"RoleWorkloadShim",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("default production path %s wires guest process entrypoint %s", filepath.ToSlash(path), marker)
			}
		}
	}
}

func TestL8D7GuestProcessEntrypointsProductionFilesFailClosedWithoutListenDial(t *testing.T) {
	packages := []string{
		"hal-guest-credential-helper",
		"hal-guest-mount-monitor",
		"hal-guest-workload-shim",
	}
	for _, pkg := range packages {
		entries, err := os.ReadDir(pkg)
		if err != nil {
			t.Fatal(err)
		}
		foundLinux := false
		foundOther := false
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(pkg, entry.Name())
			source := readL8CredentialDeliveryFile(t, path)
			switch entry.Name() {
			case "main_linux.go":
				foundLinux = true
			case "main_other.go":
				foundOther = true
				if !strings.Contains(source, "os.Exit(127)") {
					t.Fatalf("%s does not fail closed", filepath.ToSlash(path))
				}
			}
			for _, forbidden := range []string{
				"sshrelay.NewHelperExtension",
				"sshrelay.NewClientExtension",
				"net.Listen",
				"net.Dial",
				"unix.Socket",
				"unix.Listen",
				"unix.Bind",
			} {
				if strings.Contains(source, forbidden) {
					t.Fatalf("production file %s contains live marker %q", filepath.ToSlash(path), forbidden)
				}
			}
			if pkg != "hal-guest-credential-helper" && strings.Contains(source, "l8composition.NewHelper") {
				t.Fatalf("production file %s calls NewHelper", filepath.ToSlash(path))
			}
			if strings.Contains(source, "l8composition.NewClient") {
				t.Fatalf("production file %s calls NewClient", filepath.ToSlash(path))
			}
		}
		if !foundLinux || !foundOther {
			t.Fatalf("%s missing linux/other mains", pkg)
		}
	}
}
