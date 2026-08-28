package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D6TmpfsActivatorVerificationContract(t *testing.T) {
	document, err := os.ReadFile("../docs/design/sandbox-runtime-v2-l8-d6-tmpfs-activator-verification.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	for _, required := range []string{
		"l8JobCredentialFileTmpfsActivator",
		"l8JobCredentialFileHandle",
		"NewProductionL8JobCredentialFileTmpfsActivator",
		"LiveSecretSource",
		"JobCredentialDeliveryModeFileTmpfs",
		"never a host absolute scratch path",
		"does not retain the live source",
		"failed revoke",
		"keeps ownership",
		"ErrL8JobCredentialRuntimeUnsupported",
		"does not implement or claim guest mount-monitor/PID1 wiring",
		"D7 live tmpfs",
		"never invoked by sandboxd",
		"NewProductionL8JobCredentialRuntime",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'Tmpfs|FileTmpfs|FileHandle' -count=1",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$' -count=1",
		"go test ./cmd -run 'TmpfsActivator|FileTmpfs' -count=1",
		"go vet ./internal/sandboxruntime/microvm/firecrackerhost",
		"No test requires KVM, Firecracker, a live guest, network, or cloud APIs.",
		"command -v golangci-lint",
		"GOOS=windows GOARCH=amd64 go test -c",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"guest mount-monitor is implemented",
		"D7 live tmpfs acceptance is complete",
		"default sandboxd constructs the activator",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("verification document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D6FileTmpfsActivatorRemainsDefaultOff(t *testing.T) {
	root := filepath.Clean("..")
	set := token.NewFileSet()
	callers := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
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
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if name == "NewProductionL8JobCredentialFileTmpfsActivator" {
				callers++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers != 0 {
		t.Fatalf("production NewProductionL8JobCredentialFileTmpfsActivator callers = %d, want zero", callers)
	}

	for _, path := range []string{
		"run.go", "run_sandbox.go", "auto.go", "auto_sandbox.go",
		"factory.go", "factory_sandbox_executor.go", "sandbox.go", "sandboxd.go",
		"../internal/sandboxworker/service.go", "../internal/sandboxworker/job_service_v2.go",
		"../internal/sandboxruntime/microvm/firecrackerhost/l8_job_credential_runtime.go",
	} {
		payload, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "NewProductionL8JobCredentialFileTmpfsActivator") {
			t.Fatalf("default production path wires file-tmpfs activator: %s", filepath.ToSlash(path))
		}
	}
}
