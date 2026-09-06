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

const l8D7L7SessionFactoryDoc = "sandbox-runtime-v2-l8-d7-l7-session-factory.md"

func TestL8D7L7SessionFactoryVerificationContract(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7L7SessionFactoryDoc))), " ")
	for _, required := range []string{
		"default-off",
		"NewProductionL7RecoverySessionFactory",
		"l7network.ReconcilerOptions",
		"l7network.NewRecoveredVMTerminationVerifier",
		"recoverNetwork",
		"l7network.ErrInvalidConfiguration",
		"errL8RuntimeOwnerInvalid",
		"NewProductionL8JobCredentialRuntime",
		"do not call `l7network.NewReconciler`",
		"sandboxd",
		"hal run",
		"hal auto",
		"fake-only",
		"does not accept D7 prepared-Linux live proof",
		"does not claim L8",
		"L10",
		"L11",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'ProductionL7RecoverySessionFactory|L7SessionFactory' -count=1",
		"go test ./cmd -run 'L7SessionFactory|L8D7PreparedLinuxDefaultConstructorsDoNotCreateL7SessionFactory' -count=1",
		"go vet ./internal/sandboxruntime/microvm/firecrackerhost ./cmd",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L7 session factory verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"D7 prepared-Linux acceptance is accepted",
		"D7 prepared-Linux acceptance is complete",
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L7 session factory verification document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D7L7SessionFactoryRemainsDefaultOff(t *testing.T) {
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
		if strings.HasSuffix(filepath.ToSlash(path), "microvm/firecrackerhost/l8_l7_recovery_session_factory.go") {
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
			if name == "NewProductionL7RecoverySessionFactory" {
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
		t.Fatalf("production NewProductionL7RecoverySessionFactory callers = %d, want zero", callers)
	}

	for _, path := range []string{
		"run.go", "run_sandbox.go", "auto.go", "auto_sandbox.go",
		"factory.go", "factory_sandbox_executor.go", "sandbox.go", "sandboxd.go",
		filepath.Join("..", "internal", "sandboxworker", "service.go"),
		filepath.Join("..", "internal", "sandboxworker", "job_service_v2.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_runtime.go"),
	} {
		payload, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "NewProductionL7RecoverySessionFactory") {
			t.Fatalf("default production path wires L7 recovery session factory: %s", filepath.ToSlash(path))
		}
	}
}
