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

const l8D6HTTPActivatorVerificationDoc = "sandbox-runtime-v2-l8-d6-http-activator-verification.md"

func TestL8D6HTTPActivatorVerificationContract(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D6HTTPActivatorVerificationDoc))
	for _, required := range []string{
		"default-off",
		"TicketStore",
		"NewProductionL8JobCredentialHTTPProxyActivator",
		"fake-only",
		"do not invoke it unless",
		"failed revoke does not drop ownership",
		"does not listen or dial",
		"does not claim D7",
		"L10",
		"L11",
		"live HTTP enforcement",
		"Default command paths stay unwired",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'L8JobCredential.*HTTP|HTTPActivator|HttpActivator' -count=1",
		"go test ./internal/credentialproxy -count=1",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$' -count=1",
		"go test ./cmd -run 'HTTPActivator|HttpActivator' -count=1",
		"go vet ./internal/sandboxruntime/microvm/firecrackerhost ./internal/credentialproxy",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("HTTP activator verification document omits %q", required)
		}
	}
}

func TestL8D6HTTPActivatorRemainsDefaultOff(t *testing.T) {
	root := filepath.Clean("..")
	set := token.NewFileSet()
	callers := 0
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
			if name == "NewProductionL8JobCredentialHTTPProxyActivator" {
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
		t.Fatalf("production NewProductionL8JobCredentialHTTPProxyActivator callers = %d, want zero", callers)
	}

	targets := []string{
		"run_sandbox.go", "auto_sandbox.go", "factory.go", "factory_sandbox_executor.go",
		filepath.Join("..", "internal", "sandboxworker", "service.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_runtime.go"),
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
		if strings.Contains(source, "NewProductionL8JobCredentialHTTPProxyActivator") {
			t.Fatalf("default production path %s wires HTTP activator constructor", filepath.ToSlash(path))
		}
	}
}

func TestL8D6HTTPActivatorProductionSourceIsTicketStoreBackedAndFakeOnly(t *testing.T) {
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_http_activator.go")
	source := readL8CredentialDeliveryFile(t, path)
	for _, required := range []string{
		"credentialproxy.TicketStore",
		"credentialproxy.NewTicketStore",
		"activator.store.Issue(",
		"handle.store.Renew(",
		"handle.store.Revoke(",
		"NewProductionL8JobCredentialHTTPProxyActivator",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("HTTP activator production file omits TicketStore marker %q", required)
		}
	}
	for _, forbidden := range []string{
		"net.Listen", "net.Dial", "tls.Dial", "http.ListenAndServe", "http.Server{",
		"kvm", "KVM", "os/exec", "firecracker.Start", "unix.KVM",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("HTTP activator production file contains live marker %q", forbidden)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
