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
)

func TestL8D6SSHActivatorVerificationContract(t *testing.T) {
	document, err := os.ReadFile("../docs/design/sandbox-runtime-v2-l8-d6-ssh-activator-verification.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	for _, required := range []string{
		"default-off",
		"NewProductionL8JobCredentialSSHRelayActivator",
		"l8JobCredentialSSHRelayActivator",
		"l8JobCredentialSSHRelayHandle",
		"never invoked by sandboxd",
		"`hal run`",
		"`hal auto`",
		"NewProductionL8JobCredentialRuntime",
		"JobCredentialDeliveryModeSSHAgent",
		"daemon-local sshrelay lease",
		"PolicyID",
		"PolicyRevision",
		"does not persist entry, path, peer, or key",
		"failed revoke must not drop ownership",
		"liveValue",
		"ErrSerialization",
		"no agent paths, sockets, peer keys, or secrets",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'SSHRelay|SSHActivator|JobCredential.*SSH' -count=1",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost/sshrelay -count=1",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$' -count=1",
		"go test ./cmd -run 'SSHActivator|SSHRelayActivator' -count=1",
		"go vet ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxruntime/microvm/firecrackerhost/sshrelay",
		"fake-only",
		"no real ssh-agent sockets",
		"do not use KVM",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
		"architecture document remains unchanged",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("verification document omits %q", required)
		}
	}
}

func TestL8D6SSHRelayActivatorRemainsDefaultOff(t *testing.T) {
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
			if name == "NewProductionL8JobCredentialSSHRelayActivator" {
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
		t.Fatalf("production NewProductionL8JobCredentialSSHRelayActivator callers = %d, want zero", callers)
	}

	for _, path := range []string{
		"sandboxd.go", "run.go", "run_sandbox.go", "auto.go", "auto_sandbox.go",
		"factory.go", "factory_sandbox_executor.go",
		filepath.Join("..", "internal", "sandboxworker", "service.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_runtime.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "adapter.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver.go"),
	} {
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(payload), "NewProductionL8JobCredentialSSHRelayActivator") {
			t.Fatalf("default production path %s constructs the SSH-agent activator", filepath.ToSlash(path))
		}
	}
}

func TestL8D6SSHActivatorProductionSourceGuards(t *testing.T) {
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l8_job_credential_ssh_activator.go")
	source := readL8CredentialDeliveryFile(t, path)
	for _, forbidden := range []string{
		"SSH_AUTH_SOCK",
		"OpenVerifiedConnection",
		"NewLinuxAgentDialer",
		"NewLinuxPeerVerifier",
		"os/exec",
		"net.Dial",
		"net.Listen",
		"/run/user/",
		"agent.sock",
		"WriteFile",
		"KVM",
		"kvm",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("SSH-agent activator production file contains forbidden marker %q", forbidden)
		}
	}

	file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"context": true,
		"errors":  true,
		"fmt":     true,
		"sync":    true,
		"github.com/jywlabs/hal/internal/sandboxruntime":                                       true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/sshrelay":      true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol": true,
	}
	for _, spec := range file.Imports {
		importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
		if unquoteErr != nil {
			t.Fatal(unquoteErr)
		}
		if !allowed[importPath] {
			t.Fatalf("SSH-agent activator production file imports %q", importPath)
		}
	}
}
