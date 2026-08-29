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

const l8D7HelperTransportVerificationDoc = "sandbox-runtime-v2-l8-d7-helper-transport.md"

func TestL8D7HelperTransportVerificationContract(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7HelperTransportVerificationDoc))
	for _, required := range []string{
		"default-off",
		"injected helper I/O",
		"HelperConnectionOwner",
		"VerifiedHelperStream",
		"inherited/preopened",
		"ErrClientControlDependencyUnaccepted",
		"PacketTypePrepareBegin",
		"does not add `net.Listen`",
		"`unix.Socket`",
		"`SOCK_STREAM`",
		"control_contract_red.go",
		"socketpairs exist in tests only",
		"never creates sockets",
		"Payload send",
		"SCM_RIGHTS",
		"does not mint proofs",
		"Default command paths stay unwired",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"D7 prepared-Linux acceptance remains unaccepted",
		"go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1",
		"go test ./cmd -run '^TestL8D7HelperTransport' -count=1",
		"go vet ./internal/sandboxruntime/microvm/guestagent/server/credentialclient ./cmd",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
		"sandboxd",
		"`hal run`",
		"`hal auto`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("D7 helper transport verification document omits %q", required)
		}
	}
}

func TestL8D7HelperTransportRemainsDefaultOff(t *testing.T) {
	root := filepath.Clean("..")
	set := token.NewFileSet()
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
		if strings.Contains(normalized, "/credentialclient/") {
			return nil
		}
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			ident, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			switch ident.Name {
			case "HelperConnectionOwner", "VerifiedHelperStream", "newPreopenedHelperConnectionOwner":
				t.Errorf("production file %s references helper transport %s", normalized, ident.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	targets := []string{
		"run_sandbox.go", "auto_sandbox.go", "factory.go", "factory_sandbox_executor.go",
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
			"HelperConnectionOwner",
			"VerifiedHelperStream",
			"newPreopenedHelperConnectionOwner",
			"writeHelperSendPacket",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("default production path %s wires helper transport %s", filepath.ToSlash(path), marker)
			}
		}
	}
}

func TestL8D7HelperTransportControlContractStillForbidsListenDial(t *testing.T) {
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "credentialclient", "control_contract_red.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"net.Listen",
		"net.Dial",
		"unix.Socket",
		"SOCK_STREAM",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("control_contract_red.go contains live helper transport %q", forbidden)
		}
	}
}
