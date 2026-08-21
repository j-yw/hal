package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestL8D6HostV2ControlFoundationVerificationContract(t *testing.T) {
	document, err := os.ReadFile("../docs/design/sandbox-runtime-v2-l8-d6-host-v2-control-foundation-verification.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	for _, required := range []string{
		"fixed guest-agent v2 control port 1025",
		"exact live Firecracker process",
		"private VSOCK socket identity",
		"canonical compatibility",
		"controller-authenticated session handshake",
		"One admitted open consumes the bridge",
		"does not implement or claim `JobCredentialRuntime`",
		"dependency_unaccepted",
		"go test -count=20 ./internal/sandboxruntime/microvm/firecrackerhost -run 'TestL8D6V2ControlFoundation'",
		"go test -race -count=5 ./internal/sandboxruntime/microvm/firecrackerhost -run 'TestL8D6V2ControlFoundation'",
		"GOOS=windows GOARCH=amd64 go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$'",
		"go test ./...", "go vet ./...", "make docs-check", "make build", "git diff --check",
		"command -v golangci-lint",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("verification document omits %q", required)
		}
	}
}
