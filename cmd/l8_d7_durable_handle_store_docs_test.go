package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestL8D7DurableHandleStoreVerificationDocument(t *testing.T) {
	document, err := os.ReadFile("../docs/design/sandbox-runtime-v2-l8-d7-durable-handle-store.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(document)), " ")
	for _, required := range []string{
		"handle metadata",
		"NewProductionL8JobCredentialHandleStore",
		"RecoverJobCredentials",
		"dependency_unaccepted",
		"NewJobCredentialCleanupProof",
		"openat",
		"O_NOFOLLOW",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"never constructed by sandboxd",
		"NewProductionL8JobCredentialRuntime",
		"No test requires KVM, Firecracker, a live guest, network, or cloud APIs.",
		"command -v golangci-lint",
		"GOOS=windows GOARCH=amd64 go test -c",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"default sandboxd constructs the handle store",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("verification document contains forbidden claim %q", forbidden)
		}
	}
}
