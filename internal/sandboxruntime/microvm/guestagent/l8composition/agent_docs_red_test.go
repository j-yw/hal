package l8composition

import (
	"os"
	"strings"
	"testing"
)

func TestL8D6GuestControlREDVerificationDocumentFreezesScopeAndSelectors(t *testing.T) {
	document, err := os.ReadFile("../../../../../docs/design/sandbox-runtime-v2-l8-d6-guest-control-contract-red.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	for _, required := range []string{
		"dependency_unaccepted", "inherited/preopened", "ControlConnectionOwner",
		"VerifiedControlStream", "package-private", "server.Options.CredentialClient",
		"nil credential client preserves", "^TestL8D6GuestV2",
		"^TestL8D6Guest(Control|Transport|Packet|CredentialClient)",
		"^TestL8D6GuestServer", "^TestL8D6Guest(ControlBoot|Agent)",
		"no command/default", "no bind, listen, dial, socket creation",
		"synthetic active or cleanup proof", "absence proof",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("verification document omits %q", required)
		}
	}
	if strings.Contains(text, "tests are intentionally RED") {
		t.Fatal("verification document still describes implemented focused tests as intentionally RED")
	}
}
