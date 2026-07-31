//go:build l7_setpriv_semantics

package l7profile

import (
	"os/exec"
	"strings"
	"testing"
)

func TestL7SetprivLockedKeepCapsSemantics(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Fatal("unshare is required for the explicit setpriv semantic gate")
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Fatal("setpriv is required for the explicit setpriv semantic gate")
	}
	output, err := exec.Command(
		"unshare", "--user", "--map-root-user",
		"setpriv",
		"--securebits=+keep_caps_locked",
		"--bounding-set=-all",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--no-new-privs",
		"setpriv", "--dump",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("setpriv semantic probe failed: %v", err)
	}
	text := string(output)
	for _, required := range []string{
		"no_new_privs: 1",
		"Inheritable capabilities: [none]",
		"Ambient capabilities: [none]",
		"Capability bounding set: [none]",
		"Securebits: keep_caps_locked",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("setpriv semantic probe missing %q", required)
		}
	}
}
