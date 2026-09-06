//go:build linux && integration

package firecrackerhost

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// This tagged test starts only this test executable, with an empty environment.
// Its ordinary files and injected ownership checks are not prepared-host proof.
func TestJailerIdentityProcessSharedLock(t *testing.T) {
	authority, directory := realJailerIdentityFixture(t)
	lease := reserveTestJailerIdentity(t, authority)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(want string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestJailerIdentityLockChild$", "--", "identity-lock-child", directory, want)
		cmd.Env = []string{}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("lock child: %v: %s", err, output)
		}
	}
	run("busy")
	if err := lease.release(t.Context()); err != nil {
		t.Fatal(err)
	}
	run("available")
}

func TestJailerIdentityLockChild(t *testing.T) {
	args := os.Args
	if len(args) < 4 || args[len(args)-3] != "identity-lock-child" {
		return
	}
	directory, want := args[len(args)-2], args[len(args)-1]
	fs, err := openLinuxJailerIdentityFilesystemWithChecks(directory, ordinaryJailerIdentityChecks(t))
	if err != nil {
		t.Fatal(err)
	}
	defer fs.close()
	err = fs.lock()
	if (want == "busy" && err == nil) || (want == "available" && err != nil) || (want != "busy" && want != "available") {
		t.Fatal("unexpected process-shared lock result")
	}
}
