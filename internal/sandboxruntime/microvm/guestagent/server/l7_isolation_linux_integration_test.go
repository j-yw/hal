//go:build l7_guest_isolation_semantics && linux

package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

const l7IsolationChildEnvironment = "HAL_L7_GUEST_ISOLATION_CHILD"

func TestL7GuestAgentLiveProcessIsolationSemantics(t *testing.T) {
	if os.Getenv(l7IsolationChildEnvironment) == "1" {
		if os.Geteuid() != 1000 || os.Getegid() != 1000 {
			t.Fatal("live proof child identity transition failed")
		}
		verifier, err := NewLinuxIsolationVerifier(LinuxIsolationVerifierOptions{})
		if err != nil {
			t.Fatal("construct live verifier failed")
		}
		result, err := verifier.VerifyIsolation(context.Background(), guestagent.IsolationProofRequest{Generation: "selected-live-generation"})
		if err != nil || !result.RestrictedIdentity || !result.CapabilitiesCleared || !result.NoNewPrivileges || !result.SupplementaryGroupsCleared || !result.RawPacketSocketDenied {
			t.Fatal("exact live guest-agent process isolation proof failed")
		}
		return
	}

	for _, executable := range []string{"getsubids", "newgidmap", "newuidmap", "setpriv", "unshare"} {
		if _, err := exec.LookPath(executable); err != nil {
			t.Fatalf("%s is required for the selected live guest isolation gate", executable)
		}
	}
	current, err := user.Current()
	if err != nil || strings.TrimSpace(current.Username) == "" {
		t.Fatal("current user identity is required for the selected live guest isolation gate")
	}
	uidStart := l7RequiredSubordinateStart(t, current.Username, false)
	gidStart := l7RequiredSubordinateStart(t, current.Username, true)
	arguments := []string{
		"--user",
		fmt.Sprintf("--map-users=0:%d:1", os.Getuid()),
		fmt.Sprintf("--map-users=1:%d:65536", uidStart),
		fmt.Sprintf("--map-groups=0:%d:1", os.Getgid()),
		fmt.Sprintf("--map-groups=1:%d:65536", gidStart),
		"--setgroups=allow",
		"setpriv",
		"--bounding-set=-all",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--securebits=+keep_caps_locked",
		"--reuid", "1000",
		"--regid", "1000",
		"--clear-groups",
		"--no-new-privs",
		os.Args[0], "-test.run", "^TestL7GuestAgentLiveProcessIsolationSemantics$",
	}
	command := exec.Command("unshare", arguments...)
	command.Env = append(os.Environ(), l7IsolationChildEnvironment+"=1")
	if err := command.Run(); err != nil {
		t.Fatalf("selected live guest isolation process proof failed with sanitized exit state: %v", err)
	}
}

func l7RequiredSubordinateStart(t *testing.T, username string, group bool) uint64 {
	t.Helper()
	arguments := []string{username}
	if group {
		arguments = []string{"-g", username}
	}
	output, err := exec.Command("getsubids", arguments...).Output()
	if err != nil || len(output) > 16<<10 {
		t.Fatal("configured subordinate ID provider query failed")
	}
	fields := strings.Fields(string(output))
	if len(fields) != 4 || fields[1] != username {
		t.Fatal("configured subordinate ID provider returned invalid output")
	}
	start, err := strconv.ParseUint(fields[2], 10, 64)
	count, countErr := strconv.ParseUint(fields[3], 10, 64)
	if err != nil || countErr != nil || start == 0 || count < 65536 {
		t.Fatal("configured subordinate ID provider returned invalid output")
	}
	return start
}
