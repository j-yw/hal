//go:build l7_setpriv_semantics && linux

package l7profile

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestL7SetprivLockedKeepCapsSemantics(t *testing.T) {
	for _, command := range []string{"getsubids", "newgidmap", "newuidmap", "setpriv", "unshare"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("%s is required for the explicit setpriv semantic gate", command)
		}
	}
	current, err := user.Current()
	if err != nil || strings.TrimSpace(current.Username) == "" {
		t.Fatal("current user identity is required for the explicit setpriv semantic gate")
	}
	uidStart := requireL7SubordinateID(t, current.Username, false)
	gidStart := requireL7SubordinateID(t, current.Username, true)

	productionOptions := l7ProductionSetprivOptions(t)
	arguments := []string{
		"--user",
		"--map-users=" + l7IDMap(0, uint64(os.Getuid()), 1),
		"--map-users=" + l7SubordinateIDMap(uidStart),
		"--map-groups=" + l7IDMap(0, uint64(os.Getgid()), 1),
		"--map-groups=" + l7SubordinateIDMap(gidStart),
		"--setgroups=allow",
		"setpriv",
	}
	arguments = append(arguments, productionOptions...)
	arguments = append(arguments,
		"/bin/sh", "-c",
		"/usr/bin/setpriv --dump; grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' /proc/self/status",
	)
	output, err := exec.Command("unshare", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("setpriv semantic probe failed with sanitized exit state: %v", err)
	}
	text := string(output)
	for _, required := range []string{
		"Inheritable capabilities: [none]",
		"Ambient capabilities: [none]",
		"Capability bounding set: [none]",
		"Securebits: keep_caps_locked",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("setpriv semantic probe missing sanitized assertion %q", required)
		}
	}
	requireL7StatusFields(t, text, "uid:", []string{"1000"})
	requireL7StatusFields(t, text, "euid:", []string{"1000"})
	requireL7StatusFields(t, text, "gid:", []string{"1000"})
	requireL7StatusFields(t, text, "egid:", []string{"1000"})
	requireL7StatusFields(t, text, "Supplementary groups:", []string{"[none]"})
	requireL7StatusFields(t, text, "no_new_privs:", []string{"1"})
	requireL7ProcStatusFields(t, text, "Uid:", []string{"1000", "1000", "1000", "1000"})
	requireL7ProcStatusFields(t, text, "Gid:", []string{"1000", "1000", "1000", "1000"})
	requireL7ProcStatusFields(t, text, "Groups:", nil)
	for _, field := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
		requireL7ProcStatusFields(t, text, field, []string{"0000000000000000"})
	}
	requireL7ProcStatusFields(t, text, "NoNewPrivs:", []string{"1"})
}

func requireL7ProcStatusFields(t *testing.T, output, name string, want []string) {
	requireL7StatusFields(t, output, name, want)
}

func requireL7StatusFields(t *testing.T, output, name string, want []string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		got := strings.Fields(strings.TrimPrefix(line, name))
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("setpriv semantic probe returned an invalid sanitized %s field", name)
		}
		return
	}
	t.Fatalf("setpriv semantic probe omitted sanitized %s field", name)
}

func l7ProductionSetprivOptions(t *testing.T) []string {
	t.Helper()
	init := readProfileFile(t, "rootfs-overlay/sbin/init")
	lines := strings.Split(init, "\n")
	options := make([]string, 0, 12)
	reading := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "/usr/bin/setpriv \\" {
			reading = true
			continue
		}
		if !reading {
			continue
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		if line == "/usr/bin/hal-guest-agent" {
			break
		}
		options = append(options, strings.Fields(line)...)
	}
	want := []string{
		"--bounding-set=-all",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--securebits=+keep_caps_locked",
		"--reuid", "1000",
		"--regid", "1000",
		"--clear-groups",
		"--no-new-privs",
	}
	if strings.Join(options, "\x00") != strings.Join(want, "\x00") {
		t.Fatal("production setpriv option sequence drifted from the semantic probe contract")
	}
	return options
}

func requireL7SubordinateID(t *testing.T, username string, group bool) uint64 {
	t.Helper()
	arguments := []string{username}
	if group {
		arguments = []string{"-g", username}
	}
	output, err := exec.Command("getsubids", arguments...).Output()
	if err != nil {
		t.Fatal("configured subordinate ID provider query failed for the explicit setpriv semantic gate")
	}
	id, err := parseL7GetSubIDs(output, username)
	if err != nil {
		t.Fatal("configured subordinate ID provider returned invalid output for the explicit setpriv semantic gate")
	}
	return id
}

func parseL7GetSubIDs(output []byte, username string) (uint64, error) {
	const maximumLinuxID = uint64(1<<32 - 2)
	if username == "" {
		return 0, fmt.Errorf("invalid configured provider identity")
	}
	text := strings.TrimSuffix(string(output), "\n")
	if text == "" {
		return 0, fmt.Errorf("empty configured provider output")
	}
	lines := strings.Split(text, "\n")
	var first uint64
	for index, line := range lines {
		fields := strings.Fields(strings.TrimSuffix(line, "\r"))
		if len(fields) != 4 || fields[0] != strconv.Itoa(index)+":" || fields[1] != username {
			return 0, fmt.Errorf("malformed configured provider record")
		}
		start, startErr := strconv.ParseUint(fields[2], 10, 64)
		count, countErr := strconv.ParseUint(fields[3], 10, 64)
		if startErr != nil || countErr != nil || start == 0 || start > maximumLinuxID || count == 0 || count-1 > maximumLinuxID-start {
			return 0, fmt.Errorf("invalid configured provider range")
		}
		if index == 0 {
			first = start
		}
	}
	return first, nil
}

func l7SubordinateIDMap(outer uint64) string {
	return l7IDMap(1000, outer, 1)
}

func l7IDMap(inner, outer, count uint64) string {
	return fmt.Sprintf("%d:%d:%d", inner, outer, count)
}
