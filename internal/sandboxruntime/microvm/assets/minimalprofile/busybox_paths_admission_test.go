//go:build linux

package minimalprofile

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMinimalBusyboxRawTrailingSlash(t *testing.T) {
	for _, name := range []string{"usr/bin/[/", "usr/bin/[[/"} {
		t.Run(name, func(t *testing.T) {
			archive, _ := stagedFixture(t, func(entries map[string]fixtureEntry) {
				entries[name] = fixtureEntry{mode: 0777, link: "../../bin/busybox"}
			})
			if _, _, err := extractStage(archive, privateDir(t), 1700000000); err == nil {
				t.Fatal("noncanonical applet spelling accepted")
			}
		})
	}
}

// An earlier ordinary symlink can share the applet's inode. The content cache
// must not skip the per-path target/BusyBox-inode check after reading it once.
func TestMinimalBusyboxSharedInodeTargetValidation(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			target := "../../bin/busybox"
			if !valid {
				target = "../../bin/evilbox"
			}
			archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
				entries["bin/evilbox"] = fixtureEntry{mode: 0755, data: "different executable"}
				entries["usr/bin/Alias"] = fixtureEntry{mode: 0777, link: target}
				entries["usr/bin/["] = fixtureEntry{mode: 0777, link: "../../bin/busybox"}
			})
			transcript := fakeTranscript(t, archive)
			var inode string
			for _, output := range transcript {
				for _, line := range strings.Split(string(output), "\n") {
					if strings.Contains(line, "/Alias/") {
						inode = strings.Split(line, "/")[1]
					}
				}
			}
			if inode == "" {
				t.Fatal("shared-inode fixture missing")
			}
			injected, readShared := false, false
			_, err := inspect(func(command string) ([]byte, error) {
				output, ok := transcript[command]
				if !ok {
					return nil, errors.New("unexpected fixture query")
				}
				if command == "stat <"+inode+">" {
					readShared = true
				}
				if strings.HasPrefix(command, "ls ") {
					lines := strings.Split(string(output), "\n")
					for index, line := range lines {
						if strings.Contains(line, "/[/") {
							fields := strings.Split(line, "/")
							fields[1] = inode
							lines[index] = strings.Join(fields, "/")
							injected = true
						}
					}
					output = []byte(strings.Join(lines, "\n"))
				}
				return output, nil
			}, pins)
			if !injected || !readShared {
				t.Fatal("shared symlink content path not reached")
			}
			if (err == nil) != valid {
				t.Fatalf("shared-inode acceptance=%v want=%v", err == nil, valid)
			}
		})
	}
}
