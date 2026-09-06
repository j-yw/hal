package l7profile

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestL7PostBuildWorkspaceDoesNotRequireGuestOwnership(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new workspace", true: "existing workspace"}[existing], func(t *testing.T) {
			root := t.TempDir()
			target, bin, sources := filepath.Join(root, "target"), filepath.Join(root, "bin"), filepath.Join(root, "sources")
			for _, path := range []string{bin, sources, filepath.Join(target, "bin"), filepath.Join(target, "sbin"), filepath.Join(target, "usr", "bin"), filepath.Join(target, "etc")} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range []string{"bin/busybox", "sbin/ip", "usr/bin/nc", "bin/ping", "bin/ping6", "usr/bin/nslookup", "usr/bin/wget", "usr/bin/setpriv"} {
				if err := os.WriteFile(filepath.Join(target, filepath.FromSlash(path)), []byte("fixture executable\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"hal-init", "hal-guest-agent"} {
				if err := os.WriteFile(filepath.Join(sources, name), []byte("fixture "+name+"\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			workspace := filepath.Join(target, "workspace")
			if existing {
				if err := os.Mkdir(workspace, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(workspace, "keep"), []byte("existing workspace canary\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Execute the actual script. Only install is intercepted: it refuses
			// foreign owner/group requests for a simulated unprivileged builder,
			// and maps fixed /build input files into this test's private fixture.
			// No real ownership change, container, namespace or build is used.
			shim := `#!/bin/sh
set -eu
for argument do
    case "$argument" in
        -o|-g|--owner*|--group*)
            echo "pre-fakeroot install ownership denied for builder $L7_TEST_UID:$L7_TEST_GID" >&2
            exit 42 ;;
    esac
done
case "$1:$#" in
    -D:5)
        case "$5" in "$L7_TEST_TARGET"/*) ;; *) exit 90 ;; esac
        source=$4
        case "$source" in
            /build/guest-bin/hal-init) source=$L7_TEST_SOURCES/hal-init ;;
            /build/guest-bin/hal-guest-agent) source=$L7_TEST_SOURCES/hal-guest-agent ;;
            /dev/null) ;;
            *) exit 91 ;;
        esac
        mkdir -p "${5%/*}"
        cp "$source" "$5"
        chmod "$3" "$5" ;;
    -d:4)
        test "$4" = "$L7_TEST_TARGET/workspace"
        mkdir -p "$4"
        chmod "$3" "$4" ;;
    *) exit 92 ;;
esac
`
			if err := os.WriteFile(filepath.Join(bin, "install"), []byte(shim), 0755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/sh", "post-build.sh", target)
			command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "L7_TEST_UID=2001", "L7_TEST_GID=3001", "L7_TEST_TARGET=" + target, "L7_TEST_SOURCES=" + sources}
			command.WaitDelay = time.Second
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("post-build must run before fakeroot as nonmatching builder 2001:3001: %v\n%s", err, output)
			}
			info, err := os.Stat(workspace)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
				t.Fatalf("pre-fakeroot workspace is not a private directory: %v %v", info, err)
			}
			if existing {
				if data, err := os.ReadFile(filepath.Join(workspace, "keep")); err != nil || string(data) != "existing workspace canary\n" {
					t.Fatal("existing workspace contents changed")
				}
			}
		})
	}
}

func TestL7WorkspaceFinalOwnershipRemainsExplicit(t *testing.T) {
	permissions := readProfileFile(t, "permissions.txt")
	for _, required := range []string{"/workspace d 0700 1000 1000 - - - - -", "/bin/busybox f 0755 0 0 - - - - -"} {
		if !linePresent(permissions, required) {
			t.Errorf("fakeroot permissions table missing %q", required)
		}
	}
	config := readProfileFile(t, "buildroot.config")
	for _, required := range []string{`BR2_ROOTFS_DEVICE_TABLE="system/device_table.txt /src/tools/microvm/l7/permissions.txt"`, `BR2_ROOTFS_USERS_TABLES="/src/tools/microvm/l7/users.txt"`} {
		if !linePresent(config, required) {
			t.Errorf("Buildroot ownership hook missing %q", required)
		}
	}
	if !linePresent(readProfileFile(t, "users.txt"), "agent 1000 agent 1000 ! /workspace /bin/sh - Agent") {
		t.Error("guest identity changed")
	}
	verify := readProfileFile(t, "verify-final-image.sh")
	for _, required := range []string{"require_entry /workspace directory 0700 1000 1000", `require_entry "$path" regular 0755 0 0`} {
		if !strings.Contains(verify, required) {
			t.Errorf("mandatory final-image ownership check missing %q", required)
		}
	}
}
