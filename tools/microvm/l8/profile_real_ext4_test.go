package l8profile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const l8ProfileContentLimit = int64(512 * 1024 * 1024)

type l8RealExt4Fixture struct {
	image   string
	debugfs string
	binDir  string
	log     string
}

func TestL8ImageProfileVerifierRealExt4Inspection(t *testing.T) {
	t.Run("logical size is not overwritten by fragment size", func(t *testing.T) {
		fixture := newL8RealExt4Fixture(t, map[string]int64{
			"oversized-sparse": l8ProfileContentLimit + 1,
		})
		payload, err := fixture.runVerifier(t, "skip-batch-content", "")
		assertL8VerifierRejection(t, payload, err, "regular-file content exceeds bounded scan limit")
	})

	t.Run("required content is size checked before extraction", func(t *testing.T) {
		fixture := newL8RealExt4Fixture(t, map[string]int64{
			"usr/bin/setpriv": l8ProfileContentLimit + 1,
		})
		payload, err := fixture.runVerifier(t, "reject-premature-required-cat", "")
		assertL8VerifierRejection(t, payload, err, "regular-file content exceeds bounded scan limit")
		if data, readErr := os.ReadFile(fixture.log); readErr == nil {
			t.Fatalf("verify-image-profile.sh read oversized required content before its size check: %s", data)
		} else if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
	})

	t.Run("reserved metadata inode is not extracted", func(t *testing.T) {
		fixture := newL8RealExt4Fixture(t, nil)
		reserved := fixture.stat(t, "<7>")
		if !strings.Contains(reserved, "Type: regular") {
			t.Fatalf("real ext4 fixture inode 7 is not the reserved regular metadata inode:\n%s", reserved)
		}
		payload, err := fixture.runVerifier(t, "reject-reserved-batch", "")
		if err != nil {
			t.Fatalf("verify-image-profile.sh safe real ext4 fixture error = %v output = %s", err, payload)
		}
		if data, readErr := os.ReadFile(fixture.log); readErr == nil {
			t.Fatalf("verify-image-profile.sh attempted to extract reserved inode 7: %s", data)
		} else if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
	})

	t.Run("individual extraction error fails closed", func(t *testing.T) {
		fixture := newL8RealExt4Fixture(t, map[string]int64{"inspect-me": 12})
		inode := l8StatInode(t, fixture.stat(t, "/inspect-me"))
		payload, err := fixture.runVerifier(t, "fail-one-extraction", inode)
		assertL8VerifierRejection(t, payload, err, "regular-file content inspection failed")
	})

	t.Run("incomplete attribute batch fails closed", func(t *testing.T) {
		fixture := newL8RealExt4Fixture(t, nil)
		payload, err := fixture.runVerifier(t, "omit-attribute-prompts", "")
		assertL8VerifierRejection(t, payload, err, "regular-file attribute inspection failed")
	})

	t.Run("newline filename fails closed", func(t *testing.T) {
		fixture := newL8RealExt4Fixture(t, map[string]int64{"npm-session\n-token": 12})
		payload, err := fixture.runVerifier(t, "skip-batch-content", "")
		assertL8VerifierRejection(t, payload, err, "directory inspection failed")
	})

	t.Run("required symlink target cannot spoof stat identity", func(t *testing.T) {
		fixture := newL8RealExt4FixtureWithNodeSymlink(t, "T\nType: regular\nMode: 0755\nUser: 0 Group: 0 ")
		payload, err := fixture.runVerifier(t, "", "")
		assertL8VerifierRejection(t, payload, err, "required-entry inspection failed")
	})
}

func newL8RealExt4Fixture(t *testing.T, extraFiles map[string]int64) l8RealExt4Fixture {
	t.Helper()
	return newL8RealExt4FixtureWithOptions(t, extraFiles, "")
}

func newL8RealExt4FixtureWithNodeSymlink(t *testing.T, target string) l8RealExt4Fixture {
	t.Helper()
	return newL8RealExt4FixtureWithOptions(t, nil, target)
}

func newL8RealExt4FixtureWithOptions(t *testing.T, extraFiles map[string]int64, nodeSymlink string) l8RealExt4Fixture {
	t.Helper()
	mke2fs := l8RequireHostTool(t, "mke2fs")
	debugfs := l8RequireHostTool(t, "debugfs")
	root := t.TempDir()
	imageRoot := filepath.Join(root, "root")
	for _, directory := range []string{
		"bin", "etc", "run/agent", "sbin", "usr/bin", "workspace",
	} {
		if err := os.MkdirAll(filepath.Join(imageRoot, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(imageRoot, "workspace"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(imageRoot, "run/agent"), 0o700); err != nil {
		t.Fatal(err)
	}

	executables := map[string]string{
		"bin/busybox":                         "safe busybox fixture\n",
		"sbin/init":                           "safe init fixture\n",
		"sbin/hal-init":                       "safe hal-init fixture\n",
		"sbin/hal-guest-role-bootstrap":       "safe bootstrap fixture\n",
		"usr/bin/hal-guest-agent":             "safe guest agent fixture\n",
		"usr/bin/hal-guest-credential-helper": "safe credential helper fixture\n",
		"usr/bin/hal-guest-mount-monitor":     "safe mount monitor fixture\n",
		"usr/bin/hal-guest-workload-shim":     "safe workload shim fixture\n",
		"usr/bin/pi":                          "safe pi fixture\n",
		"usr/bin/setpriv": strings.Join([]string{
			"--reuid", "--regid", "--clear-groups", "--no-new-privs",
			"--bounding-set", "--inh-caps", "--ambient-caps", "--securebits",
		}, " ") + "\n",
	}
	for name, content := range executables {
		l8WriteRealExt4File(t, filepath.Join(imageRoot, name), []byte(content), 0o755)
	}
	if nodeSymlink == "" {
		l8WriteRealExt4File(t, filepath.Join(imageRoot, "usr/bin/node"), []byte("safe node fixture\n"), 0o755)
		executables["usr/bin/node"] = "safe node fixture\n"
	} else if err := os.Symlink(nodeSymlink, filepath.Join(imageRoot, "usr/bin/node")); err != nil {
		t.Fatal(err)
	}
	for _, applet := range []string{
		"bin/sh", "sbin/ip", "usr/bin/env", "usr/bin/nc", "bin/ping",
		"bin/ping6", "usr/bin/nslookup", "usr/bin/wget",
	} {
		if err := os.Symlink("/bin/busybox", filepath.Join(imageRoot, applet)); err != nil {
			t.Fatal(err)
		}
	}
	l8WriteRealExt4File(t, filepath.Join(imageRoot, "etc/resolv.conf"), nil, 0o644)
	l8WriteRealExt4File(t, filepath.Join(imageRoot, "etc/passwd"), []byte(
		"agent:x:998:998:Agent:/run/agent:/bin/sh\n"+
			"workload:x:1000:1000:Workload:/workspace:/bin/sh\n"), 0o644)
	l8WriteRealExt4File(t, filepath.Join(imageRoot, "etc/group"), []byte(
		"agent:x:998:\nworkload:x:1000:\n"), 0o644)
	l8WriteRealExt4File(t, filepath.Join(imageRoot, "etc/shadow"), []byte(
		"agent:!:::::::\nworkload:!:::::::\n"), 0o600)
	for name, size := range extraFiles {
		path := filepath.Join(imageRoot, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(size); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}

	image := filepath.Join(root, "rootfs.ext4")
	imageFile, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := imageFile.Truncate(16 * 1024 * 1024); err != nil {
		imageFile.Close()
		t.Fatal(err)
	}
	if err := imageFile.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(mke2fs, "-q", "-t", "ext4", "-d", imageRoot, "-N", "128", "-F", image)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mke2fs real-ext4 fixture error = %v output = %s", err, output)
	}

	rootOwned := make([]string, 0, len(executables)+1)
	for name := range executables {
		rootOwned = append(rootOwned, "/"+name)
	}
	rootOwned = append(rootOwned, "/etc/resolv.conf")
	for _, path := range rootOwned {
		l8SetExt4InodeField(t, debugfs, image, path, "uid", "0")
		l8SetExt4InodeField(t, debugfs, image, path, "gid", "0")
	}
	for _, change := range []struct {
		path, field, value string
	}{
		{"/workspace", "uid", "1000"}, {"/workspace", "gid", "1000"},
		{"/run/agent", "uid", "998"}, {"/run/agent", "gid", "998"},
	} {
		l8SetExt4InodeField(t, debugfs, image, change.path, change.field, change.value)
	}

	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	l8WriteRealExt4File(t, filepath.Join(binDir, "debugfs"), []byte(l8RealExt4DebugfsWrapper), 0o700)
	return l8RealExt4Fixture{
		image:   image,
		debugfs: debugfs,
		binDir:  binDir,
		log:     filepath.Join(root, "debugfs-wrapper.log"),
	}
}

func (fixture l8RealExt4Fixture) runVerifier(t *testing.T, mode, inode string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", "verify-image-profile.sh", fixture.image)
	command.Env = append(os.Environ(),
		"PATH="+fixture.binDir+":"+os.Getenv("PATH"),
		"HAL_L8_REAL_DEBUGFS="+fixture.debugfs,
		"HAL_L8_REAL_EXT4_TEST_MODE="+mode,
		"HAL_L8_REAL_EXT4_TEST_INODE="+inode,
		"HAL_L8_REAL_EXT4_TEST_LOG="+fixture.log,
	)
	payload, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("verify-image-profile.sh exceeded bounded real-ext4 test timeout: %v", ctx.Err())
	}
	return payload, err
}

func (fixture l8RealExt4Fixture) stat(t *testing.T, filespec string) string {
	t.Helper()
	command := exec.Command(fixture.debugfs, "-R", "stat "+filespec, fixture.image)
	payload, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("debugfs stat %s error = %v output = %s", filespec, err, payload)
	}
	return string(payload)
}

func l8RequireHostTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("real-ext4 regression requires %s: %v", name, err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func l8WriteRealExt4File(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func l8SetExt4InodeField(t *testing.T, debugfs, image, path, field, value string) {
	t.Helper()
	command := exec.Command(debugfs, "-w", "-R", fmt.Sprintf("set_inode_field %s %s %s", path, field, value), image)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("debugfs set_inode_field %s %s error = %v output = %s", path, field, err, output)
	}
}

func l8StatInode(t *testing.T, stat string) string {
	t.Helper()
	match := regexp.MustCompile(`(?m)^Inode: ([1-9][0-9]*) `).FindStringSubmatch(stat)
	if len(match) != 2 {
		t.Fatalf("debugfs stat is missing inode: %s", stat)
	}
	return match[1]
}

func assertL8VerifierRejection(t *testing.T, payload []byte, err error, diagnostic string) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 || exitErr.ExitCode() == 2 {
		t.Fatalf("verify-image-profile.sh exit = %v output = %s, want fail-closed rejection", err, payload)
	}
	if !strings.Contains(string(payload), diagnostic) {
		t.Fatalf("verify-image-profile.sh output = %s, want sanitized diagnostic %q", payload, diagnostic)
	}
}

const l8RealExt4DebugfsWrapper = `#!/bin/sh
set -eu

mode=${HAL_L8_REAL_EXT4_TEST_MODE:-}
if [ "${1:-}" = "-R" ] && [ "$mode" = "reject-premature-required-cat" ] && [ "$2" = "cat /usr/bin/setpriv" ]; then
	printf '%s\n' 'oversized required content read before size check' >"$HAL_L8_REAL_EXT4_TEST_LOG"
	printf '%s\n' 'debugfs test wrapper: premature required-content read rejected' >&2
	exit 0
fi

if [ "${1:-}" = "-R" ] && [ "$mode" = "reject-reserved-batch" ]; then
	case "$2" in
		"dump <7> "*)
			printf '%s\n' 'reserved inode 7 extraction attempted' >"$HAL_L8_REAL_EXT4_TEST_LOG"
			printf '%s\n' 'debugfs test wrapper: reserved inode rejected' >&2
			exit 91
			;;
	esac
fi

if [ "${1:-}" = "-f" ] && [ "$mode" = "omit-attribute-prompts" ] && grep -Fq 'ea_list <' "$2"; then
	printf '%s\n' 'debugfs 1.47.4 (test wrapper)' >&2
	exit 0
fi

if [ "${1:-}" = "-f" ] && grep -Fq 'cat <' "$2"; then
	case "$mode" in
		reject-reserved-batch)
			if grep -Fxq 'cat <7>' "$2"; then
				printf '%s\n' 'reserved inode 7 extraction attempted' >"$HAL_L8_REAL_EXT4_TEST_LOG"
				printf '%s\n' 'debugfs test wrapper: reserved inode rejected' >&2
				exit 91
			fi
			;;
		skip-batch-content|fail-one-extraction)
			printf '%s\n' 'debugfs test wrapper: content batch omitted' >&2
			exit 0
			;;
	esac
fi

if [ "${1:-}" = "-R" ] && [ "$mode" = "fail-one-extraction" ]; then
	case "$2" in
		"dump <${HAL_L8_REAL_EXT4_TEST_INODE}> "*)
			printf '%s\n' 'debugfs test wrapper: simulated per-file extraction error' >&2
			exit 0
			;;
	esac
fi

exec "$HAL_L8_REAL_DEBUGFS" "$@"
`
