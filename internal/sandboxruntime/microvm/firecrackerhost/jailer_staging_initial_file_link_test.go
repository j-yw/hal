//go:build linux

package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxJailerCreateFileDoesNotMutateRenamedOpenedFile(t *testing.T) {
	parent := t.TempDir()
	parentFD, err := openLinuxJailerAbsoluteDirectory(parent)
	if err != nil {
		t.Fatalf("openLinuxJailerAbsoluteDirectory(parent): %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(parentFD) })
	fd, err := unix.Openat(parentFD, "payload", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatalf("Openat(payload): %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	created, err := linuxJailerFstat(fd)
	if err != nil {
		t.Fatalf("linuxJailerFstat(payload): %v", err)
	}
	expected := linuxJailerStagingEntry{
		id: linuxJailerIdentity(created), uid: created.Uid, gid: created.Gid, mode: 0o600,
	}
	if err := unix.Renameat(parentFD, "payload", parentFD, "renamed-payload"); err != nil {
		t.Fatalf("Renameat(payload): %v", err)
	}
	replacementFD, err := unix.Openat(parentFD, "payload", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatalf("Openat(replacement): %v", err)
	}
	if err := unix.Close(replacementFD); err != nil {
		t.Fatalf("Close(replacement): %v", err)
	}
	renamed := filepath.Join(parent, "renamed-payload")
	if err := os.Chmod(renamed, 0o640); err != nil {
		t.Fatalf("Chmod(renamed payload fixture): %v", err)
	}

	if err := secureLinuxJailerOpenedFile(fd, parentFD, "payload", expected); !errors.Is(err, errJailerStagingFailed) {
		t.Errorf("secureLinuxJailerOpenedFile() error = %v, want staging failure", err)
	}
	after, err := linuxJailerFstat(fd)
	if err != nil {
		t.Fatalf("linuxJailerFstat(renamed payload): %v", err)
	}
	if !linuxJailerSameIdentity(after, expected.id) || after.Mode&0o777 != 0o640 {
		t.Errorf("renamed payload changed: identity=%t mode=%#o, want same identity and mode %#o",
			linuxJailerSameIdentity(after, expected.id), after.Mode&0o777, uint32(0o640))
	}
}
