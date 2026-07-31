//go:build linux

package rootlesspodman

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestL7RawPacketProcInspectionRejectsSymlinkSubstitution(t *testing.T) {
	root := t.TempDir()
	realProcess := filepath.Join(root, "real-process")
	if err := os.Mkdir(realProcess, 0o700); err != nil {
		t.Fatalf("Mkdir(real process) error: %v", err)
	}
	if err := os.Symlink(realProcess, filepath.Join(root, "4242")); err != nil {
		t.Fatalf("Symlink(process directory) error: %v", err)
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open test root error: %v", err)
	}
	defer unix.Close(rootFD)
	if fd, err := openRawPacketProcessDirectory(rootFD, 4242); err == nil {
		unix.Close(fd)
		t.Fatal("openRawPacketProcessDirectory(symlink) error = nil, want O_NOFOLLOW rejection")
	}

	processFD, err := unix.Open(realProcess, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open real process error: %v", err)
	}
	defer unix.Close(processFD)
	outside := filepath.Join(root, "outside-status")
	if err := os.WriteFile(outside, []byte(validRawPacketProcStatusFixture()), 0o600); err != nil {
		t.Fatalf("write outside status error: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(realProcess, "status")); err != nil {
		t.Fatalf("Symlink(status) error: %v", err)
	}
	if _, err := readRawPacketProcFile(context.Background(), processFD, "status", defaultRawPacketProcBytes); err == nil {
		t.Fatal("readRawPacketProcFile(symlink) error = nil, want O_NOFOLLOW rejection")
	}
}
