//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These are real unprivileged sealed-memfd readback tests, not bind-mount,
// trusted path/UID ownership, gate process, or Jailer launch acceptance.
func TestJailerRecoveryGateMeasuredSnapshotReadback(t *testing.T) {
	payload := []byte("measured executable fixture, never executed")
	digest := sha256.Sum256(payload)
	file, err := snapshotStrictJailerExecutable(bytes.NewReader(payload), digest)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	expected := jailerRecoveryMountedExecutable{Path: "/prepared/jailer", Device: uint64(stat.Dev), Inode: stat.Ino, Size: stat.Size, SHA256: hex.EncodeToString(digest[:])}
	if err := verifyJailerRecoveryMountedFile(file, expected); err != nil {
		t.Errorf("exact sealed snapshot refused: %v", err)
	}
	for name, mutate := range map[string]func(*jailerRecoveryMountedExecutable){
		"device": func(e *jailerRecoveryMountedExecutable) { e.Device++ },
		"inode":  func(e *jailerRecoveryMountedExecutable) { e.Inode++ },
		"size":   func(e *jailerRecoveryMountedExecutable) { e.Size++ },
		"digest": func(e *jailerRecoveryMountedExecutable) { e.SHA256 = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := expected
			mutate(&changed)
			if verifyJailerRecoveryMountedFile(file, changed) == nil {
				t.Fatal("mismatched mounted bytes accepted")
			}
		})
	}
	other, err := snapshotStrictJailerExecutable(bytes.NewReader(payload), digest)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if verifyJailerRecoveryMountedFile(other, expected) == nil {
		t.Fatal("same bytes on replacement inode accepted")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if verifyJailerRecoveryMountedFile(file, expected) == nil {
		t.Fatal("closed descriptor accepted")
	}
}

func TestJailerRecoveryGateRejectsMutableSnapshot(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "mutable")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	payload := []byte("mutable executable fixture")
	if _, err := file.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o555); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	expected := jailerRecoveryMountedExecutable{Path: "/prepared/jailer", Device: uint64(stat.Dev), Inode: stat.Ino, Size: stat.Size, SHA256: hex.EncodeToString(digest[:])}
	if verifyJailerRecoveryMountedFile(file, expected) == nil {
		t.Fatal("mutable regular file accepted as sealed mounted snapshot")
	}
}
