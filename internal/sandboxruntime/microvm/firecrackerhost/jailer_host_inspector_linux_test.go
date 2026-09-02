//go:build linux

package firecrackerhost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOSStrictJailerHostInspectionOpenDoesNotFollowLeafSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "jailer")
	link := filepath.Join(directory, "jailer-link")
	if err := os.WriteFile(target, []byte("configured jailer bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	filesystem := osStrictJailerHostInspectionFilesystem{}
	file, err := filesystem.OpenNoFollow(target)
	if err != nil {
		t.Fatalf("OpenNoFollow(target) error = %v, want nil", err)
	}
	info, err := file.Stat()
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("inspect opened target: %v", err)
	}
	if uid, ok := filesystem.OwnerUID(info); !ok || uid != uint32(os.Geteuid()) {
		t.Fatalf("OwnerUID() = %d/%t, want current effective UID", uid, ok)
	}

	if file, err := filesystem.OpenNoFollow(link); err == nil {
		file.Close()
		t.Fatal("OpenNoFollow(symlink) error = nil, want fail closed")
	}
}
