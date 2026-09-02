//go:build linux

package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxJailerStagerRejectsReplacedNestedMutationParent(t *testing.T) {
	for _, tt := range []struct {
		name   string
		child  string
		mutate func(*testing.T, *linuxJailerStagingRoot) error
	}{
		{
			name:  "directory",
			child: "nested",
			mutate: func(_ *testing.T, root *linuxJailerStagingRoot) error {
				return root.createDirectory("boot/nested", root.authority.DirectoryMode, root.authority.UID, root.authority.GID)
			},
		},
		{
			name:  "file",
			child: "payload",
			mutate: func(t *testing.T, root *linuxJailerStagingRoot) error {
				t.Helper()
				file, err := root.createFileExclusive("boot/payload")
				if !interfaceValueIsNil(file) {
					if closeErr := file.close(); closeErr != nil {
						t.Fatalf("close staged file: %v", closeErr)
					}
				}
				return err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request, root := newMutationOrderLinuxJailerRoot(t)
			if err := root.createDirectory("boot", request.Authority.DirectoryMode, request.Authority.UID, request.Authority.GID); err != nil {
				t.Fatalf("createDirectory(boot): %v", err)
			}
			boot := filepath.Join(request.Authority.JailRootHostPath, "boot")
			if err := os.Rename(boot, boot+".owned"); err != nil {
				t.Fatalf("Rename(boot): %v", err)
			}
			if err := os.Mkdir(boot, 0o700); err != nil {
				t.Fatalf("Mkdir(replacement boot): %v", err)
			}

			if err := tt.mutate(t, root); !errors.Is(err, errJailerStagingFailed) {
				t.Errorf("nested mutation error = %v, want staging failure", err)
			}
			if _, err := os.Lstat(filepath.Join(boot, tt.child)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("replacement parent child exists: %v", err)
			}
		})
	}
}

func TestLinuxJailerStagerRejectsAliasedFileBeforeMutation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		prepare func(*testing.T, *linuxJailerStagingFile, string)
		mutate  func(*linuxJailerStagingFile) error
		check   func(*testing.T, string)
	}{
		{
			name:    "write",
			prepare: func(*testing.T, *linuxJailerStagingFile, string) {},
			mutate: func(file *linuxJailerStagingFile) error {
				_, err := file.Write([]byte("mutated"))
				return err
			},
			check: func(t *testing.T, external string) {
				t.Helper()
				if data, err := os.ReadFile(external); err != nil || len(data) != 0 {
					t.Errorf("external link data = %q, error = %v; want empty", data, err)
				}
			},
		},
		{
			name: "ownership",
			prepare: func(t *testing.T, file *linuxJailerStagingFile, _ string) {
				t.Helper()
				if err := unix.Fchmod(file.fd, unix.S_ISUID|0o600); err != nil {
					t.Fatalf("Fchmod(setuid fixture): %v", err)
				}
			},
			mutate: func(file *linuxJailerStagingFile) error {
				return file.setOwnership(file.root.authority.UID, file.root.authority.GID)
			},
			check: func(t *testing.T, external string) {
				t.Helper()
				var stat unix.Stat_t
				if err := unix.Stat(external, &stat); err != nil {
					t.Fatalf("Stat(external): %v", err)
				}
				if stat.Mode&unix.S_ISUID == 0 {
					t.Error("external link setuid bit was cleared")
				}
			},
		},
		{
			name:    "mode",
			prepare: func(*testing.T, *linuxJailerStagingFile, string) {},
			mutate:  func(file *linuxJailerStagingFile) error { return file.setMode(0o400) },
			check: func(t *testing.T, external string) {
				t.Helper()
				info, err := os.Stat(external)
				if err != nil {
					t.Fatalf("Stat(external): %v", err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Errorf("external link mode = %#o, want %#o", info.Mode().Perm(), os.FileMode(0o600))
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request, root := newMutationOrderLinuxJailerRoot(t)
			value, err := root.createFileExclusive("payload")
			if err != nil {
				t.Fatalf("createFileExclusive(payload): %v", err)
			}
			file := value.(*linuxJailerStagingFile)
			t.Cleanup(func() { _ = file.close() })
			external := filepath.Join(request.Authority.ChrootBaseDir, "external-link")
			if err := os.Link(filepath.Join(request.Authority.JailRootHostPath, "payload"), external); err != nil {
				t.Fatalf("Link(external): %v", err)
			}
			tt.prepare(t, file, external)

			if err := tt.mutate(file); !errors.Is(err, errJailerStagingFailed) {
				t.Errorf("aliased mutation error = %v, want staging failure", err)
			}
			tt.check(t, external)
		})
	}
}

func newMutationOrderLinuxJailerRoot(t *testing.T) (jailerStagingRequest, *linuxJailerStagingRoot) {
	t.Helper()
	request, _ := newLinuxJailerStagingRequest(t)
	filesystem, err := newLinuxJailerStagingFilesystem(request.Authority)
	if err != nil {
		t.Fatalf("newLinuxJailerStagingFilesystem(): %v", err)
	}
	owned, err := filesystem.createExclusiveRoot(jailerStagingRootRequest{
		HostRoot: request.Authority.JailRootHostPath,
		Mode:     request.Authority.DirectoryMode,
		UID:      request.Authority.UID,
		GID:      request.Authority.GID,
	})
	if err != nil {
		t.Fatalf("createExclusiveRoot(): %v", err)
	}
	root := owned.(*linuxJailerStagingRoot)
	t.Cleanup(func() { _ = root.close() })
	return request, root
}
