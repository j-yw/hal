//go:build linux

package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxJailerStagerStagesAndRemovesExactOwnedGeneration(t *testing.T) {
	request, common := newLinuxJailerStagingRequest(t)
	filesystem, err := newLinuxJailerStagingFilesystem(request.Authority)
	if err != nil {
		t.Fatalf("newLinuxJailerStagingFilesystem() error = %v, want nil", err)
	}

	result, err := stageStrictJailerResources(filesystem, request)
	if err != nil {
		t.Fatalf("stageStrictJailerResources() error = %v, want nil", err)
	}
	if err := result.verifyOwnedRoot(); err != nil {
		t.Fatalf("verifyOwnedRoot() error = %v, want nil", err)
	}

	for _, correlation := range result.pathCorrelations() {
		data, readErr := os.ReadFile(correlation.hostPath)
		if readErr != nil {
			t.Fatalf("read staged %s: %v", correlation.role, readErr)
		}
		if int64(len(data)) != correlation.sizeBytes || sha256Hex(data) != correlation.sha256 {
			t.Fatalf("staged %s measurement does not match correlation", correlation.role)
		}
		assertLinuxJailerPathMetadata(t, correlation.hostPath, request.Authority.UID, request.Authority.GID, uint32(correlation.mode.Perm()), false)
	}
	assertLinuxJailerPathMetadata(t, request.Authority.JailRootHostPath, request.Authority.UID, request.Authority.GID, 0o700, true)
	runtimeRoot := filepath.Dir(request.Authority.JailRootHostPath)
	assertLinuxJailerPathMetadata(t, runtimeRoot, request.Authority.UID, request.Authority.GID, 0o700, true)

	// Jailer may add runtime-owned state after the pre-launch verification. The
	// retained lease must remove those descendants without following symlinks.
	jailerState := filepath.Join(request.Authority.JailRootHostPath, "jailer-state")
	if err := os.Mkdir(jailerState, 0o700); err != nil {
		t.Fatalf("Mkdir(jailer state): %v", err)
	}
	if err := os.WriteFile(filepath.Join(jailerState, "log"), []byte("runtime output"), 0o600); err != nil {
		t.Fatalf("WriteFile(jailer log): %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside): %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(jailerState, "outside-link")); err != nil {
		t.Fatalf("Symlink(outside): %v", err)
	}

	if err := result.releaseOwnedRoot(); err != nil {
		t.Fatalf("releaseOwnedRoot() error = %v, want nil", err)
	}
	if err := result.releaseOwnedRoot(); err != nil {
		t.Fatalf("second releaseOwnedRoot() error = %v, want idempotent nil", err)
	}
	if _, err := os.Lstat(runtimeRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned runtime generation remains: %v", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "preserve" {
		t.Fatalf("outside symlink target changed: data=%q error=%v", data, err)
	}
	if info, err := os.Stat(common); err != nil || !info.IsDir() {
		t.Fatalf("common authority removed or changed: info=%v error=%v", info, err)
	}
}

func TestLinuxJailerStagerRetainsRootWhenPostMkdirStatFails(t *testing.T) {
	request, _ := newLinuxJailerStagingRequest(t)
	filesystem, err := newLinuxJailerStagingFilesystem(request.Authority)
	if err != nil {
		t.Fatalf("newLinuxJailerStagingFilesystem() error = %v, want nil", err)
	}
	linuxFilesystem := filesystem.(*linuxJailerStagingFilesystem)
	realStatEntry := linuxFilesystem.statEntry
	failRootStat := true
	linuxFilesystem.statEntry = func(parentFD int, name string) (unix.Stat_t, error) {
		if name == "root" && failRootStat {
			failRootStat = false
			return unix.Stat_t{}, unix.EIO
		}
		return realStatEntry(parentFD, name)
	}

	result, err := stageStrictJailerResources(filesystem, request)
	if !errors.Is(err, errJailerStagingFailed) || !errors.Is(err, errJailerStagingCleanupIncomplete) {
		t.Fatalf("stage error = %v, want failed and cleanup-incomplete", err)
	}
	if !result.retainsOwnedRoot() {
		t.Fatal("post-mkdir stat failure discarded retained dirfd cleanup authority")
	}
	if _, statErr := os.Stat(request.Authority.JailRootHostPath); statErr != nil {
		t.Fatalf("quarantined root is unavailable before retry: %v", statErr)
	}
	if releaseErr := result.releaseOwnedRoot(); releaseErr != nil {
		t.Fatalf("releaseOwnedRoot() error = %v, want exact retry cleanup", releaseErr)
	}
	if _, statErr := os.Lstat(filepath.Dir(request.Authority.JailRootHostPath)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("runtime generation remains after terminal retry: %v", statErr)
	}
}

func TestLinuxJailerStagerRequiresPrivatePreexistingCommonAuthority(t *testing.T) {
	t.Run("missing common directory", func(t *testing.T) {
		request, common := newLinuxJailerStagingRequestWithoutCommon(t)
		_, err := newLinuxJailerStagingFilesystem(request.Authority)
		if !errors.Is(err, errJailerStagingFailed) {
			t.Fatalf("constructor error = %v, want staging failure", err)
		}
		if _, statErr := os.Lstat(common); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("constructor created broad parent %q: %v", common, statErr)
		}
		assertJailerStagingErrorRedacted(t, err)
	})

	t.Run("symlink common directory", func(t *testing.T) {
		request, common := newLinuxJailerStagingRequestWithoutCommon(t)
		outside := t.TempDir()
		if err := os.Symlink(outside, common); err != nil {
			t.Fatalf("Symlink(common): %v", err)
		}
		_, err := newLinuxJailerStagingFilesystem(request.Authority)
		if !errors.Is(err, errJailerStagingFailed) {
			t.Fatalf("constructor error = %v, want staging failure", err)
		}
		assertJailerStagingErrorRedacted(t, err)
	})
}

func TestLinuxJailerStagerRejectsCollisionsWithoutRemovingUnownedState(t *testing.T) {
	request, _ := newLinuxJailerStagingRequest(t)
	filesystem, err := newLinuxJailerStagingFilesystem(request.Authority)
	if err != nil {
		t.Fatalf("newLinuxJailerStagingFilesystem() error = %v, want nil", err)
	}
	runtimeRoot := filepath.Dir(request.Authority.JailRootHostPath)
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatalf("Mkdir(collision): %v", err)
	}
	sentinel := filepath.Join(runtimeRoot, "unowned")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("WriteFile(sentinel): %v", err)
	}

	_, err = stageStrictJailerResources(filesystem, request)
	if !errors.Is(err, errJailerStagingFailed) {
		t.Fatalf("stage error = %v, want staging failure", err)
	}
	if data, readErr := os.ReadFile(sentinel); readErr != nil || string(data) != "preserve" {
		t.Fatalf("unowned collision changed: data=%q error=%v", data, readErr)
	}
	assertJailerStagingErrorRedacted(t, err)
}

func TestLinuxJailerStagerRejectsDescendantSymlinks(t *testing.T) {
	request, _ := newLinuxJailerStagingRequest(t)
	filesystem, err := newLinuxJailerStagingFilesystem(request.Authority)
	if err != nil {
		t.Fatalf("newLinuxJailerStagingFilesystem() error = %v, want nil", err)
	}
	root, err := filesystem.createExclusiveRoot(jailerStagingRootRequest{
		HostRoot: request.Authority.JailRootHostPath,
		Mode:     request.Authority.DirectoryMode,
		UID:      request.Authority.UID,
		GID:      request.Authority.GID,
	})
	if err != nil {
		t.Fatalf("createExclusiveRoot() error = %v, want nil", err)
	}
	defer func() {
		_ = root.removeOwned()
		_ = root.close()
	}()

	outside := t.TempDir()
	parentLink := filepath.Join(request.Authority.JailRootHostPath, "parent-link")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Fatalf("Symlink(parent): %v", err)
	}
	if _, err := root.createFileExclusive(filepath.Join("parent-link", "payload")); !errors.Is(err, errJailerStagingFailed) {
		t.Fatalf("create through symlink parent error = %v, want staging failure", err)
	}

	outFile := filepath.Join(outside, "outside-file")
	if err := os.WriteFile(outFile, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside): %v", err)
	}
	destinationLink := filepath.Join(request.Authority.JailRootHostPath, "destination")
	if err := os.Symlink(outFile, destinationLink); err != nil {
		t.Fatalf("Symlink(destination): %v", err)
	}
	if _, err := root.createFileExclusive("destination"); !errors.Is(err, errJailerStagingFailed) {
		t.Fatalf("create at symlink destination error = %v, want staging failure", err)
	}
	if data, err := os.ReadFile(outFile); err != nil || string(data) != "preserve" {
		t.Fatalf("outside destination changed: data=%q error=%v", data, err)
	}
}

func TestLinuxJailerStagingLeaseDetectsReplacementAndFailsCleanupClosed(t *testing.T) {
	for _, tt := range []struct {
		name    string
		replace func(*testing.T, jailerStagingRequest, jailerStagingResult)
		check   func(*testing.T, jailerStagingRequest)
		restore func(*testing.T, jailerStagingRequest)
	}{
		{
			name: "staged file",
			replace: func(t *testing.T, request jailerStagingRequest, result jailerStagingResult) {
				t.Helper()
				kernel := result.pathCorrelations()[0].hostPath
				if err := os.Rename(kernel, kernel+".owned"); err != nil {
					t.Fatalf("Rename(kernel): %v", err)
				}
				if err := os.WriteFile(kernel, []byte("replacement"), 0o400); err != nil {
					t.Fatalf("WriteFile(replacement): %v", err)
				}
			},
			check: func(t *testing.T, request jailerStagingRequest) {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(request.Authority.JailRootHostPath, "boot", "vmlinux"))
				if err != nil || string(data) != "replacement" {
					t.Fatalf("replacement file was removed: data=%q error=%v", data, err)
				}
			},
			restore: func(t *testing.T, request jailerStagingRequest) {
				t.Helper()
				kernel := filepath.Join(request.Authority.JailRootHostPath, "boot", "vmlinux")
				if err := os.Remove(kernel); err != nil {
					t.Fatalf("Remove(replacement kernel): %v", err)
				}
				if err := os.Rename(kernel+".owned", kernel); err != nil {
					t.Fatalf("Restore(kernel): %v", err)
				}
			},
		},
		{
			name: "root generation",
			replace: func(t *testing.T, request jailerStagingRequest, _ jailerStagingResult) {
				t.Helper()
				root := request.Authority.JailRootHostPath
				if err := os.Rename(root, root+".owned"); err != nil {
					t.Fatalf("Rename(root): %v", err)
				}
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatalf("Mkdir(replacement root): %v", err)
				}
			},
			check: func(t *testing.T, request jailerStagingRequest) {
				t.Helper()
				if info, err := os.Stat(request.Authority.JailRootHostPath); err != nil || !info.IsDir() {
					t.Fatalf("replacement root was removed: info=%v error=%v", info, err)
				}
			},
			restore: func(t *testing.T, request jailerStagingRequest) {
				t.Helper()
				root := request.Authority.JailRootHostPath
				if err := os.Remove(root); err != nil {
					t.Fatalf("Remove(replacement root): %v", err)
				}
				if err := os.Rename(root+".owned", root); err != nil {
					t.Fatalf("Restore(root): %v", err)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request, _ := newLinuxJailerStagingRequest(t)
			filesystem, err := newLinuxJailerStagingFilesystem(request.Authority)
			if err != nil {
				t.Fatalf("newLinuxJailerStagingFilesystem() error = %v, want nil", err)
			}
			result, err := stageStrictJailerResources(filesystem, request)
			if err != nil {
				t.Fatalf("stageStrictJailerResources() error = %v, want nil", err)
			}
			tt.replace(t, request, result)

			if err := result.verifyOwnedRoot(); !errors.Is(err, errJailerStagingFailed) {
				t.Fatalf("verify replaced root error = %v, want staging failure", err)
			} else {
				assertJailerStagingErrorRedacted(t, err)
			}
			first := result.releaseOwnedRoot()
			if !errors.Is(first, errJailerStagingCleanupIncomplete) {
				t.Fatalf("release replaced root error = %v, want cleanup incomplete", first)
			}
			tt.check(t, request)
			tt.restore(t, request)
			if second := result.releaseOwnedRoot(); second != nil {
				t.Fatalf("release retry after restoring exact identity = %v, want nil", second)
			}
			if third := result.releaseOwnedRoot(); third != nil {
				t.Fatalf("terminal idempotent release = %v, want nil", third)
			}
			assertJailerStagingErrorRedacted(t, first)
		})
	}
}

func TestLinuxJailerStagerCleansPartialGenerationAfterMeasurementFailure(t *testing.T) {
	request, _ := newLinuxJailerStagingRequest(t)
	request.Config.SHA256 = strings.Repeat("0", 64)
	filesystem, err := newLinuxJailerStagingFilesystem(request.Authority)
	if err != nil {
		t.Fatalf("newLinuxJailerStagingFilesystem() error = %v, want nil", err)
	}

	_, err = stageStrictJailerResources(filesystem, request)
	if !errors.Is(err, errJailerStagingFailed) {
		t.Fatalf("stage error = %v, want staging failure", err)
	}
	if _, statErr := os.Lstat(filepath.Dir(request.Authority.JailRootHostPath)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial runtime generation remains: %v", statErr)
	}
	assertJailerStagingErrorRedacted(t, err)
}

func newLinuxJailerStagingRequest(t *testing.T) (jailerStagingRequest, string) {
	t.Helper()
	request, common := newLinuxJailerStagingRequestWithoutCommon(t)
	if err := os.Mkdir(common, 0o700); err != nil {
		t.Fatalf("Mkdir(common): %v", err)
	}
	if err := os.Chmod(common, 0o700); err != nil {
		t.Fatalf("Chmod(common): %v", err)
	}
	return request, common
}

func newLinuxJailerStagingRequestWithoutCommon(t *testing.T) (jailerStagingRequest, string) {
	t.Helper()
	chrootBase := filepath.Join(t.TempDir(), "chroot")
	if err := os.Mkdir(chrootBase, 0o700); err != nil {
		t.Fatalf("Mkdir(chroot base): %v", err)
	}
	request := validJailerStagingRequest()
	request.Authority.ChrootBaseDir = chrootBase
	request.Authority.CanonicalFirecrackerPath = "/opt/hal/bin/firecracker"
	common := filepath.Join(chrootBase, filepath.Base(request.Authority.CanonicalFirecrackerPath))
	request.Authority.JailRootHostPath = filepath.Join(common, request.Authority.RuntimeID, "root")
	request.Authority.UID = uint32(os.Geteuid())
	request.Authority.GID = uint32(os.Getegid())
	if request.Authority.UID == 0 || request.Authority.GID == 0 {
		request.Authority.UID = 65534
		request.Authority.GID = 65534
	}
	return request, common
}

func assertLinuxJailerPathMetadata(t *testing.T, path string, uid, gid, mode uint32, directory bool) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatalf("Lstat(%q): %v", path, err)
	}
	wantType := uint32(unix.S_IFREG)
	if directory {
		wantType = unix.S_IFDIR
	}
	if stat.Mode&unix.S_IFMT != wantType || stat.Mode&0o777 != mode || stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("metadata for %q = type %#o mode %#o uid %d gid %d, want type %#o mode %#o uid %d gid %d",
			path, stat.Mode&unix.S_IFMT, stat.Mode&0o777, stat.Uid, stat.Gid, wantType, mode, uid, gid)
	}
}
