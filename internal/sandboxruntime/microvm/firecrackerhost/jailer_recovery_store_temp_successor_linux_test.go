//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Real selected-store IO in an ordinary same-UID private directory. These
// filesystem interleavings prove neither root ownership nor live VM authority.
func newJailerRecoveryPublicationFixture(t *testing.T) (*l8RuntimeOwnerLinuxRecordStore, firecrackerRuntimeOwnerRecordV1) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	record, config := jailerRecoveryTestRecord(t)
	store := &l8RuntimeOwnerLinuxRecordStore{directoryFD: int(directory.Fd()), bootID: record.HostBootID, selected: &jailerRecoveryStore{config: config}}
	t.Cleanup(func() {
		if store.selected.file != nil {
			_ = store.selected.file.Close()
		}
		_ = directory.Close()
	})
	return store, record
}

func jailerRecoveryPublicationCanary(t *testing.T, directoryFD int, name string) *os.File {
	t.Helper()
	fd, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "private-publication-canary")
	t.Cleanup(func() { _ = file.Close() })
	if n, err := file.Write([]byte("unrelated successor bytes\n")); err != nil || n != 26 {
		t.Fatal("canary write failed")
	}
	return file
}

func assertJailerRecoveryPublicationCanary(t *testing.T, directoryFD int, name string, expected unix.Stat_t, file *os.File) {
	t.Helper()
	payload, err := io.ReadAll(io.NewSectionReader(file, 0, 64))
	if err != nil || !bytes.Equal(payload, []byte("unrelated successor bytes\n")) {
		t.Fatal("unrelated retained canary bytes changed")
	}
	var current unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != expected.Dev || current.Ino != expected.Ino || current.Mode != expected.Mode {
		t.Fatalf("unowned successor entry was removed or replaced: %v", err)
	}
}

func TestJailerRecoveryStorePublicationPreservesConsumedTemporarySuccessor(t *testing.T) {
	for _, mode := range []string{"genesis-noreplace", "existing-record-rename"} {
		for _, outcome := range []string{"success", "directory-sync-error", "readback-error"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				store, record := newJailerRecoveryPublicationFixture(t)
				ctx := context.Background()
				replacing := mode == "existing-record-rename"
				if replacing {
					if _, err := store.CreateGenesis(ctx, record); err != nil {
						t.Fatal(err)
					}
				}
				var canary *os.File
				var source string
				var expected unix.Stat_t
				renames, syncs := 0, 0
				store.selected.publication = &jailerRecoveryRecordPublicationOps{
					rename: func(fd int, name string, replaceExisting bool) error {
						renames++
						if fd != store.directoryFD || replaceExisting != replacing {
							t.Fatal("changed publication destination or no-replace selection")
						}
						if err := renameJailerRecoveryRecord(fd, name, replaceExisting); err != nil {
							t.Fatal(err)
						}
						if err := unix.Fstatat(fd, name, &expected, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
							t.Fatal("actual rename did not consume the temporary name")
						}
						source = name
						canary = jailerRecoveryPublicationCanary(t, fd, name)
						if unix.Fstat(int(canary.Fd()), &expected) != nil {
							t.Fatal("stat successor")
						}
						if outcome == "readback-error" {
							current, err := unix.Openat(fd, l8RuntimeOwnerRecordName, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
							if err != nil {
								t.Fatal(err)
							}
							n, writeErr := unix.Pwrite(current, []byte("!"), 0)
							closeErr := unix.Close(current)
							if n != 1 || writeErr != nil || closeErr != nil {
								t.Fatal("could not exercise actual corrupt readback")
							}
						}
						return nil
					},
					syncDirectory: func(fd int) error {
						syncs++
						if outcome == "directory-sync-error" {
							return unix.EIO
						}
						return unix.Fsync(fd)
					},
				}
				var err error
				if replacing {
					_, _, err = store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
						err := store.writeSelectedRecord(record, nil, false)
						return record, err == nil, err
					})
				} else {
					_, err = store.CreateGenesis(ctx, record)
				}
				if renames != 1 || syncs != 1 || canary == nil {
					t.Fatal("real publication/final sync boundary not reached exactly once")
				}
				loaded, loadErr := store.Load(ctx)
				if outcome == "success" {
					if err != nil || loadErr != nil || loaded != record || store.selected.poisoned {
						t.Fatal("canonical publication did not succeed")
					}
				} else if err == nil || loadErr == nil || !store.selected.poisoned {
					t.Fatal("post-rename failure became accepted record authority")
				}
				t.Logf("actual rename completed; publication accepted=%t poisoned=%t", err == nil, store.selected.poisoned)
				assertJailerRecoveryPublicationCanary(t, store.directoryFD, source, expected, canary)
			})
		}
	}
}

func TestJailerRecoveryStorePublicationUnpublishedCleanupPreservesOwnership(t *testing.T) {
	for _, outcome := range []string{"owned-temporary", "noreplace-conflict", "replaced-regular", "replaced-symlink"} {
		t.Run(outcome, func(t *testing.T) {
			store, record := newJailerRecoveryPublicationFixture(t)
			var source, canaryName string
			var canary *os.File
			var expected unix.Stat_t
			renames, syncs := 0, 0
			store.selected.publication = &jailerRecoveryRecordPublicationOps{
				rename: func(fd int, name string, replaceExisting bool) error {
					renames++
					if fd != store.directoryFD || replaceExisting {
						t.Fatal("changed genesis publication")
					}
					source = name
					if outcome == "owned-temporary" {
						return unix.EIO
					}
					if outcome == "noreplace-conflict" {
						canaryName = l8RuntimeOwnerRecordName
						canary = jailerRecoveryPublicationCanary(t, fd, canaryName)
					} else {
						// Preserve the original retained inode elsewhere, and put an
						// unrelated entry at its former still-unpublished name.
						if err := unix.Renameat(fd, name, fd, name+"-retained"); err != nil {
							t.Fatal(err)
						}
						canaryName = name
						if outcome == "replaced-regular" {
							canary = jailerRecoveryPublicationCanary(t, fd, name)
						} else {
							canary = jailerRecoveryPublicationCanary(t, fd, "foreign-target")
							if err := unix.Symlinkat("foreign-target", fd, name); err != nil {
								t.Fatal(err)
							}
						}
					}
					if unix.Fstatat(fd, canaryName, &expected, unix.AT_SYMLINK_NOFOLLOW) != nil {
						t.Fatal("stat unowned entry")
					}
					if outcome == "noreplace-conflict" {
						err := renameJailerRecoveryRecord(fd, name, false)
						if err != unix.EEXIST {
							t.Fatalf("actual no-replace conflict = %v", err)
						}
						return err
					}
					return unix.EIO
				},
				syncDirectory: func(int) error { syncs++; return unix.EIO },
			}
			_, err := store.CreateGenesis(context.Background(), record)
			if err == nil || !store.selected.poisoned || store.selected.file != nil || renames != 1 || syncs != 0 {
				t.Fatal("unpublished failure did not retain uncertain state")
			}
			if outcome == "owned-temporary" || outcome == "noreplace-conflict" {
				var stat unix.Stat_t
				if err := unix.Fstatat(store.directoryFD, source, &stat, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
					t.Fatal("owned unpublished temporary not cleaned")
				}
			}
			if canary != nil {
				assertJailerRecoveryPublicationCanary(t, store.directoryFD, canaryName, expected, canary)
			}
		})
	}
}

func TestJailerRecoveryStorePublicationDefaultsAndIncompleteOperations(t *testing.T) {
	for _, mode := range []string{"nil-defaults", "empty", "rename-only", "sync-only"} {
		t.Run(mode, func(t *testing.T) {
			store, record := newJailerRecoveryPublicationFixture(t)
			calls := 0
			if mode != "nil-defaults" {
				store.selected.publication = &jailerRecoveryRecordPublicationOps{}
				if mode == "rename-only" {
					store.selected.publication.rename = func(int, string, bool) error { calls++; return unix.EIO }
				}
				if mode == "sync-only" {
					store.selected.publication.syncDirectory = func(int) error { calls++; return unix.EIO }
				}
			}
			_, err := store.CreateGenesis(context.Background(), record)
			if mode == "nil-defaults" {
				got, loadErr := store.Load(context.Background())
				if err != nil || loadErr != nil || got != record {
					t.Fatal("nil publication options changed existing selected store behavior")
				}
				return
			}
			if err == nil || calls != 0 || store.selected.file != nil {
				t.Fatal("incomplete operation set did not fail before IO")
			}
			fd, openErr := unix.Openat(store.directoryFD, ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
			if openErr != nil {
				t.Fatal(openErr)
			}
			directory := os.NewFile(uintptr(fd), "publication-empty-directory")
			entries, readErr := directory.Readdirnames(1)
			closeErr := directory.Close()
			if len(entries) != 0 || readErr != io.EOF || closeErr != nil {
				t.Fatal("incomplete publication operations mutated the directory")
			}
		})
	}
}
