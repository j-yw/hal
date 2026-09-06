//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These checks admit the real fixture owner's files, not root-owned host
// authority. Only the shared /tmp ancestor's writable mode is exempted.
func ordinaryJailerIdentityChecks(t *testing.T) linuxJailerIdentityChecks {
	t.Helper()
	var temp unix.Stat_t
	if err := unix.Stat("/tmp", &temp); err != nil {
		t.Fatal(err)
	}
	return linuxJailerIdentityChecks{
		directory: func(stat unix.Stat_t, final bool) bool {
			owner := stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())
			sharedTemp := stat.Dev == temp.Dev && stat.Ino == temp.Ino
			return owner && (stat.Mode&0o022 == 0 || sharedTemp) && (!final || stat.Mode&0o7777 == 0o700)
		},
		file: func(stat unix.Stat_t) bool { return stat.Uid == uint32(os.Geteuid()) && stat.Mode&0o7777 == 0o600 },
	}
}

func realJailerIdentityFixture(t *testing.T) (*strictJailerIdentityAuthority, string) {
	t.Helper()
	// Explicit /tmp keeps the observed ancestry stable under callers' TMPDIR.
	parent, err := os.MkdirTemp("/tmp", "hal-jailer-identity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Error(err)
		}
	})
	directory := filepath.Join(parent, "identity")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	slot := strictJailerIdentitySlot{directory: directory, uid: 1001, gid: 1002}
	for name, payload := range map[string][]byte{jailerIdentityLockName: {}, jailerIdentityJournalName: idleJailerIdentityRecord(slot).payload()} {
		if err := os.WriteFile(filepath.Join(directory, name), payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checks := ordinaryJailerIdentityChecks(t)
	return &strictJailerIdentityAuthority{slot: slot, open: func(path string) (strictJailerIdentityFilesystem, error) {
		return openLinuxJailerIdentityFilesystemWithChecks(path, checks)
	}}, directory
}

func TestJailerIdentityLinuxRealChecksRefuseOrdinaryFixture(t *testing.T) {
	authority, directory := realJailerIdentityFixture(t)
	before, err := os.ReadFile(filepath.Join(directory, jailerIdentityJournalName))
	if err != nil {
		t.Fatal(err)
	}
	production := newStrictJailerIdentityAuthority(authority.slot)
	if lease, err := production.reserve(context.Background(), "run-1", strings.Repeat("a", 64), 1001, 1002); err == nil || lease != nil {
		t.Fatal("ordinary user/writable-ancestor fixture accepted as prepared root-owned authority")
	}
	after, err := os.ReadFile(filepath.Join(directory, jailerIdentityJournalName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal modified prepared journal")
	}
}

func TestJailerIdentityLinuxKernelLockContentionAcrossAuthorityInstances(t *testing.T) {
	authority, directory := realJailerIdentityFixture(t)
	first := reserveTestJailerIdentity(t, authority)
	second, err := authority.open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.close() })
	if err := second.lock(); err == nil {
		t.Fatal("independently opened file description bypassed kernel exclusive lock")
	}
	if err := second.close(); err != nil {
		t.Fatal(err)
	}
	if err := first.verify(context.Background()); err != nil {
		t.Fatal("contender closed another open description's lock", err)
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	// Kernel lock is now free, but the durable busy record remains quarantined.
	if lease, err := authority.reserve(context.Background(), "run-2", strings.Repeat("b", 64), 1001, 1002); err == nil || lease != nil {
		t.Fatal("busy journal automatically reclaimed after lock release")
	}
}

func TestJailerIdentityLinuxReleasePreservesInodesAndNewOwner(t *testing.T) {
	authority, directory := realJailerIdentityFixture(t)
	stat := func(name string) unix.Stat_t {
		t.Helper()
		var s unix.Stat_t
		if err := unix.Lstat(filepath.Join(directory, name), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	lockBefore, journalBefore := stat(jailerIdentityLockName), stat(jailerIdentityJournalName)
	lease := reserveTestJailerIdentity(t, authority)
	fs := lease.fs.(*linuxJailerIdentityFilesystem)
	for _, node := range append(append([]linuxJailerIdentityNode{}, fs.chain...), fs.lockNode, fs.journal) {
		flags, err := unix.FcntlInt(uintptr(node.fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("identity descriptor could reach guest")
		}
	}
	if err := lease.release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sameLinuxJailerIdentityStat(lockBefore, stat(jailerIdentityLockName)) || !sameLinuxJailerIdentityStat(journalBefore, stat(jailerIdentityJournalName)) {
		t.Fatal("durable update replaced a prepared inode")
	}
	next := reserveTestJailerIdentity(t, authority)
	if next.busy.Nonce == lease.busy.Nonce {
		t.Fatal("generation nonce reused")
	}
	if lease.close() != nil || lease.release(context.Background()) != nil || next.verify(context.Background()) != nil {
		t.Fatal("stale alias touched current kernel lock or journal")
	}
	if err := next.release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestJailerIdentityLinuxRefusesUnsafePreparedFilesWithoutRepair(t *testing.T) {
	for _, name := range []string{"missing lock", "missing journal", "empty journal", "large journal", "lock symlink", "journal symlink", "lock hardlink", "journal hardlink", "file mode", "directory mode", "lock not empty", "journal fifo"} {
		t.Run(name, func(t *testing.T) {
			authority, directory := realJailerIdentityFixture(t)
			lock, journal := filepath.Join(directory, jailerIdentityLockName), filepath.Join(directory, jailerIdentityJournalName)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "missing lock":
				must(os.Remove(lock))
			case "missing journal":
				must(os.Remove(journal))
			case "empty journal":
				must(os.WriteFile(journal, nil, 0o600))
			case "large journal":
				must(os.WriteFile(journal, bytes.Repeat([]byte("x"), jailerIdentityJournalLimit+1), 0o600))
			case "lock symlink":
				must(os.Rename(lock, lock+".original"))
				must(os.Symlink(lock+".original", lock))
			case "journal symlink":
				must(os.Rename(journal, journal+".original"))
				must(os.Symlink(journal+".original", journal))
			case "lock hardlink":
				must(os.Link(lock, lock+".alias"))
			case "journal hardlink":
				must(os.Link(journal, journal+".alias"))
			case "file mode":
				must(os.Chmod(journal, 0o620))
			case "directory mode":
				must(os.Chmod(directory, 0o720))
			case "lock not empty":
				must(os.WriteFile(lock, []byte("untrusted"), 0o600))
			case "journal fifo":
				must(os.Remove(journal))
				must(unix.Mkfifo(journal, 0o600))
			}
			if lease, err := authority.reserve(context.Background(), "run-1", strings.Repeat("a", 64), 1001, 1002); err == nil || lease != nil {
				if lease != nil {
					_ = lease.close()
				}
				t.Fatal("unsafe fixture admitted")
			}
			if name == "missing journal" {
				if _, err := os.Lstat(journal); !os.IsNotExist(err) {
					t.Fatal("missing journal was initialized")
				}
			}
			if name == "missing lock" {
				if _, err := os.Lstat(lock); !os.IsNotExist(err) {
					t.Fatal("missing lock was initialized")
				}
			}
		})
	}
}

func TestJailerIdentityLinuxReplacementAndSameInodeMutationPoisonLease(t *testing.T) {
	for _, name := range []string{"lock", "journal", "parent", "journal content", "journal mode"} {
		t.Run(name, func(t *testing.T) {
			authority, directory := realJailerIdentityFixture(t)
			lease := reserveTestJailerIdentity(t, authority)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			restore := func() {}
			switch name {
			case "lock", "journal":
				path := filepath.Join(directory, jailerIdentityLockName)
				if name == "journal" {
					path = filepath.Join(directory, jailerIdentityJournalName)
				}
				must(os.Rename(path, path+".old"))
				must(os.WriteFile(path, []byte("replacement"), 0o600))
				restore = func() { must(os.Remove(path)); must(os.Rename(path+".old", path)) }
			case "parent":
				must(os.Rename(directory, directory+".old"))
				must(os.Mkdir(directory, 0o700))
				restore = func() { must(os.Remove(directory)); must(os.Rename(directory+".old", directory)) }
			case "journal content":
				path := filepath.Join(directory, jailerIdentityJournalName)
				must(os.WriteFile(path, idleJailerIdentityRecord(authority.slot).payload(), 0o600))
				restore = func() { must(os.WriteFile(path, lease.busy.payload(), 0o600)) }
			case "journal mode":
				path := filepath.Join(directory, jailerIdentityJournalName)
				must(os.Chmod(path, 0o640))
				restore = func() { must(os.Chmod(path, 0o600)) }
			}
			if lease.verify(context.Background()) == nil {
				t.Fatal("changed authority accepted")
			}
			restore()
			if lease.verify(context.Background()) == nil || lease.release(context.Background()) == nil {
				t.Fatal("restoring pathname erased quarantine")
			}
		})
	}
}

func TestJailerIdentityLinuxPartialOpensDoNotLeakDescriptors(t *testing.T) {
	for _, failure := range []string{"missing journal", "unsafe journal"} {
		t.Run(failure, func(t *testing.T) {
			authority, directory := realJailerIdentityFixture(t)
			journal := filepath.Join(directory, jailerIdentityJournalName)
			var err error
			if failure == "missing journal" {
				err = os.Remove(journal)
			} else {
				err = os.Chmod(journal, 0o620)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := strictJailerOpenFDCount(t)
			for attempt := 0; attempt < 20; attempt++ {
				if fs, err := authority.open(directory); err == nil || fs != nil {
					if fs != nil {
						_ = fs.close()
					}
					t.Fatal("unsafe partial open admitted")
				}
			}
			if after := strictJailerOpenFDCount(t); after > before {
				t.Fatalf("partial-open descriptor leak: before=%d after=%d", before, after)
			}
		})
	}
}
