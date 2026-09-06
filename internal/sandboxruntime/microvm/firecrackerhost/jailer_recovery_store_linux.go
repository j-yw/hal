//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// This is an extension of the existing locked record store, not a recovered
// authority constructor. The continuously retained record FD and in-memory
// reservation pointer must survive. A new owner never reopens a busy record.
type jailerRecoveryStore struct {
	mu                          sync.Mutex
	config                      jailerRecoverySupervisorConfig
	file                        *os.File
	record                      firecrackerRuntimeOwnerRecordV1
	reservation                 *strictJailerIdentityLease
	busy                        *jailerIdentityRecord
	terminal, poisoned, retired bool
}

func (store *l8RuntimeOwnerLinuxRecordStore) readRecord() (firecrackerRuntimeOwnerRecordV1, bool, error) {
	if store.selected == nil {
		return readL8RuntimeOwnerRecordAt(store.directoryFD, store.seed, store.bootID)
	}
	selected := store.selected
	if selected.poisoned || selected.retired {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	file, err := openJailerRecoveryRecordFile(store.directoryFD)
	if errors.Is(err, unix.ENOENT) && selected.file == nil {
		return firecrackerRuntimeOwnerRecordV1{}, false, nil
	}
	if err != nil {
		selected.poisoned = true
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	defer file.Close()
	if selected.file == nil || !sameJailerRecoveryFile(file, selected.file) {
		selected.poisoned = true
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	record, busy, terminal, err := readJailerRecoveryRecordFile(file, selected.config)
	if err != nil || record != selected.record || !equalJailerRecoveryBusy(busy, selected.busy) || terminal != selected.terminal || record.HostBootID != store.bootID {
		selected.poisoned = true
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	return record, true, nil
}

// Called under the existing store lock after exact record validation. A failed
// unlink/sync/readback remains uncertain. Once committed, later handle closure
// cannot rewrite the directory or affect a successor record.
func (store *l8RuntimeOwnerLinuxRecordStore) retireSelectedRecord() error {
	s := store.selected
	if s == nil || s.file == nil || s.poisoned || s.retired {
		return errL8RuntimeOwnerInvalid
	}
	if unix.Unlinkat(store.directoryFD, l8RuntimeOwnerRecordName, 0) != nil || unix.Fsync(store.directoryFD) != nil {
		s.poisoned = true
		return errL8RuntimeOwnerInvalid
	}
	var stat unix.Stat_t
	if !errors.Is(unix.Fstatat(store.directoryFD, l8RuntimeOwnerRecordName, &stat, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) || unix.Fstat(int(s.file.Fd()), &stat) != nil || stat.Nlink != 0 {
		s.poisoned = true
		return errL8RuntimeOwnerInvalid
	}
	s.retired = true
	file := s.file
	s.file = nil
	if file.Close() != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (store *l8RuntimeOwnerLinuxRecordStore) writeRecord(record firecrackerRuntimeOwnerRecordV1) error {
	if store.selected == nil {
		return writeL8RuntimeOwnerRecordAt(store.directoryFD, record, store.seed, store.bootID)
	}
	return store.writeSelectedRecord(record, store.selected.busy, store.selected.terminal)
}

func (store *l8RuntimeOwnerLinuxRecordStore) writeSelectedRecord(record firecrackerRuntimeOwnerRecordV1, busy *jailerIdentityRecord, terminal bool) error {
	s := store.selected
	if s == nil || s.poisoned || s.retired || record.HostBootID != store.bootID {
		return errL8RuntimeOwnerInvalid
	}
	payload, err := encodeJailerRecoveryRecord(record, s.config, busy, terminal)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	name := ".runtime-owner-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(store.directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "jailer-owner-record-update")
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
		_ = unix.Unlinkat(store.directoryFD, name, 0)
	}()
	// Once IO starts, a failure poisons this owner. Readback of a rename after a
	// failed sync cannot promote uncertain state into launch/idle authority.
	if unix.Fchmod(fd, 0o600) != nil || writeL8RuntimeOwnerRecordPayload(fd, payload) != nil || unix.Fsync(fd) != nil {
		s.poisoned = true
		return errL8RuntimeOwnerInvalid
	}
	if s.file != nil {
		if _, present, err := store.readRecord(); err != nil || !present {
			s.poisoned = true
			return errL8RuntimeOwnerInvalid
		}
		err = unix.Renameat(store.directoryFD, name, store.directoryFD, l8RuntimeOwnerRecordName)
	} else {
		err = unix.Renameat2(store.directoryFD, name, store.directoryFD, l8RuntimeOwnerRecordName, unix.RENAME_NOREPLACE)
	}
	if err != nil || unix.Fsync(store.directoryFD) != nil {
		s.poisoned = true
		return errL8RuntimeOwnerInvalid
	}
	current, err := openJailerRecoveryRecordFile(store.directoryFD)
	if err != nil {
		s.poisoned = true
		return errL8RuntimeOwnerInvalid
	}
	defer current.Close()
	got, gotBusy, gotTerminal, readErr := readJailerRecoveryRecordFile(current, s.config)
	if readErr != nil || !sameJailerRecoveryFile(current, file) || got != record || !equalJailerRecoveryBusy(gotBusy, busy) || gotTerminal != terminal {
		s.poisoned = true
		return errL8RuntimeOwnerInvalid
	}
	old := s.file
	s.file = file
	s.record = record
	s.busy = gotBusy
	s.terminal = terminal
	keep = true
	if old != nil && old.Close() != nil {
		s.poisoned = true
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (store *l8RuntimeOwnerLinuxRecordStore) recoveryAuthority() *jailerRecoveryAuthority {
	return &jailerRecoveryAuthority{
		current: func(ctx context.Context, runtimeID, digest string) error {
			record, err := store.Load(ctx)
			if err != nil || store.selected == nil || record.Revision != 0 || record.State != "starting" || record.RuntimeID != runtimeID || store.selected.config.Config.SHA256 != digest {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		busy: func(ctx context.Context, lease *strictJailerIdentityLease) error {
			return store.checkpoint(ctx, lease, false)
		},
		terminal: func(ctx context.Context, lease *strictJailerIdentityLease) error {
			return store.checkpoint(ctx, lease, true)
		},
	}
}

// The original lease remembers its successful durable idle/readback commit.
// Do not re-open its journal: another job may already own that prepared slot.
func (store *l8RuntimeOwnerLinuxRecordStore) confirmTerminalCleanup(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errL8RuntimeOwnerInvalid
	}
	_, _, err := store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		if store.selected == nil {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		record, present, err := store.readRecord()
		s := store.selected
		if err != nil || !present || !s.terminal || s.reservation == nil || s.busy == nil {
			return record, false, errL8RuntimeOwnerInvalid
		}
		lease := s.reservation
		lease.mu.Lock()
		defer lease.mu.Unlock()
		if ctx.Err() != nil || !equalJailerRecoveryBusy(&lease.busy, s.busy) || lease.poisoned || !lease.idleCommitted || !lease.released || !lease.closed || lease.closeErr != nil {
			return record, false, errL8RuntimeOwnerInvalid
		}
		return record, true, nil
	})
	return err
}

func (store *l8RuntimeOwnerLinuxRecordStore) checkpoint(ctx context.Context, lease *strictJailerIdentityLease, terminal bool) error {
	if lease == nil {
		return errL8RuntimeOwnerInvalid
	}
	_, _, err := store.withLock(ctx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		s := store.selected
		if s == nil || s.poisoned || s.retired {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		// Terminal retries after idle are handle-local. Never re-read or affect
		// a successor's identity slot through an old authority.
		if terminal && s.terminal && s.reservation == lease {
			return s.record, true, nil
		}
		record, present, err := store.readRecord()
		if err != nil || !present {
			return record, false, errL8RuntimeOwnerInvalid
		}
		lease.mu.Lock()
		if lease.verifyLocked(ctx) != nil {
			lease.mu.Unlock()
			return record, false, errL8RuntimeOwnerInvalid
		}
		busy := lease.busy
		lease.mu.Unlock()
		if terminal {
			if s.reservation != lease || !equalJailerRecoveryBusy(s.busy, &busy) {
				return record, false, errL8RuntimeOwnerInvalid
			}
		} else if s.reservation != nil || s.busy != nil || record.Revision != 0 {
			return record, false, errL8RuntimeOwnerInvalid
		}
		if err := store.writeSelectedRecord(record, &busy, terminal); err != nil {
			return record, false, errL8RuntimeOwnerInvalid
		}
		s.reservation = lease
		return record, true, nil
	})
	return err
}

func openJailerRecoveryRecordFile(directoryFD int) (*os.File, error) {
	fd, err := unix.Openat(directoryFD, l8RuntimeOwnerRecordName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "jailer-owner-current-record")
	if !validL8RuntimeOwnerPrivateFile(fd) {
		_ = file.Close()
		return nil, errL8RuntimeOwnerInvalid
	}
	return file, nil
}

func sameJailerRecoveryFile(left, right *os.File) bool {
	if left == nil || right == nil {
		return false
	}
	l, le := left.Stat()
	r, re := right.Stat()
	return le == nil && re == nil && os.SameFile(l, r)
}

func readJailerRecoveryRecordFile(file *os.File, config jailerRecoverySupervisorConfig) (firecrackerRuntimeOwnerRecordV1, *jailerIdentityRecord, bool, error) {
	payload, err := io.ReadAll(io.NewSectionReader(file, 0, l8RuntimeOwnerRecordLimit+1))
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
	}
	return decodeJailerRecoveryRecord(payload, config)
}

func equalJailerRecoveryBusy(left, right *jailerIdentityRecord) bool {
	if left == nil || right == nil {
		return left == right
	}
	return bytes.Equal(left.payload(), right.payload())
}
