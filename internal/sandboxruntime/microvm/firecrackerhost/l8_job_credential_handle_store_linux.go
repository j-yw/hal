//go:build linux

package firecrackerhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"golang.org/x/sys/unix"
)

type l8JobCredentialLinuxHandleStore struct {
	directoryFD int
}

func openL8JobCredentialHandleStore(directory string) (l8JobCredentialHandleStore, error) {
	directoryFD, err := openL8RuntimeOwnerDirectory(directory)
	if err != nil {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	return &l8JobCredentialLinuxHandleStore{directoryFD: directoryFD}, nil
}

func (store *l8JobCredentialLinuxHandleStore) Save(ctx context.Context, record l8JobCredentialHandleRecordV1) error {
	if store == nil || store.directoryFD < 0 || l8JobCredentialRuntimeValueIsNil(ctx) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	if ctx.Err() != nil {
		return ErrL8JobCredentialRuntimeUnavailable
	}
	payload, err := encodeL8JobCredentialHandleRecord(record)
	if err != nil {
		return err
	}
	digest, err := l8JobCredentialHandleDigestFromRecord(record)
	if err != nil {
		return err
	}
	name := l8JobCredentialHandleRecordName(digest)
	if unix.Flock(store.directoryFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	defer unix.Flock(store.directoryFD, unix.LOCK_UN)
	return writeL8JobCredentialHandleRecordAt(store.directoryFD, name, payload)
}

func (store *l8JobCredentialLinuxHandleStore) Load(ctx context.Context, identity sandboxruntime.JobCredentialIdentity) (l8JobCredentialHandleRecordV1, bool, error) {
	if store == nil || store.directoryFD < 0 || l8JobCredentialRuntimeValueIsNil(ctx) {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeInvalid
	}
	if ctx.Err() != nil {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeUnavailable
	}
	digest, err := sandboxruntime.JobCredentialIdentityDigest(identity)
	if err != nil {
		return l8JobCredentialHandleRecordV1{}, false, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	name := l8JobCredentialHandleRecordName(digest)
	if unix.Flock(store.directoryFD, unix.LOCK_SH|unix.LOCK_NB) != nil {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeInvalid
	}
	defer unix.Flock(store.directoryFD, unix.LOCK_UN)
	record, present, err := readL8JobCredentialHandleRecordAt(store.directoryFD, name)
	if err != nil || !present {
		return record, present, err
	}
	if err := bindL8JobCredentialHandleRecord(record, identity); err != nil {
		return l8JobCredentialHandleRecordV1{}, false, err
	}
	return record, true, nil
}

func writeL8JobCredentialHandleRecordAt(directoryFD int, name string, payload []byte) error {
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	temporary := ".job-credential-handle-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(directoryFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	removeTemporary := true
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if removeTemporary {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	if unix.Fchmod(fd, 0o600) != nil || writeL8RuntimeOwnerRecordPayload(fd, payload) != nil || unix.Fsync(fd) != nil || unix.Close(fd) != nil {
		fd = -1
		return ErrL8JobCredentialRuntimeInvalid
	}
	fd = -1
	if unix.Renameat(directoryFD, temporary, directoryFD, name) != nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	removeTemporary = false
	if unix.Fsync(directoryFD) != nil {
		return ErrL8JobCredentialRuntimeInvalid
	}
	return nil
}

func readL8JobCredentialHandleRecordAt(directoryFD int, name string) (l8JobCredentialHandleRecordV1, bool, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return l8JobCredentialHandleRecordV1{}, false, nil
	}
	if err != nil {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeInvalid
	}
	file := os.NewFile(uintptr(fd), "job-credential-handle-record")
	if file == nil {
		_ = unix.Close(fd)
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeInvalid
	}
	defer file.Close()
	if !validL8RuntimeOwnerPrivateFile(fd) {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file, l8JobCredentialHandleRecordLimit+1))
	if err != nil || len(payload) > l8JobCredentialHandleRecordLimit {
		return l8JobCredentialHandleRecordV1{}, false, ErrL8JobCredentialRuntimeInvalid
	}
	record, err := decodeL8JobCredentialHandleRecord(payload)
	if err != nil {
		return l8JobCredentialHandleRecordV1{}, false, err
	}
	return record, true, nil
}

func (*l8JobCredentialLinuxHandleStore) String() string {
	return l8JobCredentialHandleStoreValuePlaceholder
}
func (*l8JobCredentialLinuxHandleStore) GoString() string {
	return l8JobCredentialHandleStoreValuePlaceholder
}
func (*l8JobCredentialLinuxHandleStore) Format(state fmt.State, verb rune) {
	redactL8JobCredentialHandleStore(state, verb)
}
func (*l8JobCredentialLinuxHandleStore) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*l8JobCredentialLinuxHandleStore) MarshalText() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
func (*l8JobCredentialLinuxHandleStore) MarshalBinary() ([]byte, error) {
	return nil, ErrL8JobCredentialRuntimeSerialization
}
