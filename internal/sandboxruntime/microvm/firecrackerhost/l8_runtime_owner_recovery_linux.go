//go:build linux

package firecrackerhost

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"golang.org/x/sys/unix"
)

func l8RuntimeOwnerPlatformSupported() bool { return true }

func readL8RuntimeOwnerHostBootID() (string, error) {
	fd, err := unix.Open("/proc/sys/kernel/random/boot_id", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "boot-id")
	if file == nil {
		_ = unix.Close(fd)
		return "", errL8RuntimeOwnerInvalid
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errL8RuntimeOwnerInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file, 65))
	value := strings.TrimSuffix(string(payload), "\n")
	if err != nil || len(payload) > 64 || !validL8RuntimeOwnerHostBootID(value) || string(payload) != value+"\n" {
		return "", errL8RuntimeOwnerInvalid
	}
	return value, nil
}

func inspectL8RuntimeOwnerProcess(pid uint32) (l8RuntimeOwnerProcessObservation, error) {
	if pid == 0 || uint64(pid) > uint64(^uint(0)>>1) {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	failed := true
	defer func() {
		if failed {
			_ = unix.Close(pidfd)
		}
	}()
	if !l8RuntimeOwnerProcessAlive(pidfd) {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	procfd, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	defer unix.Close(procfd)
	processfd, err := unix.Openat(procfd, strconv.FormatUint(uint64(pid), 10), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	defer unix.Close(processfd)
	beforeParent, beforeStart, beforeState, err := readL8RuntimeOwnerProcStat(processfd, pid)
	if err != nil || !l8RuntimeOwnerProcessAlive(pidfd) {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	afterParent, afterStart, afterState, err := readL8RuntimeOwnerProcStat(processfd, pid)
	if err != nil || !sameL8RuntimeOwnerProcessIdentity(beforeParent, beforeStart, beforeState, afterParent, afterStart, afterState) ||
		!l8RuntimeOwnerProcessAlive(pidfd) {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	failed = false
	return l8RuntimeOwnerProcessObservation{PID: pid, ParentPID: afterParent, StartTime: afterStart, state: afterState, pidfd: pidfd, pidfdOwned: true}, nil
}

func sameL8RuntimeOwnerProcessIdentity(beforeParent uint32, beforeStart uint64, beforeState byte, afterParent uint32, afterStart uint64, afterState byte) bool {
	return beforeParent == afterParent && beforeStart == afterStart && beforeState != 'Z' && afterState != 'Z'
}

func l8RuntimeOwnerProcessAlive(pidfd int) bool {
	return l8RuntimeOwnerProcessAliveWithPoll(pidfd, unix.Poll)
}

func l8RuntimeOwnerProcessAliveWithPoll(pidfd int, poll func([]unix.PollFd, int) (int, error)) bool {
	if pidfd < 0 || uint64(pidfd) > uint64(^uint32(0)>>1) {
		return false
	}
	if poll == nil {
		return false
	}
	for {
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		ready, err := poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err == nil && ready == 0 && fds[0].Revents == 0
	}
}

func readL8RuntimeOwnerProcStat(processfd int, pid uint32) (uint32, uint64, byte, error) {
	statfd, err := unix.Openat(processfd, "stat", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, 0, 0, errL8RuntimeOwnerInvalid
	}
	statFile := os.NewFile(uintptr(statfd), "process-stat")
	if statFile == nil {
		_ = unix.Close(statfd)
		return 0, 0, 0, errL8RuntimeOwnerInvalid
	}
	payload, readErr := io.ReadAll(io.LimitReader(statFile, 4097))
	closeErr := statFile.Close()
	parent, startTime, state, parseErr := parseL8RuntimeOwnerProcIdentity(payload, pid)
	if readErr != nil || closeErr != nil || len(payload) > 4096 || parseErr != nil {
		return 0, 0, 0, errL8RuntimeOwnerInvalid
	}
	return parent, startTime, state, nil
}

func parseL8RuntimeOwnerProcStat(payload []byte, expectedPID uint32) (uint64, byte, error) {
	_, startTime, state, err := parseL8RuntimeOwnerProcIdentity(payload, expectedPID)
	return startTime, state, err
}

func writeL8RuntimeOwnerRecord(directory string, record firecrackerRuntimeOwnerRecordV1, seed sandboxruntime.JobCredentialIdentitySeed, currentBootID string) error {
	payload, err := encodeFirecrackerRuntimeOwnerRecordV1(record, seed, currentBootID)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	directoryFD, err := openL8RuntimeOwnerDirectory(directory)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	defer unix.Close(directoryFD)
	if unix.Flock(directoryFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errL8RuntimeOwnerInvalid
	}
	defer unix.Flock(directoryFD, unix.LOCK_UN)
	existing, exists, err := readL8RuntimeOwnerRecordAt(directoryFD, seed, currentBootID)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if exists {
		if existing == record {
			if unix.Fsync(directoryFD) != nil {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		}
		if existing.Revision == ^uint64(0) || record.Revision != existing.Revision+1 {
			return errL8RuntimeOwnerInvalid
		}
	} else if record.Revision != 0 || record.State != "starting" || record.FirecrackerPID != 0 || record.FirecrackerStartTime != 0 {
		return errL8RuntimeOwnerInvalid
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	temporary := ".runtime-owner-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(directoryFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	removeTemporary := true
	defer func() {
		_ = unix.Close(fd)
		if removeTemporary {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	if unix.Fchmod(fd, 0o600) != nil || writeL8RuntimeOwnerRecordPayload(fd, payload) != nil || unix.Fsync(fd) != nil || unix.Close(fd) != nil {
		fd = -1
		return errL8RuntimeOwnerInvalid
	}
	fd = -1
	if unix.Renameat(directoryFD, temporary, directoryFD, l8RuntimeOwnerRecordName) != nil {
		return errL8RuntimeOwnerInvalid
	}
	removeTemporary = false
	if unix.Fsync(directoryFD) != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func readL8RuntimeOwnerRecord(directory string, seed sandboxruntime.JobCredentialIdentitySeed, currentBootID string) (firecrackerRuntimeOwnerRecordV1, error) {
	directoryFD, err := openL8RuntimeOwnerDirectory(directory)
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	defer unix.Close(directoryFD)
	if unix.Flock(directoryFD, unix.LOCK_SH|unix.LOCK_NB) != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	defer unix.Flock(directoryFD, unix.LOCK_UN)
	record, exists, err := readL8RuntimeOwnerRecordAt(directoryFD, seed, currentBootID)
	if err != nil || !exists {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return record, nil
}

func readL8RuntimeOwnerRecordAt(directoryFD int, seed sandboxruntime.JobCredentialIdentitySeed, currentBootID string) (firecrackerRuntimeOwnerRecordV1, bool, error) {
	fd, err := unix.Openat(directoryFD, l8RuntimeOwnerRecordName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return firecrackerRuntimeOwnerRecordV1{}, false, nil
	}
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	file := os.NewFile(uintptr(fd), "runtime-owner-record")
	if file == nil {
		_ = unix.Close(fd)
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	defer file.Close()
	if !validL8RuntimeOwnerPrivateFile(fd) {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file, l8RuntimeOwnerRecordLimit+1))
	if err != nil || len(payload) > l8RuntimeOwnerRecordLimit {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	record, err := decodeFirecrackerRuntimeOwnerRecordV1(payload, seed, currentBootID)
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
	}
	return record, true, nil
}

func openL8RuntimeOwnerDirectory(directory string) (int, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n") {
		return -1, errL8RuntimeOwnerInvalid
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, errL8RuntimeOwnerInvalid
	}
	for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return -1, errL8RuntimeOwnerInvalid
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, errL8RuntimeOwnerInvalid
		}
		fd = next
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(fd)
		return -1, errL8RuntimeOwnerInvalid
	}
	return fd, nil
}

func validL8RuntimeOwnerPrivateFile(fd int) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o777 == 0o600 &&
		stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func writeL8RuntimeOwnerRecordPayload(fd int, payload []byte) error {
	for len(payload) != 0 {
		written, err := unix.Write(fd, payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return errL8RuntimeOwnerInvalid
		}
		payload = payload[written:]
	}
	return nil
}

func closeL8RuntimeOwnerProcessFD(fd int) error {
	if fd < 0 {
		return nil
	}
	if err := unix.Close(fd); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}
