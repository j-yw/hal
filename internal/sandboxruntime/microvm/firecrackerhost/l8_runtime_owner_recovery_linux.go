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
	beforeStart, beforeState, err := readL8RuntimeOwnerProcStat(processfd, pid)
	if err != nil {
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
	afterStart, afterState, err := readL8RuntimeOwnerProcStat(processfd, pid)
	if err != nil || afterStart != beforeStart || afterState != beforeState {
		return l8RuntimeOwnerProcessObservation{}, errL8RuntimeOwnerInvalid
	}
	failed = false
	return l8RuntimeOwnerProcessObservation{PID: pid, StartTime: afterStart, state: afterState, pidfd: pidfd}, nil
}

func readL8RuntimeOwnerProcStat(processfd int, pid uint32) (uint64, byte, error) {
	statfd, err := unix.Openat(processfd, "stat", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, 0, errL8RuntimeOwnerInvalid
	}
	statFile := os.NewFile(uintptr(statfd), "process-stat")
	if statFile == nil {
		_ = unix.Close(statfd)
		return 0, 0, errL8RuntimeOwnerInvalid
	}
	payload, readErr := io.ReadAll(io.LimitReader(statFile, 4097))
	closeErr := statFile.Close()
	startTime, state, parseErr := parseL8RuntimeOwnerProcStat(payload, pid)
	if readErr != nil || closeErr != nil || len(payload) > 4096 || parseErr != nil {
		return 0, 0, errL8RuntimeOwnerInvalid
	}
	return startTime, state, nil
}

func parseL8RuntimeOwnerProcStat(payload []byte, expectedPID uint32) (uint64, byte, error) {
	value := strings.TrimSuffix(string(payload), "\n")
	open := strings.IndexByte(value, '(')
	close := strings.LastIndexByte(value, ')')
	if open <= 0 || close <= open || strings.TrimSpace(value[close+1:]) == "" {
		return 0, 0, errL8RuntimeOwnerInvalid
	}
	parsedPID, err := strconv.ParseUint(strings.TrimSpace(value[:open]), 10, 32)
	fields := strings.Fields(value[close+1:])
	if err != nil || uint32(parsedPID) != expectedPID || len(fields) < 20 || len(fields[0]) != 1 {
		return 0, 0, errL8RuntimeOwnerInvalid
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return 0, 0, errL8RuntimeOwnerInvalid
	}
	return startTime, fields[0][0], nil
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
	existing, exists, err := readL8RuntimeOwnerRecordAt(directoryFD, seed, currentBootID)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if exists {
		if existing == record {
			return nil
		}
		if existing.Revision == ^uint64(0) || record.Revision != existing.Revision+1 {
			return errL8RuntimeOwnerInvalid
		}
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
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, errL8RuntimeOwnerInvalid
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
