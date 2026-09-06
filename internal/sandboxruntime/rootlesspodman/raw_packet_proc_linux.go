//go:build linux

package rootlesspodman

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

type linuxRawPacketProcessInspector struct{}

func defaultRawPacketProcessInspector() RawPacketProcessInspector {
	return linuxRawPacketProcessInspector{}
}

func (linuxRawPacketProcessInspector) VerifyRawPacketProcess(ctx context.Context, pid int, maxBytes int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if pid <= 1 || pid > 1<<30 || maxBytes <= 0 || maxBytes > defaultRawPacketProcBytes || ctx.Err() != nil {
		return ErrRawPacketIsolationUnverified
	}
	pidFD, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return ErrRawPacketIsolationUnverified
	}
	defer unix.Close(pidFD)
	procFD, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrRawPacketIsolationUnverified
	}
	defer unix.Close(procFD)
	var procFS unix.Statfs_t
	if err := unix.Fstatfs(procFD, &procFS); err != nil || procFS.Type != unix.PROC_SUPER_MAGIC {
		return ErrRawPacketIsolationUnverified
	}
	processFD, err := openRawPacketProcessDirectory(procFD, pid)
	if err != nil {
		return ErrRawPacketIsolationUnverified
	}
	defer unix.Close(processFD)

	var beforeDirectory unix.Stat_t
	if err := unix.Fstat(processFD, &beforeDirectory); err != nil || beforeDirectory.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrRawPacketIsolationUnverified
	}
	beforeStat, err := readRawPacketProcFile(ctx, processFD, "stat", maxBytes)
	if err != nil {
		return ErrRawPacketIsolationUnverified
	}
	beforeStart, err := parseRawPacketProcStartTime(beforeStat, pid)
	if err != nil {
		return ErrRawPacketIsolationUnverified
	}
	status, err := readRawPacketProcFile(ctx, processFD, "status", maxBytes)
	if err != nil || validateRawPacketProcStatus(status, maxBytes) != nil {
		return ErrRawPacketIsolationUnverified
	}
	afterStat, err := readRawPacketProcFile(ctx, processFD, "stat", maxBytes)
	if err != nil {
		return ErrRawPacketIsolationUnverified
	}
	afterStart, err := parseRawPacketProcStartTime(afterStat, pid)
	if err != nil || beforeStart != afterStart {
		return ErrRawPacketIsolationUnverified
	}
	var afterDirectory unix.Stat_t
	if err := unix.Fstat(processFD, &afterDirectory); err != nil ||
		beforeDirectory.Dev != afterDirectory.Dev || beforeDirectory.Ino != afterDirectory.Ino ||
		unix.PidfdSendSignal(pidFD, 0, nil, 0) != nil || ctx.Err() != nil {
		return ErrRawPacketIsolationUnverified
	}
	return nil
}

func openRawPacketProcessDirectory(procFD, pid int) (int, error) {
	fd, err := unix.Openat(procFD, strconv.Itoa(pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		if err == nil {
			err = unix.EINVAL
		}
		return -1, err
	}
	return fd, nil
}

func readRawPacketProcFile(ctx context.Context, processFD int, name string, maxBytes int64) ([]byte, error) {
	if ctx.Err() != nil || (name != "stat" && name != "status") {
		return nil, ErrRawPacketIsolationUnverified
	}
	fd, err := unix.Openat(processFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, ErrRawPacketIsolationUnverified
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, ErrRawPacketIsolationUnverified
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(payload)) > maxBytes || ctx.Err() != nil {
		return nil, errors.Join(ErrRawPacketIsolationUnverified, err)
	}
	return payload, nil
}
