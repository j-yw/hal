//go:build linux

package firecrackerhost

import (
	"errors"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type vsockSocketIdentity struct {
	socketDevice uint64
	socketInode  uint64
	parentDevice uint64
	parentInode  uint64
}

func validatePrivateFirecrackerStateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("Firecracker state directory is not private")
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, path, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		int(stat.Uid) != os.Geteuid() {
		return errors.New("Firecracker state directory owner mismatch")
	}
	return nil
}

func validateVsockSocketOwnership(path string, info os.FileInfo) error {
	if err := validatePrivateFirecrackerStateDir(filepath.Dir(path)); err != nil {
		return err
	}
	var socketStat unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, path, &socketStat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		int(socketStat.Uid) != os.Geteuid() {
		return errors.New("Firecracker socket owner mismatch")
	}
	return nil
}

func statVsockSocket(path string) (vsockSocketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return vsockSocketIdentity{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return vsockSocketIdentity{}, errors.New("Firecracker socket is not private")
	}
	if err := validateVsockSocketOwnership(path, info); err != nil {
		return vsockSocketIdentity{}, err
	}
	var socketStat unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, path, &socketStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return vsockSocketIdentity{}, errors.New("Firecracker socket identity unavailable")
	}
	var parentStat unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, filepath.Dir(path), &parentStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return vsockSocketIdentity{}, errors.New("Firecracker state directory identity unavailable")
	}
	return vsockSocketIdentity{
		socketDevice: uint64(socketStat.Dev), socketInode: socketStat.Ino,
		parentDevice: uint64(parentStat.Dev), parentInode: parentStat.Ino,
	}, nil
}

func verifyVsockPeer(conn *net.UnixConn, expectedPID int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return errors.New("Firecracker peer credentials unavailable")
	}
	var credentials *unix.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || controlErr != nil || credentials == nil || int(credentials.Pid) != expectedPID {
		return errors.New("Firecracker peer identity mismatch")
	}
	return nil
}
