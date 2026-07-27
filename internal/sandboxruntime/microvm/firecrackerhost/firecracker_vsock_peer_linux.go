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

type privateStateDirIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
}

func statPrivateFirecrackerStateDir(path string) (privateStateDirIdentity, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return privateStateDirIdentity{}, errors.New("Firecracker state directory is not private")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o777 != 0o700 {
		return privateStateDirIdentity{}, errors.New("Firecracker state directory is not private")
	}
	if int(stat.Uid) != os.Geteuid() {
		return privateStateDirIdentity{}, errors.New("Firecracker state directory owner mismatch")
	}
	return privateStateDirIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid}, nil
}

func validatePrivateFirecrackerStateDir(path string) error {
	_, err := statPrivateFirecrackerStateDir(path)
	return err
}

func removePinnedFirecrackerStateDir(path string, expected privateStateDirIdentity) error {
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("Firecracker state directory parent is unavailable")
	}
	defer unix.Close(parentFD)
	stateFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return errors.New("Firecracker state directory is not private")
	}
	stateFile := os.NewFile(uintptr(stateFD), name)
	if stateFile == nil {
		_ = unix.Close(stateFD)
		return errors.New("Firecracker state directory is unavailable")
	}
	defer stateFile.Close()
	var stateStat unix.Stat_t
	if err := unix.Fstat(stateFD, &stateStat); err != nil ||
		!privateStateIdentityMatches(expected, stateStat) ||
		stateStat.Mode&0o777 != 0o700 {
		return errors.New("Firecracker state directory identity changed")
	}
	names, err := stateFile.Readdirnames(-1)
	if err != nil {
		return errors.New("Firecracker state directory contents are unavailable")
	}
	allowed := map[string]bool{
		"firecracker.sock":        true,
		"guest.vsock":             true,
		"firecracker-config.json": true,
		"firecracker.log":         true,
		"firecracker.metrics":     true,
	}
	for _, entry := range names {
		if !allowed[entry] {
			return errors.New("Firecracker state directory contains an unexpected entry")
		}
		var entryStat unix.Stat_t
		if err := unix.Fstatat(stateFD, entry, &entryStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return errors.New("Firecracker state entry identity is unavailable")
		}
		fileType := entryStat.Mode & unix.S_IFMT
		if int(entryStat.Uid) != os.Geteuid() ||
			(fileType != unix.S_IFREG && fileType != unix.S_IFSOCK) ||
			entryStat.Mode&0o077 != 0 ||
			fileType == unix.S_IFREG && entryStat.Mode&0o777 != 0o600 {
			return errors.New("Firecracker state entry is unsafe")
		}
		if err := unix.Unlinkat(stateFD, entry, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return errors.New("Firecracker state entry removal failed")
		}
	}
	if err := stateFile.Close(); err != nil {
		return errors.New("Firecracker state directory close failed")
	}
	var finalStat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &finalStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return errors.New("Firecracker state directory final identity is unavailable")
	}
	if !privateStateIdentityMatches(expected, finalStat) {
		return errors.New("Firecracker state directory identity changed")
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("Firecracker state directory removal failed")
	}
	return nil
}

func removePinnedFirecrackerStateEntry(path, name string, expected privateStateDirIdentity) error {
	stateFD, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("Firecracker state directory is unavailable")
	}
	defer unix.Close(stateFD)
	var stateStat unix.Stat_t
	if err := unix.Fstat(stateFD, &stateStat); err != nil ||
		!privateStateIdentityMatches(expected, stateStat) ||
		stateStat.Mode&0o777 != 0o700 {
		return errors.New("Firecracker state directory identity changed")
	}
	var entryStat unix.Stat_t
	if err := unix.Fstatat(stateFD, name, &entryStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return errors.New("Firecracker state entry identity is unavailable")
	}
	if entryStat.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		entryStat.Mode&0o077 != 0 ||
		int(entryStat.Uid) != os.Geteuid() {
		return errors.New("Firecracker state entry is unsafe")
	}
	if err := unix.Unlinkat(stateFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("Firecracker state entry removal failed")
	}
	return nil
}

func privateStateIdentityMatches(expected privateStateDirIdentity, stat unix.Stat_t) bool {
	return expected.device == uint64(stat.Dev) &&
		expected.inode == stat.Ino &&
		expected.uid == stat.Uid &&
		int(stat.Uid) == os.Geteuid() &&
		stat.Mode&unix.S_IFMT == unix.S_IFDIR
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
