//go:build linux

package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// statStrictJailerPrivateStateDir validates the state directory against the
// structured runtime UID carried by strictJailerLaunchPlan. Unlike the legacy
// direct-launch helper, a root coordinator may inspect state owned by the
// non-root Firecracker identity.
func statStrictJailerPrivateStateDir(path string, runtimeUID uint32) (privateStateDirIdentity, error) {
	if !strictJailerCallerMayCleanup(uint32(os.Geteuid()), runtimeUID) {
		return privateStateDirIdentity{}, errors.New("strict Jailer state ownership is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return privateStateDirIdentity{}, errors.New("strict Jailer state directory is not private")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o777 != 0o700 || stat.Uid != runtimeUID {
		return privateStateDirIdentity{}, errors.New("strict Jailer state directory is not private")
	}
	return privateStateDirIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid}, nil
}

func validateStrictJailerSocketOwnership(path string, runtimeUID uint32) error {
	if _, err := statStrictJailerPrivateStateDir(filepath.Dir(path), runtimeUID); err != nil {
		return err
	}
	var socketStat unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, path, &socketStat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		socketStat.Mode&unix.S_IFMT != unix.S_IFSOCK || socketStat.Mode&0o077 != 0 || socketStat.Uid != runtimeUID {
		return errors.New("strict Jailer socket ownership is invalid")
	}
	return nil
}

func removeStrictJailerPinnedStateEntry(
	path, name string,
	expected privateStateDirIdentity,
	runtimeUID uint32,
) error {
	if !strictJailerCallerMayCleanup(uint32(os.Geteuid()), runtimeUID) || expected.uid != runtimeUID {
		return errors.New("strict Jailer cleanup authority is invalid")
	}
	stateFD, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("strict Jailer state directory is unavailable")
	}
	defer unix.Close(stateFD)
	var stateStat unix.Stat_t
	if err := unix.Fstat(stateFD, &stateStat); err != nil ||
		!strictJailerPrivateStateIdentityMatches(expected, stateStat, runtimeUID) || stateStat.Mode&0o777 != 0o700 {
		return errors.New("strict Jailer state directory identity changed")
	}
	var entryStat unix.Stat_t
	if err := unix.Fstatat(stateFD, name, &entryStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return errors.New("strict Jailer state entry identity is unavailable")
	}
	if entryStat.Mode&unix.S_IFMT != unix.S_IFSOCK || entryStat.Mode&0o077 != 0 || entryStat.Uid != runtimeUID {
		return errors.New("strict Jailer state entry is unsafe")
	}
	if err := unix.Unlinkat(stateFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("strict Jailer state entry removal failed")
	}
	return nil
}

func strictJailerPrivateStateIdentityMatches(
	expected privateStateDirIdentity,
	stat unix.Stat_t,
	runtimeUID uint32,
) bool {
	return expected.device == uint64(stat.Dev) && expected.inode == stat.Ino &&
		expected.uid == runtimeUID && stat.Uid == runtimeUID && stat.Mode&unix.S_IFMT == unix.S_IFDIR
}
