//go:build !windows

package sandboxexecution

import (
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func fileOwnedByCurrentUser(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func filePermissionsPrivate(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0
}

func openFileNoFollow(path string, flag int, perm fs.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openContainedFileNoFollow(root string, components []string, flag int, perm fs.FileMode) (*os.File, error) {
	dirFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	closeDir := func() {
		if dirFD >= 0 {
			_ = unix.Close(dirFD)
		}
	}
	if err := validatePrivateDirectoryFD(dirFD); err != nil {
		closeDir()
		return nil, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			closeDir()
			return nil, openErr
		}
		_ = unix.Close(dirFD)
		dirFD = nextFD
		if validateErr := validatePrivateDirectoryFD(dirFD); validateErr != nil {
			closeDir()
			dirFD = -1
			return nil, validateErr
		}
	}
	fileFD, err := unix.Openat(dirFD, components[len(components)-1], flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	closeDir()
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fileFD), components[len(components)-1]), nil
}

func validatePrivateDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fs.ErrInvalid
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 {
		return fs.ErrPermission
	}
	return nil
}
