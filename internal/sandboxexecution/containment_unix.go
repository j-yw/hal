//go:build !windows

package sandboxexecution

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	dirFD, err := openAbsoluteDirectoryNoFollow(root, false)
	if err != nil {
		return nil, err
	}
	closeDir := func() {
		if dirFD >= 0 {
			_ = unix.Close(dirFD)
		}
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

func validatePrivateStoreRoot(root string) error {
	fd, err := openAbsoluteDirectoryNoFollow(root, false)
	if err != nil {
		return filesystemUnavailable("sandbox execution store", err)
	}
	return unix.Close(fd)
}

func ensurePrivateStoreRoot(root string) error {
	fd, err := openAbsoluteDirectoryNoFollow(root, true)
	if err != nil {
		return filesystemUnavailable("sandbox execution store", err)
	}
	return unix.Close(fd)
}

// openAbsoluteDirectoryNoFollow starts from the filesystem root and opens each
// configured component relative to its verified parent. This rejects a symlink
// anywhere in the absolute store-root chain and returns a descriptor pinned to
// the validated final directory.
func openAbsoluteDirectoryNoFollow(path string, createFinal bool) (int, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return -1, fs.ErrInvalid
	}
	absolute = filepath.Clean(absolute)
	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 1 && components[0] == "" {
		components = nil
	}

	dirFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for index, component := range components {
		nextFD, openErr := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && createFinal && index == len(components)-1 {
			if mkdirErr := unix.Mkdirat(dirFD, component, uint32(privateDirMode.Perm())); mkdirErr != nil {
				_ = unix.Close(dirFD)
				return -1, mkdirErr
			}
			nextFD, openErr = unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		_ = unix.Close(dirFD)
		if openErr != nil {
			return -1, openErr
		}
		dirFD = nextFD
	}
	if err := validatePrivateDirectoryFD(dirFD); err != nil {
		_ = unix.Close(dirFD)
		return -1, err
	}
	return dirFD, nil
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
