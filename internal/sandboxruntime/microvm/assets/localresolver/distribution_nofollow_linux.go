//go:build linux

package localresolver

import (
	"os"

	"golang.org/x/sys/unix"
)

func openDistributionRootNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "distribution-root"), nil
}

func openDistributionFileNoFollow(root *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(
		int(root.Fd()),
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "distribution-file")
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		if err == nil {
			err = unix.EINVAL
		}
		return nil, err
	}
	return file, nil
}

func duplicateDistributionRoot(root *os.File) (*os.File, error) {
	fd, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "distribution-root-copy"), nil
}
