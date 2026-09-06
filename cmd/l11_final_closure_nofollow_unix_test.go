//go:build unix

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

func l11OpenFinalClosureNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
