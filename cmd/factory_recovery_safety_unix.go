//go:build unix

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

func openFactoryRecoveryFile(root *os.Root, name string) (*os.File, error) {
	// name is one checked component. Open relative to the retained directory,
	// without following a replaced symlink or blocking on a replaced FIFO.
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
