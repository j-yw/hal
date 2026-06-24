//go:build !windows

package factory

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockStoreFileHandle(file *os.File) error {
	return flockStoreFileHandle(file, unix.LOCK_EX)
}

func unlockStoreFileHandle(file *os.File) error {
	return flockStoreFileHandle(file, unix.LOCK_UN)
}

func flockStoreFileHandle(file *os.File, operation int) error {
	for {
		err := unix.Flock(int(file.Fd()), operation)
		if err != unix.EINTR {
			return err
		}
	}
}
