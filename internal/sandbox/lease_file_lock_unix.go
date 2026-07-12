//go:build !windows

package sandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockSandboxLeaseStoreFileHandle(file *os.File) error {
	return flockSandboxLeaseStoreFileHandle(file, unix.LOCK_EX)
}

func unlockSandboxLeaseStoreFileHandle(file *os.File) error {
	return flockSandboxLeaseStoreFileHandle(file, unix.LOCK_UN)
}

func flockSandboxLeaseStoreFileHandle(file *os.File, operation int) error {
	for {
		err := unix.Flock(int(file.Fd()), operation)
		if err != unix.EINTR {
			return err
		}
	}
}
