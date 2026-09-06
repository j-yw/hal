//go:build !windows

package sandboxexecution

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockExecutionFileHandle(file *os.File) error {
	return flockExecutionFileHandle(file, unix.LOCK_EX)
}

func unlockExecutionFileHandle(file *os.File) error {
	return flockExecutionFileHandle(file, unix.LOCK_UN)
}

func flockExecutionFileHandle(file *os.File, operation int) error {
	for {
		err := unix.Flock(int(file.Fd()), operation)
		if err != unix.EINTR {
			return err
		}
	}
}
