//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package sandboxworker

import (
	"os"
	"syscall"
)

func tryLockJobStateFileHandle(file *os.File) error {
	return flockJobStateFileHandle(file, syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockJobStateFileHandle(file *os.File) error {
	return flockJobStateFileHandle(file, syscall.LOCK_UN)
}

func flockJobStateFileHandle(file *os.File, operation int) error {
	for {
		err := syscall.Flock(int(file.Fd()), operation)
		if err != syscall.EINTR {
			return err
		}
	}
}
