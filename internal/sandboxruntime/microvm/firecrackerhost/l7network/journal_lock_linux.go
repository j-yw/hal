//go:build linux

package l7network

import (
	"errors"
	"os"
	"syscall"
)

var errLockContended = errors.New("host topology lock contended")

func lockFile(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errLockContended
		}
		return err
	}
	return nil
}

func unlockFile(file *os.File) error { return syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }
