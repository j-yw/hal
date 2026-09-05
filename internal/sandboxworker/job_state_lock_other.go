//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package sandboxworker

import (
	"errors"
	"os"
)

func jobStateLockSupported() bool {
	return false
}

func tryLockJobStateFileHandle(*os.File) error {
	return errors.New("job state locking is unsupported")
}

func unlockJobStateFileHandle(*os.File) error {
	return nil
}
