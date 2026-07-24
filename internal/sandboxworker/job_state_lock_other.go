//go:build !linux

package sandboxworker

import (
	"errors"
	"os"
)

func tryLockJobStateFileHandle(*os.File) error {
	return errors.New("job state locking is unsupported")
}

func unlockJobStateFileHandle(*os.File) error {
	return nil
}
