//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package sandboxworker

import (
	"errors"
	"os"
)

func validateWorkerSocketParentOwner(os.FileInfo) error {
	return errors.New("worker server socket parent ownership cannot be verified")
}
