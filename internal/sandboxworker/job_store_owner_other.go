//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package sandboxworker

import "io/fs"

func validateJobStateRootOwner(fs.FileInfo) error {
	return nil
}
