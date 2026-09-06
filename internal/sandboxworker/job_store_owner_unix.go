//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package sandboxworker

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func validateJobStateRootOwner(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("job state root ownership is invalid")
	}
	return nil
}
