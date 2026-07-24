//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package sandboxworker

import (
	"errors"
	"os"
	"syscall"
)

func validateWorkerSocketParentOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("worker server socket parent ownership is unsafe")
	}
	return nil
}
