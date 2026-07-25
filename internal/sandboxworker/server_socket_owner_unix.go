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

func validateWorkerSocketAncestorTrust(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("worker server socket ancestor ownership is unavailable")
	}
	currentUID := uint32(os.Geteuid())
	if stat.Uid != currentUID && stat.Uid != 0 {
		return errors.New("worker server socket ancestor ownership is unsafe")
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("worker server socket ancestor permissions are unsafe")
	}
	return nil
}
