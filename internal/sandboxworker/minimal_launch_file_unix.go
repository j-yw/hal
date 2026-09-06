//go:build linux || darwin

package sandboxworker

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openMinimalLaunchNoFollow(path string, directory bool) (*os.File, error) {
	flags := os.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	return os.OpenFile(path, flags, 0)
}

func minimalLaunchFileOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink > 0
}

func openMinimalLaunchRelative(root *os.Root, name string, create bool) (*os.File, error) {
	flags, mode := os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, os.FileMode(0)
	if create {
		flags, mode = os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600
	}
	return root.OpenFile(name, flags, mode)
}
