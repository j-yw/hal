//go:build linux

package firecrackerhost

import (
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

var errHostProcessPrivateLaunch = errors.New("firecracker private process launch failed")

type privateOSExecLaunchOps struct {
	unshare func(int) error
	umask   func(int) int
	start   func() error
}

func startOSExecCommandWithPrivateUmask(start func() error) error {
	if start == nil {
		return errHostProcessPrivateLaunch
	}
	return startPrivateOSExecLaunch(privateOSExecLaunchOps{
		unshare: unix.Unshare,
		umask:   unix.Umask,
		start:   start,
	})
}

func startPrivateOSExecLaunch(ops privateOSExecLaunchOps) error {
	result := make(chan error, 1)
	go func() {
		// CLONE_FS makes umask private to this OS thread. Deliberately leave the
		// goroutine locked so the Go runtime terminates the altered thread when
		// this function returns instead of reusing it for unrelated work.
		runtime.LockOSThread()
		if ops.unshare == nil || ops.umask == nil || ops.start == nil {
			result <- errHostProcessPrivateLaunch
			return
		}
		if err := ops.unshare(unix.CLONE_FS); err != nil {
			result <- errHostProcessPrivateLaunch
			return
		}
		previous := ops.umask(0o177)
		defer ops.umask(previous)
		result <- ops.start()
	}()
	return <-result
}
