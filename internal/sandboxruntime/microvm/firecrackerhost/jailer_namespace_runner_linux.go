//go:build linux

package firecrackerhost

import (
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

type strictJailerOSExecLaunchOps struct {
	lockOSThread         func()
	unshareFilesystem    func() error
	umask                func(int) int
	armParentDeathSignal func()
	start                func() error
	publishStarted       func(error)
	wait                 func() error
	publishCompleted     func(error)
}

// runStrictJailerOSExecLaunch keeps the exact OS thread which creates the
// foreground Jailer alive through Wait. Linux delivers Pdeathsig when that
// creating thread dies, so returning from a short-lived locked goroutine after
// Start would kill a healthy child and is not a valid containment model.
// The thread is intentionally never unlocked after CLONE_FS; the Go runtime
// retires it after the child exits instead of reusing its private fs context.
//
// This bounds the foreground Jailer launch but does not prove final
// Firecracker orphan prevention: Linux may clear Pdeathsig across Jailer
// credential changes. Production selection therefore remains blocked on
// post-drop containment proof or a retained supervisor design.
func runStrictJailerOSExecLaunch(ops strictJailerOSExecLaunchOps) {
	if ops.lockOSThread == nil || ops.unshareFilesystem == nil || ops.umask == nil ||
		ops.armParentDeathSignal == nil || ops.start == nil || ops.publishStarted == nil ||
		ops.wait == nil || ops.publishCompleted == nil {
		if ops.publishStarted != nil {
			ops.publishStarted(errStrictJailerNamespaceStartFailed)
		}
		return
	}
	ops.lockOSThread()
	if err := ops.unshareFilesystem(); err != nil {
		ops.publishStarted(errStrictJailerNamespaceStartFailed)
		return
	}
	previousUmask := ops.umask(0o177)
	defer ops.umask(previousUmask)
	ops.armParentDeathSignal()
	if err := ops.start(); err != nil {
		ops.publishStarted(errStrictJailerNamespaceStartFailed)
		return
	}
	ops.publishStarted(nil)
	ops.publishCompleted(ops.wait())
}

func armStrictJailerParentDeathSignal(command *exec.Cmd) {
	if command == nil {
		return
	}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func startStrictJailerOSExecCommand(command *exec.Cmd) (HostProcess, error) {
	if command == nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	process := &osExecHostProcess{cmd: command, done: make(chan struct{})}
	started := make(chan error, 1)
	go runStrictJailerOSExecLaunch(strictJailerOSExecLaunchOps{
		lockOSThread:      runtime.LockOSThread,
		unshareFilesystem: func() error { return unix.Unshare(unix.CLONE_FS) },
		umask:             unix.Umask,
		armParentDeathSignal: func() {
			armStrictJailerParentDeathSignal(command)
		},
		start:          command.Start,
		publishStarted: func(err error) { started <- err },
		wait:           command.Wait,
		publishCompleted: func(err error) {
			process.mu.Lock()
			process.waitErr = err
			process.mu.Unlock()
			close(process.done)
		},
	})
	if err := <-started; err != nil || command.Process == nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	return process, nil
}
