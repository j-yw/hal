//go:build linux

package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const terminationGrace = 5 * time.Second

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(command []string) int {
	if len(command) == 0 || os.Getpid() != 1 {
		return 127
	}
	signals := make(chan os.Signal, 32)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)

	child, err := os.StartProcess(command[0], command, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Setpgid: true,
		},
	})
	if err != nil {
		return 127
	}
	childPID := child.Pid
	_ = child.Release()

	var deadline <-chan time.Time
	var timer *time.Timer
	terminating := false
	for {
		select {
		case received := <-signals:
			if received != syscall.SIGCHLD {
				signalValue, ok := received.(syscall.Signal)
				if ok {
					_ = unix.Kill(-childPID, signalValue)
				}
				if !terminating {
					terminating = true
					timer = time.NewTimer(terminationGrace)
					deadline = timer.C
				}
			}
			if status, exited := reapChildren(childPID); exited {
				stopTimer(timer)
				return waitStatusExitCode(status)
			}
		case <-deadline:
			_ = unix.Kill(-childPID, unix.SIGKILL)
			deadline = nil
		}
	}
}

func reapChildren(mainPID int) (unix.WaitStatus, bool) {
	var mainStatus unix.WaitStatus
	mainExited := false
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		switch {
		case pid > 0:
			if pid == mainPID {
				mainStatus = status
				mainExited = true
			}
		case pid == 0:
			return mainStatus, mainExited
		case errors.Is(err, unix.EINTR):
			continue
		default:
			return mainStatus, mainExited
		}
	}
}

func waitStatusExitCode(status unix.WaitStatus) int {
	if status.Exited() {
		return status.ExitStatus()
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
