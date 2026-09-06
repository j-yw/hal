//go:build linux && l8_production_pid1

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func run(_ []string) int {
	if os.Getpid() != 1 {
		return 127
	}
	admitted, code := pid1StartGateRelease()
	if code != 0 || !admitted {
		return 127
	}
	return superviseAdmittedPID1()
}

func superviseAdmittedPID1() int {
	signals := make(chan os.Signal, 32)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	for received := range signals {
		if received == syscall.SIGCHLD {
			reapChildren(0)
			continue
		}
		reapChildren(0)
		return 0
	}
	return 1
}
