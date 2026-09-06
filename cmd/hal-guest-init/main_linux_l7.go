//go:build linux && !l8_production_pid1

package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func run(arguments []string) int {
	requireNetwork := len(arguments) > 0 && arguments[0] == requireL7NetworkArgument
	if requireNetwork {
		arguments = arguments[1:]
	}
	if len(arguments) == 0 || os.Getpid() != 1 {
		return 127
	}
	network, present, err := loadL7NetworkBootConfig()
	if err != nil || (requireNetwork && !present) {
		return 127
	}
	var childEnvironment []string
	if present {
		if err := configureL7GuestNetwork(network); err != nil {
			return 127
		}
		childEnvironment = l7NetworkBootstrapEnvironment(network)
	}
	if code := releasePID1AgentStartGate(); code != 0 {
		return code
	}
	signals := make(chan os.Signal, 32)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)

	child, err := os.StartProcess(arguments[0], arguments, &os.ProcAttr{
		Env:   childEnvironment,
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
			reapContext, cancelReap := context.WithTimeout(context.Background(), forceStopReapTimeout)
			status, exited := waitForKilledChildren(reapContext, childPID, unix.Wait4)
			cancelReap()
			stopTimer(timer)
			if !exited {
				return 1
			}
			return waitStatusExitCode(status)
		}
	}
}

func configureL7GuestNetwork(config l7NetworkBootConfig) error {
	return configureL7GuestNetworkWithDeps(config, configureL7IPv6StaticAddressing, func(ctx context.Context, command []string) error {
		return exec.CommandContext(ctx, command[0], command[1:]...).Run()
	})
}
