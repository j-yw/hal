//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
	"golang.org/x/sys/unix"
)

const (
	terminationGrace         = 5 * time.Second
	forceStopReapTimeout     = 5 * time.Second
	forceStopReapPoll        = 10 * time.Millisecond
	networkCommandTimeout    = 5 * time.Second
	requireL7NetworkArgument = "--require-l7-network"
)

var errInvalidL7NetworkBootstrap = guestnetwork.ErrInvalidBootConfig

type l7NetworkBootConfig = guestnetwork.BootConfig

func main() {
	os.Exit(run(os.Args[1:]))
}

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
			deadline = nil
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

func loadL7NetworkBootConfig() (l7NetworkBootConfig, bool, error) {
	return guestnetwork.LoadLinuxBootConfig(context.Background())
}

func parseL7NetworkBootConfig(commandLine string) (l7NetworkBootConfig, bool, error) {
	return guestnetwork.ParseBootCommandLine(commandLine)
}

func l7NetworkBootstrapCommands(config l7NetworkBootConfig) [][]string {
	return [][]string{
		{"/sbin/ip", "link", "set", "dev", config.InterfaceName(), "up"},
		{"/sbin/ip", "addr", "add", config.IPv4Address(), "dev", config.InterfaceName()},
		{"/sbin/ip", "-6", "addr", "add", config.IPv6Address(), "dev", config.InterfaceName()},
		{"/sbin/ip", "route", "add", "default", "via", config.IPv4Gateway(), "dev", config.InterfaceName()},
		{"/sbin/ip", "-6", "route", "add", "default", "via", config.IPv6Gateway(), "dev", config.InterfaceName()},
	}
}

func configureL7GuestNetwork(config l7NetworkBootConfig) error {
	return configureL7GuestNetworkWithDeps(config, disableL7IPv6AddressGeneration, func(ctx context.Context, command []string) error {
		return exec.CommandContext(ctx, command[0], command[1:]...).Run()
	})
}

func configureL7GuestNetworkWithDeps(
	config l7NetworkBootConfig,
	disableAddressGeneration func(context.Context, l7NetworkBootConfig) error,
	runCommand func(context.Context, []string) error,
) error {
	if disableAddressGeneration == nil || runCommand == nil {
		return errInvalidL7NetworkBootstrap
	}
	ctx, cancel := context.WithTimeout(context.Background(), networkCommandTimeout)
	err := disableAddressGeneration(ctx, config)
	cancel()
	if err != nil {
		return errInvalidL7NetworkBootstrap
	}
	for _, command := range l7NetworkBootstrapCommands(config) {
		ctx, cancel := context.WithTimeout(context.Background(), networkCommandTimeout)
		err := runCommand(ctx, command)
		cancel()
		if err != nil {
			return errInvalidL7NetworkBootstrap
		}
	}
	return nil
}

func disableL7IPv6AddressGeneration(ctx context.Context, config l7NetworkBootConfig) error {
	if err := ctx.Err(); err != nil || !config.Valid() {
		return errInvalidL7NetworkBootstrap
	}
	path := "/proc/sys/net/ipv6/conf/" + config.InterfaceName() + "/addr_gen_mode"
	return writeAndConfirmL7IPv6AddressGenerationMode(ctx, path, openL7NetworkControlFile)
}

type l7NetworkControlOpener func(string, int) (*os.File, error)

func openL7NetworkControlFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errInvalidL7NetworkBootstrap
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errInvalidL7NetworkBootstrap
	}
	return file, nil
}

func writeAndConfirmL7IPv6AddressGenerationMode(ctx context.Context, path string, openFile l7NetworkControlOpener) error {
	if ctx == nil || openFile == nil || ctx.Err() != nil {
		return errInvalidL7NetworkBootstrap
	}
	writer, err := openFile(path, unix.O_WRONLY|unix.O_NONBLOCK)
	if err != nil || !regularL7NetworkControl(writer) {
		if writer != nil {
			_ = writer.Close()
		}
		return errInvalidL7NetworkBootstrap
	}
	writeErr := writeExactL7IPv6AddressGenerationMode(writer)
	closeErr := writer.Close()
	if writeErr != nil || closeErr != nil || ctx.Err() != nil {
		return errInvalidL7NetworkBootstrap
	}
	reader, err := openFile(path, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil || !regularL7NetworkControl(reader) {
		if reader != nil {
			_ = reader.Close()
		}
		return errInvalidL7NetworkBootstrap
	}
	defer reader.Close()
	if ctx.Err() != nil {
		return errInvalidL7NetworkBootstrap
	}
	payload, err := io.ReadAll(io.LimitReader(reader, 4))
	if err != nil || len(payload) > 3 || (string(payload) != "1" && string(payload) != "1\n") || ctx.Err() != nil {
		return errInvalidL7NetworkBootstrap
	}
	return nil
}

func regularL7NetworkControl(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode().IsRegular()
}

func writeExactL7IPv6AddressGenerationMode(writer io.Writer) error {
	if writer == nil {
		return errInvalidL7NetworkBootstrap
	}
	written, err := writer.Write([]byte("1\n"))
	if err != nil || written != 2 {
		return errInvalidL7NetworkBootstrap
	}
	return nil
}

func l7NetworkBootstrapEnvironment(config l7NetworkBootConfig) []string {
	return []string{
		"HOME=/workspace",
		"PATH=/usr/bin:/bin",
		"TMPDIR=/tmp",
		"USER=agent",
		"LOGNAME=agent",
		"HTTP_PROXY=" + config.ProxyURL(),
		"HTTPS_PROXY=" + config.ProxyURL(),
		"http_proxy=" + config.ProxyURL(),
		"https_proxy=" + config.ProxyURL(),
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

func waitForKilledChildren(
	ctx context.Context,
	mainPID int,
	wait func(int, *unix.WaitStatus, int, *unix.Rusage) (int, error),
) (unix.WaitStatus, bool) {
	if ctx == nil || mainPID <= 0 || wait == nil {
		return 0, false
	}
	var mainStatus unix.WaitStatus
	mainExited := false
	for {
		var childStatus unix.WaitStatus
		pid, err := wait(-1, &childStatus, unix.WNOHANG, nil)
		switch {
		case pid > 0 && err == nil:
			if pid == mainPID {
				mainStatus = childStatus
				mainExited = true
			}
			if ctx.Err() != nil {
				return 0, false
			}
		case errors.Is(err, unix.EINTR):
			if ctx.Err() != nil {
				return 0, false
			}
			continue
		case errors.Is(err, unix.ECHILD):
			if ctx.Err() != nil {
				return 0, false
			}
			return mainStatus, mainExited
		case pid == 0 && err == nil:
			timer := time.NewTimer(forceStopReapPoll)
			select {
			case <-ctx.Done():
				stopTimer(timer)
				return 0, false
			case <-timer.C:
			}
		default:
			return 0, false
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
