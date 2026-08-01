//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	terminationGrace         = 5 * time.Second
	networkCommandTimeout    = 5 * time.Second
	requireL7NetworkArgument = "--require-l7-network"
)

var errInvalidL7NetworkBootstrap = errors.New("L7 guest network bootstrap is invalid")

type l7NetworkBootConfig struct {
	interfaceName string
	ipv4Address   string
	ipv4Gateway   string
	ipv6Address   string
	ipv6Gateway   string
	proxyURL      string
}

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
		}
	}
}

func loadL7NetworkBootConfig() (l7NetworkBootConfig, bool, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return l7NetworkBootConfig{}, false, errInvalidL7NetworkBootstrap
	}
	return parseL7NetworkBootConfig(string(data))
}

func parseL7NetworkBootConfig(commandLine string) (l7NetworkBootConfig, bool, error) {
	required := []string{
		"hal_l7_net_if",
		"hal_l7_ipv4",
		"hal_l7_ipv4_gateway",
		"hal_l7_ipv6",
		"hal_l7_ipv6_gateway",
		"hal_l7_proxy",
	}
	values := make(map[string]string, len(required))
	present := false
	for _, field := range strings.Fields(commandLine) {
		name, value, ok := strings.Cut(field, "=")
		if !strings.HasPrefix(name, "hal_l7_") {
			continue
		}
		present = true
		if !ok || value == "" || !stringInList(required, name) {
			return l7NetworkBootConfig{}, true, errInvalidL7NetworkBootstrap
		}
		if _, duplicate := values[name]; duplicate {
			return l7NetworkBootConfig{}, true, errInvalidL7NetworkBootstrap
		}
		values[name] = value
	}
	if !present {
		return l7NetworkBootConfig{}, false, nil
	}
	for _, name := range required {
		if values[name] == "" {
			return l7NetworkBootConfig{}, true, errInvalidL7NetworkBootstrap
		}
	}
	if !safeGuestInterfaceName(values["hal_l7_net_if"]) {
		return l7NetworkBootConfig{}, true, errInvalidL7NetworkBootstrap
	}
	ipv4, ipv4Gateway, err := parseGuestAddressPair(values["hal_l7_ipv4"], values["hal_l7_ipv4_gateway"], false)
	if err != nil {
		return l7NetworkBootConfig{}, true, errInvalidL7NetworkBootstrap
	}
	ipv6, ipv6Gateway, err := parseGuestAddressPair(values["hal_l7_ipv6"], values["hal_l7_ipv6_gateway"], true)
	if err != nil {
		return l7NetworkBootConfig{}, true, errInvalidL7NetworkBootstrap
	}
	proxy, err := parseGuestProxyURL(values["hal_l7_proxy"])
	if err != nil {
		return l7NetworkBootConfig{}, true, errInvalidL7NetworkBootstrap
	}
	return l7NetworkBootConfig{
		interfaceName: values["hal_l7_net_if"],
		ipv4Address:   ipv4.String(),
		ipv4Gateway:   ipv4Gateway.String(),
		ipv6Address:   ipv6.String(),
		ipv6Gateway:   ipv6Gateway.String(),
		proxyURL:      proxy,
	}, true, nil
}

func parseGuestAddressPair(address, gateway string, ipv6 bool) (netip.Prefix, netip.Addr, error) {
	prefix, err := netip.ParsePrefix(address)
	if err != nil || prefix.Addr().Is6() != ipv6 || !usableGuestAddress(prefix.Addr()) {
		return netip.Prefix{}, netip.Addr{}, errInvalidL7NetworkBootstrap
	}
	prefix = netip.PrefixFrom(prefix.Addr(), prefix.Bits())
	parsedGateway, err := netip.ParseAddr(gateway)
	if err != nil || parsedGateway.Is6() != ipv6 || !usableGuestAddress(parsedGateway) ||
		!prefix.Contains(parsedGateway) || parsedGateway == prefix.Addr() {
		return netip.Prefix{}, netip.Addr{}, errInvalidL7NetworkBootstrap
	}
	return prefix, parsedGateway, nil
}

func parseGuestProxyURL(value string) (string, error) {
	if len(value) > 256 || strings.IndexFunc(value, func(char rune) bool { return char <= ' ' || char == 0x7f }) >= 0 {
		return "", errInvalidL7NetworkBootstrap
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errInvalidL7NetworkBootstrap
	}
	host, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !usableGuestProxyAddress(host) {
		return "", errInvalidL7NetworkBootstrap
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", errInvalidL7NetworkBootstrap
	}
	hostText := host.String()
	if host.Is6() {
		hostText = "[" + hostText + "]"
	}
	canonical := "http://" + hostText + ":" + strconv.Itoa(port)
	if value != canonical {
		return "", errInvalidL7NetworkBootstrap
	}
	return canonical, nil
}

func usableGuestProxyAddress(address netip.Addr) bool {
	return usableGuestAddress(address) && !address.IsPrivate()
}

func usableGuestAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsLoopback() &&
		!address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified()
}

func safeGuestInterfaceName(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 15 {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '_', char == '-', char == '.':
		default:
			return false
		}
	}
	return true
}

func l7NetworkBootstrapCommands(config l7NetworkBootConfig) [][]string {
	return [][]string{
		{"/sbin/ip", "link", "set", "dev", config.interfaceName, "up"},
		{"/sbin/ip", "addr", "add", config.ipv4Address, "dev", config.interfaceName},
		{"/sbin/ip", "-6", "addr", "add", config.ipv6Address, "dev", config.interfaceName},
		{"/sbin/ip", "route", "add", "default", "via", config.ipv4Gateway, "dev", config.interfaceName},
		{"/sbin/ip", "-6", "route", "add", "default", "via", config.ipv6Gateway, "dev", config.interfaceName},
	}
}

func configureL7GuestNetwork(config l7NetworkBootConfig) error {
	for _, command := range l7NetworkBootstrapCommands(config) {
		ctx, cancel := context.WithTimeout(context.Background(), networkCommandTimeout)
		err := exec.CommandContext(ctx, command[0], command[1:]...).Run()
		cancel()
		if err != nil {
			return errInvalidL7NetworkBootstrap
		}
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
		"HTTP_PROXY=" + config.proxyURL,
		"HTTPS_PROXY=" + config.proxyURL,
		"http_proxy=" + config.proxyURL,
		"https_proxy=" + config.proxyURL,
	}
}

func stringInList(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
