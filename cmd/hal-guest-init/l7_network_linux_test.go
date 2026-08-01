//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestL7GuestInitParsesStaticBootstrapAndBuildsFixedCommands(t *testing.T) {
	line := "console=ttyS0 hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
		"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.1:18080"
	config, present, err := parseL7NetworkBootConfig(line)
	if err != nil || !present {
		t.Fatalf("parseL7NetworkBootConfig() = %#v, %t, %v", config, present, err)
	}
	wantCommands := [][]string{
		{"/sbin/ip", "link", "set", "dev", "eth0", "up"},
		{"/sbin/ip", "addr", "add", "192.0.2.2/30", "dev", "eth0"},
		{"/sbin/ip", "-6", "addr", "add", "fd00:7::2/126", "dev", "eth0"},
		{"/sbin/ip", "route", "add", "default", "via", "192.0.2.1", "dev", "eth0"},
		{"/sbin/ip", "-6", "route", "add", "default", "via", "fd00:7::1", "dev", "eth0"},
	}
	if got := l7NetworkBootstrapCommands(config); !reflect.DeepEqual(got, wantCommands) {
		t.Fatalf("commands = %#v, want %#v", got, wantCommands)
	}
	env := l7NetworkBootstrapEnvironment(config)
	for _, want := range []string{
		"HOME=/workspace", "PATH=/usr/bin:/bin", "HTTP_PROXY=http://198.18.0.1:18080",
		"HTTPS_PROXY=http://198.18.0.1:18080", "http_proxy=http://198.18.0.1:18080", "https_proxy=http://198.18.0.1:18080",
	} {
		if !containsString(env, want) {
			t.Fatalf("environment missing %q: %#v", want, env)
		}
	}
}

func TestL7GuestInitDisablesAutomaticIPv6BeforeAnyNetworkCommand(t *testing.T) {
	config, present, err := parseL7NetworkBootConfig("hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
		"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.1:18080")
	if err != nil || !present {
		t.Fatal("test boot config is invalid")
	}
	order := []string{}
	err = configureL7GuestNetworkWithDeps(
		config,
		func(context.Context, l7NetworkBootConfig) error { order = append(order, "disable_addrgen"); return nil },
		func(_ context.Context, command []string) error {
			order = append(order, strings.Join(command, " "))
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 6 || order[0] != "disable_addrgen" || !strings.Contains(order[1], " link set ") {
		t.Fatalf("network bootstrap order = %#v", order)
	}
}

func TestL7GuestInitWritesAndConfirmsNoIPv6AutomaticAddressMode(t *testing.T) {
	directory := t.TempDir()
	control := filepath.Join(directory, "addr_gen_mode")
	if err := os.WriteFile(control, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAndConfirmL7IPv6AddressGenerationMode(context.Background(), control, openL7NetworkControlFile); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(control)
	if err != nil || string(payload) != "1\n" {
		t.Fatalf("addr_gen_mode = %q, %v, want Linux mode 1 (none)", payload, err)
	}

	symlink := filepath.Join(directory, "addr_gen_mode_link")
	if err := os.Symlink(control, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{symlink, directory} {
		if err := writeAndConfirmL7IPv6AddressGenerationMode(context.Background(), path, openL7NetworkControlFile); err == nil {
			t.Fatalf("unsafe control path %q accepted", path)
		} else if strings.Contains(err.Error(), directory) {
			t.Fatalf("error leaked path: %v", err)
		}
	}
}

func TestL7GuestInitRejectsAddressModeReadbackMismatchOverflowAndCancellation(t *testing.T) {
	directory := t.TempDir()
	writePath := filepath.Join(directory, "write")
	if err := os.WriteFile(writePath, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		readback string
		cancel   bool
	}{
		{name: "wrong mode", readback: "2\n"},
		{name: "stable privacy is not none", readback: "2"},
		{name: "extra content", readback: "1\nx"},
		{name: "overflow", readback: "1\nxx"},
		{name: "canceled", readback: "1\n", cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			readPath := filepath.Join(directory, strings.ReplaceAll(test.name, " ", "_"))
			if err := os.WriteFile(readPath, []byte(test.readback), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opener := func(_ string, flags int) (*os.File, error) {
				if flags&unix.O_WRONLY != 0 {
					return os.OpenFile(writePath, os.O_WRONLY, 0)
				}
				file, err := os.Open(readPath)
				if test.cancel {
					cancel()
				}
				return file, err
			}
			if err := writeAndConfirmL7IPv6AddressGenerationMode(ctx, "ignored", opener); err == nil {
				t.Fatal("unsafe readback accepted")
			}
		})
	}
}

type shortL7Writer struct{}

func (shortL7Writer) Write(payload []byte) (int, error) { return len(payload) - 1, nil }

type failedL7Writer struct{}

func (failedL7Writer) Write([]byte) (int, error) { return 0, errors.New("secret write cause") }

func TestL7GuestInitRequiresExactAddressModeWrite(t *testing.T) {
	for _, writer := range []io.Writer{shortL7Writer{}, failedL7Writer{}} {
		err := writeExactL7IPv6AddressGenerationMode(writer)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("writeExactL7IPv6AddressGenerationMode() error = %v", err)
		}
	}
}

func TestL7GuestInitRejectsPartialUnsafeOrMismatchedBootstrapWithoutEcho(t *testing.T) {
	for _, line := range []string{
		"hal_l7_net_if=eth0",
		"hal_l7_net_if=eth0;token hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://192.0.2.1:18080",
		"hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=198.51.100.1 hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://192.0.2.1:18080",
		"hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://10.0.0.8:19443",
	} {
		_, present, err := parseL7NetworkBootConfig(line)
		if err == nil || !present {
			t.Fatalf("parseL7NetworkBootConfig(%q) = present %t error %v, want fail closed", line, present, err)
		}
		for _, forbidden := range []string{"192.0.2", "198.51.100", "10.0.0.8", "18080", "19443", "token"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("error leaked %q in %q", forbidden, err)
			}
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
