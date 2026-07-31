//go:build linux

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestL7GuestInitParsesStaticBootstrapAndBuildsFixedCommands(t *testing.T) {
	line := "console=ttyS0 hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
		"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://192.0.2.1:18080"
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
		"HOME=/workspace", "PATH=/usr/bin:/bin", "HTTP_PROXY=http://192.0.2.1:18080",
		"HTTPS_PROXY=http://192.0.2.1:18080", "http_proxy=http://192.0.2.1:18080", "https_proxy=http://192.0.2.1:18080",
	} {
		if !containsString(env, want) {
			t.Fatalf("environment missing %q: %#v", want, env)
		}
	}
}

func TestL7GuestInitRejectsPartialUnsafeOrMismatchedBootstrapWithoutEcho(t *testing.T) {
	for _, line := range []string{
		"hal_l7_net_if=eth0",
		"hal_l7_net_if=eth0;token hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://192.0.2.1:18080",
		"hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=198.51.100.1 hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://192.0.2.1:18080",
		"hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://203.0.113.8:19443",
	} {
		_, present, err := parseL7NetworkBootConfig(line)
		if err == nil || !present {
			t.Fatalf("parseL7NetworkBootConfig(%q) = present %t error %v, want fail closed", line, present, err)
		}
		for _, forbidden := range []string{"192.0.2", "198.51.100", "203.0.113", "18080", "19443", "token"} {
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
