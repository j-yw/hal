//go:build linux && !l8_production_pid1

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
)

func TestMinimalPID1PreservesL7OrderingArgumentsEnvironmentAndExit(t *testing.T) {
	arguments := []string{"/usr/bin/setpriv", "--reuid", "1000", "--regid", "1000", "--clear-groups", "--no-new-privs", "/usr/bin/hal-guest-agent"}
	wantArguments := append([]string(nil), arguments...)
	wantEnvironment := []string{
		"HOME=/workspace", "PATH=/usr/bin:/bin", "TMPDIR=/tmp", "USER=agent", "LOGNAME=agent",
		"HTTP_PROXY=http://198.18.0.1:18080", "HTTPS_PROXY=http://198.18.0.1:18080",
		"http_proxy=http://198.18.0.1:18080", "https_proxy=http://198.18.0.1:18080",
	}
	for _, selected := range []bool{false, true} {
		for _, required := range []bool{false, true} {
			for _, present := range []bool{false, true} {
				name := "legacy"
				boot := "console=ttyS0"
				if selected {
					name, boot = "minimal", minimalPID1BootLine()
				}
				if required {
					name += "_required"
				}
				if present {
					name += "_network"
					boot += " " + minimalPID1NetworkLine
				}
				t.Run(name, func(t *testing.T) {
					if _, gotSelected, err := minimalcontrol.ParseBootCommandLine(boot); err != nil || gotSelected != selected {
						t.Fatal("invalid synthetic selection fixture")
					}
					var calls []string
					code := runGuestInitEntry(arguments, required, guestInitEntryDependencies{
						readBootCommandLine: func(context.Context) (string, error) { calls = append(calls, "read"); return boot + "\n", nil },
						configureNetwork: func(config l7NetworkBootConfig) error {
							calls = append(calls, "network")
							if config.InterfaceName() != "eth0" || config.IPv4Address() != "192.0.2.2/30" || config.IPv4Gateway() != "192.0.2.1" ||
								config.IPv6Address() != "fd00:7::2/126" || config.IPv6Gateway() != "fd00:7::1" || config.ProxyURL() != "http://198.18.0.1:18080" {
								t.Fatal("network expectations changed")
							}
							return nil
						},
						releaseAgentGate: func() int { calls = append(calls, "gate"); return 0 },
						superviseChild: func(args, environment []string) int {
							calls = append(calls, "child")
							if !reflect.DeepEqual(args, wantArguments) {
								t.Error("child arguments changed")
							}
							if present && !reflect.DeepEqual(environment, wantEnvironment) {
								t.Error("fixed L7 child environment changed")
							}
							if !present && environment != nil {
								t.Error("legacy nil child environment changed")
							}
							return 23
						},
					})
					wantCalls, wantCode := []string{"read"}, 127
					if present {
						wantCalls, wantCode = []string{"read", "network", "gate", "child"}, 23
					} else if !required {
						wantCalls, wantCode = []string{"read", "gate", "child"}, 23
					}
					if code != wantCode || !reflect.DeepEqual(calls, wantCalls) {
						t.Fatalf("code=%d calls=%v; want %d %v", code, calls, wantCode, wantCalls)
					}
					if !reflect.DeepEqual(arguments, wantArguments) {
						t.Error("caller arguments mutated")
					}
				})
			}
		}
	}
}

func TestMinimalPID1StopsAtFailedBoundary(t *testing.T) {
	for _, test := range []struct {
		name         string
		boot         string
		networkError error
		gateCode     int
		wantCalls    []string
		wantCode     int
	}{
		{"malformed_l7", minimalPID1BootLine() + " hal_l7_net_if=eth0", nil, 0, []string{"read"}, 127},
		{"network_failure", minimalPID1BootLine() + " " + minimalPID1NetworkLine, errors.New("synthetic network failure"), 0, []string{"read", "network"}, 127},
		{"gate_failure", minimalPID1BootLine() + " " + minimalPID1NetworkLine, nil, 19, []string{"read", "network", "gate"}, 19},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			code := runGuestInitEntry([]string{"/usr/bin/hal-guest-agent"}, true, guestInitEntryDependencies{
				readBootCommandLine: func(context.Context) (string, error) { calls = append(calls, "read"); return test.boot, nil },
				configureNetwork:    func(l7NetworkBootConfig) error { calls = append(calls, "network"); return test.networkError },
				releaseAgentGate:    func() int { calls = append(calls, "gate"); return test.gateCode },
				superviseChild:      func([]string, []string) int { calls = append(calls, "child"); return 0 },
			})
			if code != test.wantCode || !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("code=%d calls=%v; want %d %v", code, calls, test.wantCode, test.wantCalls)
			}
		})
	}
}

func TestMinimalPID1CountsWholeBootLineBeforeSideEffects(t *testing.T) {
	base := minimalPID1BootLine() + " " + minimalPID1NetworkLine
	for _, test := range []struct {
		name, tail string
		size       int
		valid      bool
	}{
		{"exact", "", 4096, true},
		{"exact_linux_newline", "\n", 4096, true},
		{"overflow", "", 4097, false},
		{"overflow_linux_newline", "\n", 4097, false},
		{"repeated_newline", "\n\n", 4096, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			boot := base + strings.Repeat(" ", test.size-len(base)-len(test.tail)) + test.tail
			var calls []string
			code := runGuestInitEntry([]string{"/usr/bin/hal-guest-agent"}, true, guestInitEntryDependencies{
				readBootCommandLine: func(context.Context) (string, error) { calls = append(calls, "read"); return boot, nil },
				configureNetwork:    func(l7NetworkBootConfig) error { calls = append(calls, "network"); return nil },
				releaseAgentGate:    func() int { calls = append(calls, "gate"); return 0 },
				superviseChild:      func([]string, []string) int { calls = append(calls, "child"); return 0 },
			})
			wantCalls, wantCode := []string{"read"}, 127
			if test.valid {
				wantCalls, wantCode = []string{"read", "network", "gate", "child"}, 0
			}
			if code != wantCode || !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("code=%d calls=%v; want %d %v", code, calls, wantCode, wantCalls)
			}
		})
	}
}
