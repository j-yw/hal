//go:build linux

package server

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

type fakeLinuxNetworkIsolationBoundary struct {
	snapshot linuxNetworkSnapshot
	err      error
	probeErr error
	order    []string
}

func (boundary *fakeLinuxNetworkIsolationBoundary) Inspect(context.Context, int64) (linuxNetworkSnapshot, error) {
	boundary.order = append(boundary.order, "inspect")
	return boundary.snapshot, boundary.err
}

func (boundary *fakeLinuxNetworkIsolationBoundary) ProbeProxy(context.Context, guestnetwork.BootConfig) error {
	boundary.order = append(boundary.order, "probe")
	return boundary.probeErr
}

func TestL7LinuxNetworkIsolationVerifierProvesExactTopologyThenProxy(t *testing.T) {
	expectation := mustL7BootConfig(t)
	boundary := &fakeLinuxNetworkIsolationBoundary{snapshot: exactL7NetworkSnapshot(t)}
	verifier, err := NewLinuxNetworkIsolationVerifier(LinuxNetworkIsolationVerifierOptions{
		BootConfig: expectation,
		Timeout:    time.Second,
		boundary:   boundary,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.VerifyNetworkIsolation(context.Background())
	if err != nil || result.Status != guestagent.IsolationProofStatusVerified ||
		!result.SingleInterface || !result.StaticRoutes || !result.ProxyReachable {
		t.Fatalf("VerifyNetworkIsolation() = %#v, %v", result, err)
	}
	if strings.Join(boundary.order, ",") != "inspect,probe" {
		t.Fatalf("boundary order = %v", boundary.order)
	}
}

func TestL7LinuxNetworkIsolationVerifierFailsClosedBeforeProxy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*linuxNetworkSnapshot)
	}{
		{name: "missing interface", mutate: func(snapshot *linuxNetworkSnapshot) { snapshot.interfaces = nil }},
		{name: "extra interface", mutate: func(snapshot *linuxNetworkSnapshot) {
			snapshot.interfaces = append(snapshot.interfaces, linuxNetworkInterface{name: "eth1", up: true})
		}},
		{name: "extra address", mutate: func(snapshot *linuxNetworkSnapshot) {
			snapshot.interfaces[1].addresses = append(snapshot.interfaces[1].addresses, netip.MustParsePrefix("198.51.100.2/30"))
		}},
		{name: "extra route", mutate: func(snapshot *linuxNetworkSnapshot) {
			snapshot.routes = append(snapshot.routes, linuxNetworkRoute{interfaceName: "eth0", destination: netip.MustParsePrefix("203.0.113.0/24")})
		}},
		{name: "dns configured", mutate: func(snapshot *linuxNetworkSnapshot) { snapshot.resolverConfigured = true }},
		{name: "partial route data", mutate: func(snapshot *linuxNetworkSnapshot) { snapshot.routes = snapshot.routes[:3] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := exactL7NetworkSnapshot(t)
			tt.mutate(&snapshot)
			boundary := &fakeLinuxNetworkIsolationBoundary{snapshot: snapshot}
			verifier, err := NewLinuxNetworkIsolationVerifier(LinuxNetworkIsolationVerifierOptions{
				BootConfig: mustL7BootConfig(t), Timeout: time.Second, boundary: boundary,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := verifier.VerifyNetworkIsolation(context.Background())
			if err == nil || result != (NetworkIsolationProofResult{}) {
				t.Fatalf("VerifyNetworkIsolation() = %#v, %v, want fail closed", result, err)
			}
			if strings.Join(boundary.order, ",") != "inspect" {
				t.Fatalf("unexpected boundary order: %v", boundary.order)
			}
		})
	}
}

func TestL7LinuxNetworkIsolationVerifierBoundsCancelsAndRedactsFailures(t *testing.T) {
	secret := errors.New("read /proc/net/route /home/alice token=ghp_secret endpoint=10.0.0.8:8080")
	for _, test := range []struct {
		name     string
		ctx      func() context.Context
		boundary *fakeLinuxNetworkIsolationBoundary
	}{
		{name: "inspection", ctx: context.Background, boundary: &fakeLinuxNetworkIsolationBoundary{err: secret}},
		{name: "proxy", ctx: context.Background, boundary: &fakeLinuxNetworkIsolationBoundary{snapshot: exactL7NetworkSnapshot(t), probeErr: secret}},
		{name: "canceled", ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }, boundary: &fakeLinuxNetworkIsolationBoundary{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewLinuxNetworkIsolationVerifier(LinuxNetworkIsolationVerifierOptions{
				BootConfig: mustL7BootConfig(t), Timeout: time.Second, boundary: test.boundary,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := verifier.VerifyNetworkIsolation(test.ctx())
			if err == nil || result != (NetworkIsolationProofResult{}) {
				t.Fatalf("VerifyNetworkIsolation() = %#v, %v, want failure", result, err)
			}
			for _, forbidden := range []string{"/proc/", "/home/alice", "ghp_secret", "10.0.0.8", "8080"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error leaked %q: %v", forbidden, err)
				}
			}
		})
	}
}

func mustL7BootConfig(t *testing.T) guestnetwork.BootConfig {
	t.Helper()
	config, present, err := guestnetwork.ParseBootCommandLine("hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
		"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.1:18080")
	if err != nil || !present {
		t.Fatalf("boot config = %#v, %t, %v", config, present, err)
	}
	return config
}

func exactL7NetworkSnapshot(t *testing.T) linuxNetworkSnapshot {
	t.Helper()
	return linuxNetworkSnapshot{
		interfaces: []linuxNetworkInterface{
			{name: "lo", up: true, loopback: true},
			{name: "eth0", up: true, addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/30"), netip.MustParsePrefix("fd00:7::2/126")}},
		},
		routes: []linuxNetworkRoute{
			{interfaceName: "eth0", destination: netip.MustParsePrefix("192.0.2.0/30")},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("0.0.0.0/0"), gateway: netip.MustParseAddr("192.0.2.1")},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("fd00:7::/126")},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("::/0"), gateway: netip.MustParseAddr("fd00:7::1")},
		},
	}
}
