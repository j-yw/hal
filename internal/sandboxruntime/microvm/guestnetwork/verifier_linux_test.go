//go:build linux

package guestnetwork

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

type fakeLinuxNetworkIsolationBoundary struct {
	snapshot  linuxNetworkSnapshot
	snapshots []linuxNetworkSnapshot
	err       error
	probeErr  error
	order     []string
}

func (boundary *fakeLinuxNetworkIsolationBoundary) Inspect(context.Context, int64) (linuxNetworkSnapshot, error) {
	boundary.order = append(boundary.order, "inspect")
	if len(boundary.snapshots) != 0 {
		snapshot := boundary.snapshots[0]
		boundary.snapshots = boundary.snapshots[1:]
		return snapshot, boundary.err
	}
	return boundary.snapshot, boundary.err
}

func (boundary *fakeLinuxNetworkIsolationBoundary) ProbeProxy(context.Context, BootConfig) error {
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
	if strings.Join(boundary.order, ",") != "inspect,probe,inspect" {
		t.Fatalf("boundary order = %v", boundary.order)
	}
}

func TestL7LinuxNetworkIsolationVerifierRejectsPostProbeTopologyDrift(t *testing.T) {
	first := exactL7NetworkSnapshot(t)
	stale := exactL7NetworkSnapshot(t)
	stale.routes[0].flags = 0x201
	boundary := &fakeLinuxNetworkIsolationBoundary{snapshots: []linuxNetworkSnapshot{first, stale}}
	verifier, err := NewLinuxNetworkIsolationVerifier(LinuxNetworkIsolationVerifierOptions{
		BootConfig: mustL7BootConfig(t), Timeout: time.Second, boundary: boundary,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.VerifyNetworkIsolation(context.Background())
	if err == nil || result.Status != guestagent.IsolationProofStatusFailed {
		t.Fatalf("VerifyNetworkIsolation() = %#v, %v, want stale failure", result, err)
	}
	if strings.Join(boundary.order, ",") != "inspect,probe,inspect" {
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
			snapshot.routes = append(snapshot.routes, linuxNetworkRoute{interfaceName: "eth0", destination: netip.MustParsePrefix("203.0.113.0/24"), flags: 0x1})
		}},
		{name: "unknown interface route", mutate: func(snapshot *linuxNetworkSnapshot) {
			snapshot.routes = append(snapshot.routes, linuxNetworkRoute{interfaceName: "eth9", destination: netip.MustParsePrefix("203.0.113.0/24"), flags: 0x1})
		}},
		{name: "dead route flags", mutate: func(snapshot *linuxNetworkSnapshot) { snapshot.routes[0].flags = 0x201 }},
		{name: "wrong route metric", mutate: func(snapshot *linuxNetworkSnapshot) { snapshot.routes[3].metric = 512 }},
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
			if err == nil || result.Status != guestagent.IsolationProofStatusFailed || result.SingleInterface || result.StaticRoutes || result.ProxyReachable {
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
			if err == nil || result.Status != guestagent.IsolationProofStatusFailed || result.SingleInterface || result.StaticRoutes || result.ProxyReachable {
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

type blockingLinuxNetworkIsolationBoundary struct{}

func (blockingLinuxNetworkIsolationBoundary) Inspect(ctx context.Context, _ int64) (linuxNetworkSnapshot, error) {
	<-ctx.Done()
	return linuxNetworkSnapshot{}, ctx.Err()
}

func (blockingLinuxNetworkIsolationBoundary) ProbeProxy(context.Context, BootConfig) error {
	return nil
}

func TestL7LinuxNetworkIsolationVerifierOwnsAbsoluteTimeout(t *testing.T) {
	verifier, err := NewLinuxNetworkIsolationVerifier(LinuxNetworkIsolationVerifierOptions{
		BootConfig: mustL7BootConfig(t), Timeout: time.Millisecond, boundary: blockingLinuxNetworkIsolationBoundary{},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.VerifyNetworkIsolation(context.Background())
	if err == nil || result.Status != guestagent.IsolationProofStatusFailed {
		t.Fatalf("VerifyNetworkIsolation() = %#v, %v, want bounded failure", result, err)
	}
}

func TestL7LinuxNetworkInspectionFilesRejectSymlinkTypeOverflowAndCancellation(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "routes")
	if err := os.WriteFile(validPath, []byte("bounded"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "routes-link")
	if err := os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	overflowPath := filepath.Join(directory, "overflow")
	if err := os.WriteFile(overflowPath, []byte(strings.Repeat("x", 17)), 0600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, test := range []struct {
		name    string
		ctx     context.Context
		path    string
		maximum int64
	}{
		{name: "symlink", ctx: context.Background(), path: symlinkPath, maximum: 16},
		{name: "directory", ctx: context.Background(), path: directory, maximum: 16},
		{name: "overflow", ctx: context.Background(), path: overflowPath, maximum: 16},
		{name: "canceled", ctx: canceled, path: validPath, maximum: 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := readSecureLinuxNetworkFile(test.ctx, test.path, test.maximum)
			if err == nil || payload != nil {
				t.Fatalf("read = %q, %v, want fail closed", payload, err)
			}
			if strings.Contains(err.Error(), directory) {
				t.Fatalf("error leaked path: %v", err)
			}
		})
	}
}

func TestL7LinuxRouteParsersRecoverExactStaticShape(t *testing.T) {
	ipv4 := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 000200C0 00000000 0001 0 0 0 FCFFFFFF 0 0 0\n" +
		"eth0 00000000 010200C0 0003 0 0 0 00000000 0 0 0\n"
	ipv4Routes, err := parseLinuxIPv4Routes([]byte(ipv4))
	if err != nil || len(ipv4Routes) != 2 || ipv4Routes[0].destination != netip.MustParsePrefix("192.0.2.0/30") ||
		ipv4Routes[1].gateway != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("IPv4 routes = %#v, %v", ipv4Routes, err)
	}
	ipv6 := "fd000007000000000000000000000000 7e 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00400001 eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000007000000000000000000000001 00000400 00000000 00000000 00000003 eth0\n"
	ipv6Routes, err := parseLinuxIPv6Routes([]byte(ipv6))
	if err != nil || len(ipv6Routes) != 2 || ipv6Routes[0].destination != netip.MustParsePrefix("fd00:7::/126") ||
		ipv6Routes[0].flags != 0x00400001 || ipv6Routes[0].metric != 256 ||
		ipv6Routes[1].gateway != netip.MustParseAddr("fd00:7::1") || ipv6Routes[1].metric != 1024 {
		t.Fatalf("IPv6 routes = %#v, %v", ipv6Routes, err)
	}
}

func mustL7BootConfig(t *testing.T) BootConfig {
	t.Helper()
	config, present, err := ParseBootCommandLine("hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
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
			{interfaceName: "eth0", destination: netip.MustParsePrefix("192.0.2.0/30"), flags: 0x1},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("0.0.0.0/0"), gateway: netip.MustParseAddr("192.0.2.1"), flags: 0x3},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("fd00:7::/126"), flags: 0x1, metric: 256},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("::/0"), gateway: netip.MustParseAddr("fd00:7::1"), flags: 0x3, metric: 1024},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("fd00:7::2/128"), flags: 0x80200001},
			{interfaceName: "eth0", destination: netip.MustParsePrefix("ff00::/8"), flags: 0x1, metric: 256},
			{interfaceName: "lo", destination: netip.MustParsePrefix("::1/128"), flags: 0x80200001},
		},
	}
}
