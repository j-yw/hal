//go:build linux

package guestnetwork

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

const (
	defaultLinuxNetworkIsolationTimeout = 2 * time.Second
	maximumLinuxNetworkIsolationTimeout = 10 * time.Second
	maximumLinuxNetworkInspectionBytes  = int64(64 << 10)
)

var errLinuxNetworkIsolationUnverified = errors.New("guest network isolation is unverified")

type linuxNetworkIsolationVerifier struct {
	boot     BootConfig
	boundary linuxNetworkIsolationBoundary
	timeout  time.Duration
}

type liveLinuxNetworkIsolationBoundary struct{}

// NewLinuxNetworkIsolationVerifier creates the explicit L7 network proof
// adapter. Generic/L5 construction never calls this constructor.
func NewLinuxNetworkIsolationVerifier(options LinuxNetworkIsolationVerifierOptions) (NetworkIsolationVerifier, error) {
	if !options.BootConfig.Valid() {
		return nil, errLinuxNetworkIsolationUnverified
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultLinuxNetworkIsolationTimeout
	}
	if timeout < 0 || timeout > maximumLinuxNetworkIsolationTimeout {
		return nil, errLinuxNetworkIsolationUnverified
	}
	boundary := options.boundary
	if !configuredBoundary(boundary) {
		boundary = liveLinuxNetworkIsolationBoundary{}
	}
	return &linuxNetworkIsolationVerifier{boot: options.BootConfig, boundary: boundary, timeout: timeout}, nil
}

func (verifier *linuxNetworkIsolationVerifier) VerifyNetworkIsolation(ctx context.Context) (NetworkIsolationProofResult, error) {
	if verifier == nil || !verifier.boot.Valid() || !configuredBoundary(verifier.boundary) {
		return failedNetworkIsolation(errLinuxNetworkIsolationUnverified)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, verifier.timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return failedNetworkIsolation(err)
	}
	snapshot, err := verifier.boundary.Inspect(bounded, maximumLinuxNetworkInspectionBytes)
	if err != nil || !exactLinuxNetworkSnapshot(snapshot, verifier.boot) {
		return failedNetworkIsolation(errLinuxNetworkIsolationUnverified)
	}
	if err := bounded.Err(); err != nil {
		return failedNetworkIsolation(err)
	}
	if err := verifier.boundary.ProbeProxy(bounded, verifier.boot); err != nil {
		return failedNetworkIsolation(errLinuxNetworkIsolationUnverified)
	}
	if err := bounded.Err(); err != nil {
		return failedNetworkIsolation(err)
	}
	confirmed, err := verifier.boundary.Inspect(bounded, maximumLinuxNetworkInspectionBytes)
	if err != nil || !exactLinuxNetworkSnapshot(confirmed, verifier.boot) {
		return failedNetworkIsolation(errLinuxNetworkIsolationUnverified)
	}
	return NetworkIsolationProofResult{
		Status:          guestagent.IsolationProofStatusVerified,
		SingleInterface: true,
		StaticRoutes:    true,
		ProxyReachable:  true,
	}, nil
}

func failedNetworkIsolation(err error) (NetworkIsolationProofResult, error) {
	return NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusFailed}, err
}

func exactLinuxNetworkSnapshot(snapshot linuxNetworkSnapshot, boot BootConfig) bool {
	if snapshot.resolverConfigured {
		return false
	}
	var intended *linuxNetworkInterface
	nonLoopback := 0
	for index := range snapshot.interfaces {
		candidate := &snapshot.interfaces[index]
		if candidate.loopback {
			continue
		}
		nonLoopback++
		if candidate.name == boot.InterfaceName() {
			intended = candidate
		}
	}
	if nonLoopback != 1 || intended == nil || !intended.up || len(intended.addresses) != 2 ||
		!prefixSetEqual(intended.addresses, []netip.Prefix{boot.IPv4Prefix(), boot.IPv6Prefix()}) {
		return false
	}
	wantedRoutes := []linuxNetworkRoute{
		{interfaceName: boot.InterfaceName(), destination: boot.IPv4Prefix().Masked(), flags: 0x1},
		{interfaceName: boot.InterfaceName(), destination: netip.MustParsePrefix("0.0.0.0/0"), gateway: boot.IPv4GatewayAddr(), flags: 0x3},
		{interfaceName: boot.InterfaceName(), destination: boot.IPv6Prefix().Masked(), flags: 0x00400001, metric: 256},
		{interfaceName: boot.InterfaceName(), destination: netip.MustParsePrefix("::/0"), gateway: boot.IPv6GatewayAddr(), flags: 0x3, metric: 1024},
		{interfaceName: boot.InterfaceName(), destination: netip.PrefixFrom(boot.IPv6Prefix().Addr(), 128), flags: 0x80200001},
		{interfaceName: boot.InterfaceName(), destination: netip.MustParsePrefix("ff00::/8"), flags: 0x1, metric: 256},
	}
	actual := make([]linuxNetworkRoute, 0, len(snapshot.routes))
	for _, route := range snapshot.routes {
		switch {
		case route.interfaceName == boot.InterfaceName():
			actual = append(actual, route)
		case allowedLoopbackRoute(route):
		default:
			return false
		}
	}
	return routeSetEqual(actual, wantedRoutes)
}

func allowedLoopbackRoute(route linuxNetworkRoute) bool {
	if route.interfaceName != "lo" || route.gateway.IsValid() {
		return false
	}
	return (route.destination == netip.MustParsePrefix("127.0.0.0/8") && route.flags == 0x1 && route.metric == 0) ||
		(route.destination == netip.MustParsePrefix("::/0") && route.flags == 0x00200200 && route.metric == 0xffffffff) ||
		(route.destination == netip.MustParsePrefix("::1/128") && route.flags == 0x80200001 && route.metric == 0) ||
		(route.destination == netip.MustParsePrefix("ff00::/8") && route.flags == 0x1 && route.metric == 256)
}

func prefixSetEqual(actual, wanted []netip.Prefix) bool {
	if len(actual) != len(wanted) {
		return false
	}
	used := make([]bool, len(wanted))
	for _, item := range actual {
		matched := false
		for index, candidate := range wanted {
			if !used[index] && item == candidate {
				used[index], matched = true, true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func routeSetEqual(actual, wanted []linuxNetworkRoute) bool {
	if len(actual) != len(wanted) {
		return false
	}
	used := make([]bool, len(wanted))
	for _, item := range actual {
		matched := false
		for index, candidate := range wanted {
			if !used[index] && item.interfaceName == candidate.interfaceName &&
				item.destination == candidate.destination && item.gateway == candidate.gateway &&
				item.flags == candidate.flags && item.metric == candidate.metric {
				used[index], matched = true, true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (liveLinuxNetworkIsolationBoundary) Inspect(ctx context.Context, maximum int64) (linuxNetworkSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return linuxNetworkSnapshot{}, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
	}
	snapshot := linuxNetworkSnapshot{interfaces: make([]linuxNetworkInterface, 0, len(interfaces))}
	for _, item := range interfaces {
		if err := ctx.Err(); err != nil {
			return linuxNetworkSnapshot{}, err
		}
		addresses, err := item.Addrs()
		if err != nil {
			return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
		}
		current := linuxNetworkInterface{name: item.Name, up: item.Flags&net.FlagUp != 0, loopback: item.Flags&net.FlagLoopback != 0}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
			}
			current.addresses = append(current.addresses, prefix)
		}
		snapshot.interfaces = append(snapshot.interfaces, current)
	}
	ipv4, err := readSecureLinuxNetworkFile(ctx, "/proc/net/route", maximum)
	if err != nil {
		return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
	}
	ipv6, err := readSecureLinuxNetworkFile(ctx, "/proc/net/ipv6_route", maximum)
	if err != nil {
		return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
	}
	ipv4Routes, err := parseLinuxIPv4Routes(ipv4)
	if err != nil {
		return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
	}
	ipv6Routes, err := parseLinuxIPv6Routes(ipv6)
	if err != nil {
		return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
	}
	snapshot.routes = append(ipv4Routes, ipv6Routes...)
	resolver, err := readSecureLinuxNetworkFile(ctx, "/etc/resolv.conf", maximum)
	if err != nil {
		return linuxNetworkSnapshot{}, errLinuxNetworkIsolationUnverified
	}
	snapshot.resolverConfigured = len(resolver) != 0
	if err := ctx.Err(); err != nil {
		return linuxNetworkSnapshot{}, err
	}
	return snapshot, nil
}

func (liveLinuxNetworkIsolationBoundary) ProbeProxy(ctx context.Context, boot BootConfig) error {
	parsed, err := url.Parse(boot.ProxyURL())
	if err != nil || parsed.Host == "" {
		return errLinuxNetworkIsolationUnverified
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		return errLinuxNetworkIsolationUnverified
	}
	return connection.Close()
}

func readSecureLinuxNetworkFile(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if maximum < 1 || maximum > maximumLinuxNetworkInspectionBytes {
		return nil, errLinuxNetworkIsolationUnverified
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLinuxNetworkIsolationUnverified
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errLinuxNetworkIsolationUnverified
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errLinuxNetworkIsolationUnverified
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return nil, errLinuxNetworkIsolationUnverified
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return payload, nil
}

func parseLinuxIPv4Routes(payload []byte) ([]linuxNetworkRoute, error) {
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	if len(lines) < 1 || !strings.HasPrefix(lines[0], "Iface") {
		return nil, errLinuxNetworkIsolationUnverified
	}
	routes := make([]linuxNetworkRoute, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return nil, errLinuxNetworkIsolationUnverified
		}
		destination, err := parseLittleEndianIPv4(fields[1])
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		gateway, err := parseLittleEndianIPv4(fields[2])
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		maskAddress, err := parseLittleEndianIPv4(fields[7])
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		mask := net.IPMask(maskAddress.AsSlice())
		ones, bits := mask.Size()
		if bits != 32 || ones < 0 {
			return nil, errLinuxNetworkIsolationUnverified
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		metric, err := strconv.ParseUint(fields[6], 10, 32)
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		route := linuxNetworkRoute{interfaceName: fields[0], destination: netip.PrefixFrom(destination, ones).Masked(), flags: flags, metric: metric}
		if gateway != netip.IPv4Unspecified() {
			route.gateway = gateway
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func parseLittleEndianIPv4(value string) (netip.Addr, error) {
	if len(value) != 8 {
		return netip.Addr{}, errLinuxNetworkIsolationUnverified
	}
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return netip.Addr{}, errLinuxNetworkIsolationUnverified
	}
	return netip.AddrFrom4([4]byte{byte(parsed), byte(parsed >> 8), byte(parsed >> 16), byte(parsed >> 24)}), nil
}

func parseLinuxIPv6Routes(payload []byte) ([]linuxNetworkRoute, error) {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" {
		return nil, nil
	}
	routes := make([]linuxNetworkRoute, 0)
	for _, line := range strings.Split(trimmed, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 10 || fields[2] != strings.Repeat("0", 32) || fields[3] != "00" {
			return nil, errLinuxNetworkIsolationUnverified
		}
		destination, err := parseIPv6Hex(fields[0])
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		prefixBits, err := strconv.ParseUint(fields[1], 16, 8)
		if err != nil || prefixBits > 128 {
			return nil, errLinuxNetworkIsolationUnverified
		}
		gateway, err := parseIPv6Hex(fields[4])
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		metric, err := strconv.ParseUint(fields[5], 16, 32)
		if err != nil {
			return nil, errLinuxNetworkIsolationUnverified
		}
		route := linuxNetworkRoute{interfaceName: fields[9], destination: netip.PrefixFrom(destination, int(prefixBits)).Masked(), flags: flags, metric: metric}
		if gateway != netip.IPv6Unspecified() {
			route.gateway = gateway
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func parseIPv6Hex(value string) (netip.Addr, error) {
	if len(value) != 32 {
		return netip.Addr{}, errLinuxNetworkIsolationUnverified
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return netip.Addr{}, errLinuxNetworkIsolationUnverified
	}
	var bytes [16]byte
	copy(bytes[:], decoded)
	return netip.AddrFrom16(bytes), nil
}
