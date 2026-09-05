// Package guestnetwork owns the live-only L7 guest boot expectation. Its
// values come only from the immutable kernel command line and are never a
// durable or wire contract.
package guestnetwork

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const MaximumBootCommandLineBytes int64 = 4 << 10

var ErrInvalidBootConfig = errors.New("L7 guest network bootstrap is invalid")

// BootConfig is a validated, canonical, live-only network expectation.
// Private fields prevent accidental JSON persistence.
type BootConfig struct {
	interfaceName string
	ipv4Address   netip.Prefix
	ipv4Gateway   netip.Addr
	ipv6Address   netip.Prefix
	ipv6Gateway   netip.Addr
	proxyURL      string
}

func (config BootConfig) InterfaceName() string { return config.interfaceName }
func (config BootConfig) IPv4Address() string   { return config.ipv4Address.String() }
func (config BootConfig) IPv4Gateway() string   { return config.ipv4Gateway.String() }
func (config BootConfig) IPv6Address() string   { return config.ipv6Address.String() }
func (config BootConfig) IPv6Gateway() string   { return config.ipv6Gateway.String() }
func (config BootConfig) ProxyURL() string      { return config.proxyURL }

func (config BootConfig) IPv4Prefix() netip.Prefix    { return config.ipv4Address }
func (config BootConfig) IPv4GatewayAddr() netip.Addr { return config.ipv4Gateway }
func (config BootConfig) IPv6Prefix() netip.Prefix    { return config.ipv6Address }
func (config BootConfig) IPv6GatewayAddr() netip.Addr { return config.ipv6Gateway }

func (config BootConfig) Valid() bool {
	return config.interfaceName != "" && config.ipv4Address.IsValid() && config.ipv4Gateway.IsValid() &&
		config.ipv6Address.IsValid() && config.ipv6Gateway.IsValid() && config.proxyURL != ""
}

// MarshalJSON makes accidental serialization explicitly data-minimized.
func (config BootConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{}{})
}

// ParseBootCommandLine validates the complete fixed L7 kernel-argument set.
func ParseBootCommandLine(commandLine string) (BootConfig, bool, error) {
	if int64(len(commandLine)) > MaximumBootCommandLineBytes || strings.IndexByte(commandLine, 0) >= 0 {
		return BootConfig{}, strings.Contains(commandLine, "hal_l7_"), ErrInvalidBootConfig
	}
	required := []string{
		"hal_l7_net_if", "hal_l7_ipv4", "hal_l7_ipv4_gateway",
		"hal_l7_ipv6", "hal_l7_ipv6_gateway", "hal_l7_proxy",
	}
	values := make(map[string]string, len(required))
	present := false
	for _, field := range strings.Fields(commandLine) {
		name, value, ok := strings.Cut(field, "=")
		if !strings.HasPrefix(name, "hal_l7_") {
			continue
		}
		present = true
		if !ok || value == "" || !contains(required, name) {
			return BootConfig{}, true, ErrInvalidBootConfig
		}
		if _, duplicate := values[name]; duplicate {
			return BootConfig{}, true, ErrInvalidBootConfig
		}
		values[name] = value
	}
	if !present {
		return BootConfig{}, false, nil
	}
	for _, name := range required {
		if values[name] == "" {
			return BootConfig{}, true, ErrInvalidBootConfig
		}
	}
	if !safeInterfaceName(values["hal_l7_net_if"]) {
		return BootConfig{}, true, ErrInvalidBootConfig
	}
	ipv4, ipv4Gateway, err := parseAddressPair(values["hal_l7_ipv4"], values["hal_l7_ipv4_gateway"], false)
	if err != nil {
		return BootConfig{}, true, ErrInvalidBootConfig
	}
	ipv6, ipv6Gateway, err := parseAddressPair(values["hal_l7_ipv6"], values["hal_l7_ipv6_gateway"], true)
	if err != nil {
		return BootConfig{}, true, ErrInvalidBootConfig
	}
	proxy, err := parseProxyURL(values["hal_l7_proxy"])
	if err != nil {
		return BootConfig{}, true, ErrInvalidBootConfig
	}
	return BootConfig{
		interfaceName: values["hal_l7_net_if"],
		ipv4Address:   ipv4, ipv4Gateway: ipv4Gateway,
		ipv6Address: ipv6, ipv6Gateway: ipv6Gateway,
		proxyURL: proxy,
	}, true, nil
}

func parseAddressPair(address, gateway string, ipv6 bool) (netip.Prefix, netip.Addr, error) {
	prefix, err := netip.ParsePrefix(address)
	wantBits := 30
	if ipv6 {
		wantBits = 126
	}
	if err != nil || prefix.Bits() != wantBits || prefix.Addr().Is6() != ipv6 ||
		prefix.Addr().Zone() != "" || !usableAddress(prefix.Addr()) {
		return netip.Prefix{}, netip.Addr{}, ErrInvalidBootConfig
	}
	prefix = netip.PrefixFrom(prefix.Addr(), prefix.Bits())
	parsedGateway, err := netip.ParseAddr(gateway)
	if err != nil || parsedGateway.Is6() != ipv6 || parsedGateway.Zone() != "" || !usableAddress(parsedGateway) ||
		!prefix.Contains(parsedGateway) || parsedGateway == prefix.Addr() {
		return netip.Prefix{}, netip.Addr{}, ErrInvalidBootConfig
	}
	network := prefix.Masked().Addr()
	if prefix.Addr() == network || parsedGateway == network ||
		(!ipv6 && (isIPv4Broadcast(prefix, prefix.Addr()) || isIPv4Broadcast(prefix, parsedGateway))) {
		return netip.Prefix{}, netip.Addr{}, ErrInvalidBootConfig
	}
	return prefix, parsedGateway, nil
}

func isIPv4Broadcast(prefix netip.Prefix, address netip.Addr) bool {
	base := prefix.Masked().Addr().As4()
	base[3] |= byte((1 << uint(32-prefix.Bits())) - 1)
	return address == netip.AddrFrom4(base)
}

func parseProxyURL(value string) (string, error) {
	if len(value) > 256 || strings.IndexFunc(value, func(char rune) bool { return char <= ' ' || char == 0x7f }) >= 0 {
		return "", ErrInvalidBootConfig
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrInvalidBootConfig
	}
	host, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || host.Zone() != "" || !usableAddress(host) || host.IsPrivate() {
		return "", ErrInvalidBootConfig
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", ErrInvalidBootConfig
	}
	hostText := host.String()
	if host.Is6() {
		hostText = "[" + hostText + "]"
	}
	canonical := "http://" + hostText + ":" + strconv.Itoa(port)
	if value != canonical {
		return "", ErrInvalidBootConfig
	}
	return canonical, nil
}

func usableAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsLoopback() &&
		!address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified()
}

func safeInterfaceName(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 15 {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case char == '_', char == '-', char == '.':
		default:
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
