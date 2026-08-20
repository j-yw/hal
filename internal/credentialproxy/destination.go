package credentialproxy

import (
	"context"
	"net"
	"net/netip"
)

const maxAzureResponsesResolvedAddresses = 64

func resolveAzureResponsesTarget(ctx context.Context, resolver AzureResponsesResolver, definition ServiceDefinition) (string, error) {
	if ctx == nil || resolver == nil {
		return "", ErrRouteUpstreamUnavailable
	}
	addresses, err := resolver(ctx, "ip", definition.SealedAuthority())
	if err != nil || len(addresses) == 0 || len(addresses) > maxAzureResponsesResolvedAddresses {
		return "", ErrRouteUpstreamUnavailable
	}
	seen := make(map[netip.Addr]bool, len(addresses))
	selected := netip.Addr{}
	for _, address := range addresses {
		address = address.Unmap()
		if unsafeAzureResponsesAddress(address) || seen[address] {
			if unsafeAzureResponsesAddress(address) {
				return "", ErrRouteUpstreamUnavailable
			}
			continue
		}
		seen[address] = true
		if !selected.IsValid() {
			selected = address
		}
	}
	if !selected.IsValid() {
		return "", ErrRouteUpstreamUnavailable
	}
	return net.JoinHostPort(selected.String(), "443"), nil
}

func unsafeAzureResponsesAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return true
	}
	if translated, ok := translatedAzureResponsesAddress(address); ok {
		return unsafeAzureResponsesAddress(translated)
	}
	if netip.MustParsePrefix("64:ff9b:1::/48").Contains(address) {
		return true
	}
	if address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() ||
		address.IsMulticast() || !address.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range azureResponsesSpecialUsePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func translatedAzureResponsesAddress(address netip.Addr) (netip.Addr, bool) {
	if !netip.MustParsePrefix("64:ff9b::/96").Contains(address) {
		return netip.Addr{}, false
	}
	raw := address.As16()
	return netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]}), true
}

var azureResponsesSpecialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fec0::/10"),
}
