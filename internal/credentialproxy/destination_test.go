package credentialproxy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestL8D3UnsafeAzureResponsesAddressRejectsSpecialUseAndTransitionAddresses(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{name: "AS112 IPv4", address: "192.31.196.1"},
		{name: "AMT IPv4", address: "192.52.193.1"},
		{name: "deprecated 6to4 relay", address: "192.88.99.1"},
		{name: "direct delegation AS112 IPv4", address: "192.175.48.1"},
		{name: "deprecated IPv4 compatible private", address: "::a00:8"},
		{name: "Teredo", address: "2001:0:4136:e378:8000:63bf:3fff:fdd2"},
		{name: "6to4 private embedding", address: "2002:a00:8::1"},
		{name: "dummy IPv6", address: "100:0:0:1::1"},
		{name: "IETF protocol assignment", address: "2001:1::1"},
		{name: "AMT IPv6", address: "2001:3::1"},
		{name: "AS112 IPv6", address: "2001:4:112::1"},
		{name: "deprecated ORCHID", address: "2001:10::1"},
		{name: "ORCHIDv2", address: "2001:20::1"},
		{name: "drone remote ID", address: "2001:30::1"},
		{name: "6to4 public embedding", address: "2002:5db8:d822::1"},
		{name: "direct delegation AS112 IPv6", address: "2620:4f:8000::1"},
		{name: "documentation IPv6", address: "3fff::1"},
		{name: "segment routing IPv6", address: "5f00::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !unsafeAzureResponsesAddress(netip.MustParseAddr(tt.address)) {
				t.Fatalf("unsafeAzureResponsesAddress(%q) = false, want special-use rejection", tt.address)
			}
		})
	}
}

func TestL8D3UnsafeAzureResponsesAddressPreservesPublicAddresses(t *testing.T) {
	for _, address := range []string{
		"93.184.216.34",
		"1.1.1.1",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
		"64:ff9b::5db8:d822",
	} {
		t.Run(address, func(t *testing.T) {
			if unsafeAzureResponsesAddress(netip.MustParseAddr(address)) {
				t.Fatalf("unsafeAzureResponsesAddress(%q) = true, want ordinary public address", address)
			}
		})
	}
}

func TestL8D3ResolveAzureResponsesTargetRejectsAnySpecialUseAnswer(t *testing.T) {
	definition := l8D3AzureResponsesDefinition(t)
	public := netip.MustParseAddr("93.184.216.34")
	for _, address := range []string{
		"192.88.99.1",
		"192.175.48.1",
		"::a00:8",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",
		"2002:a00:8::1",
	} {
		t.Run(address, func(t *testing.T) {
			unsafe := netip.MustParseAddr(address)
			resolver := func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{public, unsafe}, nil
			}
			if target, err := resolveAzureResponsesTarget(context.Background(), resolver, definition); !errors.Is(err, ErrRouteUpstreamUnavailable) || target != "" {
				t.Fatalf("mixed DNS answer = (%q, %v), want sanitized rejection", target, err)
			}
		})
	}
}
