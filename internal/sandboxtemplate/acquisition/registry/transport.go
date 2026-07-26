package registry

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type NonPublicOriginException struct {
	Origin  string
	Address netip.Addr
}

type DialPolicyOptions struct {
	LookupNetIP               func(context.Context, string) ([]netip.Addr, error)
	DialContext               func(context.Context, string, string) (net.Conn, error)
	NonPublicOriginExceptions []NonPublicOriginException
}

type DialPolicy struct {
	lookup     func(context.Context, string) ([]netip.Addr, error)
	dial       func(context.Context, string, string) (net.Conn, error)
	exceptions []NonPublicOriginException
}

func NewDialPolicy(options DialPolicyOptions) (*DialPolicy, error) {
	lookup := options.LookupNetIP
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	dial := options.DialContext
	if dial == nil {
		netDialer := &net.Dialer{Timeout: DefaultRequestTimeout, KeepAlive: 30 * time.Second}
		dial = netDialer.DialContext
	}
	return &DialPolicy{
		lookup:     lookup,
		dial:       dial,
		exceptions: append([]NonPublicOriginException(nil), options.NonPublicOriginExceptions...),
	}, nil
}

func (p *DialPolicy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if p == nil {
		return nil, coded(ErrorCodeAddressRejected, nil)
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, coded(ErrorCodeAddressRejected, err)
	}
	addresses, err := p.lookup(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, requestOrRegistryError(ctx, err)
	}
	for _, resolved := range addresses {
		if err := ValidateDialAddress(resolved, p.addressExcepted(host, port, resolved)); err != nil {
			return nil, err
		}
	}
	selected := addresses[0]
	return p.dial(ctx, network, net.JoinHostPort(selected.String(), port))
}

func (p *DialPolicy) addressExcepted(host, port string, address netip.Addr) bool {
	for _, exception := range p.exceptions {
		parsed, err := url.Parse(exception.Origin)
		if err != nil {
			continue
		}
		if parsed.Hostname() == host && effectivePort(parsed) == port && parsed.Scheme == "https" && exception.Address == address {
			return true
		}
	}
	return false
}

func ValidateDialAddress(address netip.Addr, allowNonPublic bool) error {
	if !address.IsValid() {
		return coded(ErrorCodeAddressRejected, nil)
	}
	address = address.Unmap()
	if allowNonPublic {
		return nil
	}
	if !address.IsGlobalUnicast() ||
		address.IsLoopback() ||
		address.IsPrivate() ||
		address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() ||
		address.IsMulticast() ||
		address.IsUnspecified() ||
		isReservedAddress(address) {
		return coded(ErrorCodeAddressRejected, nil)
	}
	return nil
}

func ValidateOriginAddress(origin string, address netip.Addr, exceptions []NonPublicOriginException) error {
	normalized, err := normalizeOrigin(origin, false)
	if err != nil {
		return coded(ErrorCodeAddressRejected, err)
	}
	for _, exception := range exceptions {
		exceptionOrigin, originErr := normalizeOrigin(exception.Origin, false)
		if originErr == nil && exceptionOrigin == normalized && exception.Address == address {
			return ValidateDialAddress(address, true)
		}
	}
	return ValidateDialAddress(address, false)
}

func isReservedAddress(address netip.Addr) bool {
	prefixes := []string{
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"2001:db8::/32",
	}
	for _, raw := range prefixes {
		if netip.MustParsePrefix(raw).Contains(address) {
			return true
		}
	}
	return false
}

type ProductionTransportOptions struct {
	DialPolicy                *DialPolicy
	NonPublicOriginExceptions []NonPublicOriginException
}

func NewProductionTransport(options ProductionTransportOptions) (*http.Transport, error) {
	policy := options.DialPolicy
	if policy == nil {
		var err error
		policy, err = NewDialPolicy(DialPolicyOptions{
			NonPublicOriginExceptions: options.NonPublicOriginExceptions,
		})
		if err != nil {
			return nil, err
		}
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           policy.DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: DefaultRequestTimeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
	}, nil
}

func effectivePort(parsed *url.URL) string {
	if parsed.Port() != "" {
		return parsed.Port()
	}
	if parsed.Scheme == "https" {
		return "443"
	}
	return "80"
}

func requestContextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return coded(ErrorCodeRequestCanceled, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return coded(ErrorCodeRequestTimeout, context.DeadlineExceeded)
	}
	return coded(ErrorCodeRegistryUnavailable, err)
}

func requestOrRegistryError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return requestContextError(ctx.Err())
	}
	return requestContextError(err)
}

func originForURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return "", coded(ErrorCodeRedirectRejected, nil)
	}
	if strings.ContainsAny(parsed.Host, `%\`) {
		return "", coded(ErrorCodeRedirectRejected, nil)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}
