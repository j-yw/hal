package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	exceptions := make([]NonPublicOriginException, 0, len(options.NonPublicOriginExceptions))
	for _, exception := range options.NonPublicOriginExceptions {
		normalized, err := normalizeOrigin(exception.Origin, false)
		if err != nil || !exception.Address.IsValid() {
			return nil, errors.New("non-public origin exception is invalid")
		}
		exceptions = append(exceptions, NonPublicOriginException{
			Origin:  normalized,
			Address: exception.Address.Unmap(),
		})
	}
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
		exceptions: exceptions,
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
	address = address.Unmap()
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
	if address.Is6() && netip.MustParsePrefix("2001::/23").Contains(address) {
		// The IANA IPv6 Special-Purpose Address Registry contains a broad
		// 2001::/23 umbrella with a small set of explicitly globally reachable
		// exceptions. Keep those usable rather than rejecting all special-use
		// space indiscriminately.
		for _, raw := range []string{
			"2001:1::1/128",
			"2001:1::2/128",
			"2001:1::3/128",
			"2001:3::/32",
			"2001:4:112::/48",
			"2001:20::/28",
			"2001:30::/28",
		} {
			if netip.MustParsePrefix(raw).Contains(address) {
				return false
			}
		}
		return true
	}
	prefixes := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		// Translation prefixes can encode non-public IPv4 destinations, so the
		// acquisition transport applies a conservative SSRF boundary even where
		// the prefix itself is globally reachable.
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"100::/64",
		"100:0:0:1::/64",
		"2001:db8::/32",
		"2002::/16",
		"3fff::/20",
		"5f00::/16",
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
	RootCAs                   *x509.CertPool
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
		Proxy:                  nil,
		DialContext:            policy.DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.RootCAs},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  DefaultRequestTimeout,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		MaxResponseHeaderBytes: DefaultMaxResponseHeaderBytes,
	}, nil
}

type ProductionClientOptions struct {
	Transport ProductionTransportOptions
	Timeout   time.Duration
}

func NewProductionClient(options ProductionClientOptions) (*http.Client, error) {
	transport, err := NewProductionTransport(options.Transport)
	if err != nil {
		return nil, err
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
	var registryErr *Error
	if errors.As(err, &registryErr) {
		return registryErr
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
