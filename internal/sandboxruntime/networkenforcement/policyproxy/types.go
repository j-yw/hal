// Package policyproxy provides the explicitly constructed L6 HTTP/CONNECT
// listener. Runtime topology and firewall wiring remain outside this package.
package policyproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

var (
	// ErrUnsupported is returned on platforms without the Linux listener
	// ownership implementation.
	ErrUnsupported = errors.New("production policy proxy unsupported")
	// ErrInvalidConfig identifies invalid bounded listener configuration
	// without exposing a rejected address or policy value.
	ErrInvalidConfig = errors.New("production policy proxy invalid configuration")
)

const (
	maxHeaderBytes          = 1 << 20
	maxResponseHeaderBytes  = 1 << 20
	maxRequestBodyBytes     = 16 << 20
	maxResponseBodyBytes    = 64 << 20
	maxConnectBytes         = 64 << 20
	maxResolvedAddresses    = 64
	maxConcurrentRequests   = 1024
	maxAggregateBufferBytes = 384 << 20
	maxConfiguredTimeout    = 10 * time.Minute
	// Go's MIME header parser accounts for roughly 200 bytes of map overhead
	// per field. A minimal valid wire field is only four bytes, so reserve 64x
	// the wire limit for parsed request and response header working sets.
	parsedHeaderAggregateMultiplier int64 = 64
)

// ResolverFunc resolves one policy-approved host. Returned addresses are
// revalidated before any dial.
type ResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

// DialFunc dials an already validated numeric address.
type DialFunc func(context.Context, string, string) (net.Conn, error)

// Limits bounds all listener-owned protocol and lifecycle resources.
type Limits struct {
	MaxHeaderBytes         int
	MaxResponseHeaderBytes int64
	MaxRequestBodyBytes    int64
	MaxResponseBodyBytes   int64
	MaxConnectBytes        int64
	MaxResolvedAddresses   int
	MaxConcurrent          int
	ReadHeaderTimeout      time.Duration
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	IdleTimeout            time.Duration
	RequestTimeout         time.Duration
	ConnectTimeout         time.Duration
	ShutdownTimeout        time.Duration
}

// Config contains live-only listener dependencies and validation-only policy.
// ListenAddress and all dependency errors are excluded from durable contracts.
type Config struct {
	Policy        networkenforcement.PolicyProxyPolicyInput
	ListenAddress string
	Resolver      ResolverFunc
	DialContext   DialFunc
	// DecisionSink must return without blocking. Panics are isolated from
	// enforcement; callers that persist records own their bounded queue.
	DecisionSink func(networkenforcement.PolicyProxyDecisionLogRecord)
	Limits       Limits
}

func normalizeLimits(input Limits) Limits {
	out := input
	if out.MaxHeaderBytes == 0 {
		out.MaxHeaderBytes = 32 << 10
	}
	if out.MaxRequestBodyBytes == 0 {
		out.MaxRequestBodyBytes = 1 << 20
	}
	if out.MaxResponseHeaderBytes == 0 {
		out.MaxResponseHeaderBytes = 32 << 10
	}
	if out.MaxResponseBodyBytes == 0 {
		out.MaxResponseBodyBytes = 4 << 20
	}
	if out.MaxConnectBytes == 0 {
		out.MaxConnectBytes = 4 << 20
	}
	if out.MaxResolvedAddresses == 0 {
		out.MaxResolvedAddresses = 16
	}
	if out.MaxConcurrent == 0 {
		out.MaxConcurrent = 32
	}
	if out.ReadHeaderTimeout == 0 {
		out.ReadHeaderTimeout = 5 * time.Second
	}
	if out.ReadTimeout == 0 {
		out.ReadTimeout = 30 * time.Second
	}
	if out.WriteTimeout == 0 {
		out.WriteTimeout = 30 * time.Second
	}
	if out.IdleTimeout == 0 {
		out.IdleTimeout = 30 * time.Second
	}
	if out.RequestTimeout == 0 {
		out.RequestTimeout = 30 * time.Second
	}
	if out.ConnectTimeout == 0 {
		out.ConnectTimeout = 30 * time.Second
	}
	if out.ShutdownTimeout == 0 {
		out.ShutdownTimeout = 5 * time.Second
	}
	return out
}

func validLimits(limits Limits) bool {
	return limits.MaxHeaderBytes > 0 &&
		limits.MaxHeaderBytes <= maxHeaderBytes &&
		limits.MaxResponseHeaderBytes > 0 &&
		limits.MaxResponseHeaderBytes <= maxResponseHeaderBytes &&
		limits.MaxRequestBodyBytes > 0 &&
		limits.MaxRequestBodyBytes <= maxRequestBodyBytes &&
		limits.MaxResponseBodyBytes > 0 &&
		limits.MaxResponseBodyBytes <= maxResponseBodyBytes &&
		limits.MaxConnectBytes > 0 &&
		limits.MaxConnectBytes <= maxConnectBytes &&
		limits.MaxResolvedAddresses > 0 &&
		limits.MaxResolvedAddresses <= maxResolvedAddresses &&
		limits.MaxConcurrent > 0 &&
		limits.MaxConcurrent <= maxConcurrentRequests &&
		validAggregateBufferLimit(limits) &&
		limits.ReadHeaderTimeout > 0 &&
		limits.ReadHeaderTimeout <= maxConfiguredTimeout &&
		limits.ReadTimeout > 0 &&
		limits.ReadTimeout <= maxConfiguredTimeout &&
		limits.WriteTimeout > 0 &&
		limits.WriteTimeout <= maxConfiguredTimeout &&
		limits.IdleTimeout > 0 &&
		limits.IdleTimeout <= maxConfiguredTimeout &&
		limits.RequestTimeout > 0 &&
		limits.RequestTimeout <= maxConfiguredTimeout &&
		limits.ConnectTimeout > 0 &&
		limits.ConnectTimeout <= maxConfiguredTimeout &&
		limits.ShutdownTimeout > 0 &&
		limits.ShutdownTimeout <= maxConfiguredTimeout
}

func validAggregateBufferLimit(limits Limits) bool {
	perRequest := int64(0)
	for _, limit := range []int64{
		int64(limits.MaxHeaderBytes),
		limits.MaxResponseHeaderBytes,
	} {
		if limit <= 0 || limit > maxAggregateBufferBytes/parsedHeaderAggregateMultiplier {
			return false
		}
		workingSet := limit * parsedHeaderAggregateMultiplier
		if perRequest > maxAggregateBufferBytes-workingSet {
			return false
		}
		perRequest += workingSet
	}
	for _, limit := range []int64{
		limits.MaxRequestBodyBytes,
		limits.MaxResponseBodyBytes,
	} {
		if limit <= 0 || perRequest <= 0 || perRequest > maxAggregateBufferBytes-limit {
			return false
		}
		perRequest += limit
	}
	return limits.MaxConcurrent > 0 &&
		int64(limits.MaxConcurrent) <= maxAggregateBufferBytes/perRequest
}
