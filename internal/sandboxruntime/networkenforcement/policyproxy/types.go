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
		out.MaxConcurrent = 64
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
		limits.MaxResponseHeaderBytes > 0 &&
		limits.MaxRequestBodyBytes > 0 &&
		limits.MaxResponseBodyBytes > 0 &&
		limits.MaxConnectBytes > 0 &&
		limits.MaxResolvedAddresses > 0 &&
		limits.MaxConcurrent > 0 &&
		limits.ReadHeaderTimeout > 0 &&
		limits.ReadTimeout > 0 &&
		limits.WriteTimeout > 0 &&
		limits.IdleTimeout > 0 &&
		limits.RequestTimeout > 0 &&
		limits.ConnectTimeout > 0 &&
		limits.ShutdownTimeout > 0
}
