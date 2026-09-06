package guestnetwork

import (
	"context"
	"net/netip"
	"reflect"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

// Alias the existing guest-agent proof contract; this package adds no wire or
// durable representation of its own.
type NetworkIsolationVerifier = server.NetworkIsolationVerifier
type NetworkIsolationProofResult = server.NetworkIsolationProofResult

// LinuxNetworkIsolationVerifierOptions configures the explicit L7-only live
// verifier. BootConfig must be the validated immutable guest boot handoff.
type LinuxNetworkIsolationVerifierOptions struct {
	BootConfig BootConfig
	Timeout    time.Duration
	boundary   linuxNetworkIsolationBoundary
}

type linuxNetworkIsolationBoundary interface {
	Inspect(context.Context, int64) (linuxNetworkSnapshot, error)
	ProbeProxy(context.Context, BootConfig) error
}

type linuxNetworkSnapshot struct {
	interfaces         []linuxNetworkInterface
	routes             []linuxNetworkRoute
	resolverConfigured bool
}

type linuxNetworkInterface struct {
	name      string
	up        bool
	loopback  bool
	addresses []netip.Prefix
}

type linuxNetworkRoute struct {
	interfaceName string
	destination   netip.Prefix
	gateway       netip.Addr
	flags         uint64
	metric        uint64
}

func configuredBoundary(value linuxNetworkIsolationBoundary) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}
