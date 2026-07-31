package l7network

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

// RuntimeReconciler is the exact-container boundary used only after restart.
// Stop must leave the inert workload quiesced while quarantine remains
// installed; Delete runs only after exact rule absence is verified.
type RuntimeReconciler interface {
	Stop(context.Context, rootlesspodman.NetworkTopologyTargetRequest) error
	Delete(context.Context, rootlesspodman.NetworkTopologyTargetRequest) error
}

type ReconcilerOptions struct {
	Identity                 rootlesspodman.NetworkTopologyIdentity
	NamespaceResolver        NamespaceResolver
	Rules                    RuleAdapter
	RawPacketVerifierFactory RawPacketVerifierFactory
	Runtime                  RuntimeReconciler
	GuestProxyAddress        string
	ProxyPort                uint16
	TableName                string
	CleanupTimeout           time.Duration
}

type Reconciler struct {
	mu      sync.Mutex
	options ReconcilerOptions
	pending *reconcileState
	retired reconcileTargetIdentity
	done    bool
}

type reconcileState struct {
	target           reconcileTargetIdentity
	resolution       NamespaceResolution
	expected         linuxrules.ExpectedRuleSet
	validationFailed bool
	quarantined      bool
	stopped          bool
	rulesCleaned     bool
	closed           bool
}

type reconcileTargetIdentity struct{ id, name, provider, driver, runtimeID string }

func NewReconciler(options ReconcilerOptions) (*Reconciler, error) {
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = defaultCleanupTimeout
	}
	if !validIdentity(options.Identity) || options.NamespaceResolver == nil || options.Rules == nil ||
		options.RawPacketVerifierFactory == nil || options.Runtime == nil || options.ProxyPort == 0 || !safeNFTName(options.TableName) ||
		options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, ErrInvalidConfiguration
	}
	guestAddress, err := netip.ParseAddr(options.GuestProxyAddress)
	if err != nil || guestAddress.IsUnspecified() || guestAddress.IsLoopback() || guestAddress.IsMulticast() {
		return nil, ErrInvalidConfiguration
	}
	return &Reconciler{options: options}, nil
}

// Reconcile never reconstructs active proof. It reopens only the exact
// full-ID, label-bound Podman namespace, quarantines the exact owned table,
// stops the workload, proves rule absence, closes descriptors, and deletes the
// exact container. A real daemon restart has already closed its process-owned
// policy-proxy listener; an in-process loss remains Session cleanup work.
func (r *Reconciler) Reconcile(_ context.Context, request rootlesspodman.NetworkTopologyTargetRequest) error {
	if r == nil || request.Identity != r.options.Identity {
		return ErrIdentityMismatch
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	targetIdentity := reconcileTargetFromRequest(request)
	if targetIdentity.id == "" || (r.done && r.retired != targetIdentity) || (r.pending != nil && r.pending.target != targetIdentity) {
		return ErrIdentityMismatch
	}
	if r.done {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.options.CleanupTimeout)
	defer cancel()
	if r.pending == nil {
		rawPacketVerifier, err := r.options.RawPacketVerifierFactory(request)
		if err != nil || rawPacketVerifier == nil {
			return ErrNamespaceUnverified
		}
		resolution, err := r.options.NamespaceResolver.Resolve(ctx, request)
		if resolution.Close == nil {
			return ErrNamespaceUnverified
		}
		if err != nil {
			state := &reconcileState{target: targetIdentity, resolution: resolution, validationFailed: true}
			r.pending = state
			if closeErr := state.resolution.Close.Close(); closeErr != nil {
				return errors.Join(ErrNamespaceUnverified, ErrCleanupIncomplete)
			}
			state.closed = true
			r.pending = nil
			return ErrNamespaceUnverified
		}
		correlation := correlationFromIdentity(r.options.Identity)
		expected, err := linuxrules.NewExpectedRuleSet(linuxrules.RuleSetConfig{Correlation: correlation,
			Profile: linuxrules.RuleProfileWorkloadOutput, Namespace: resolution.Namespace, TableName: r.options.TableName,
			InterfaceName: resolution.InterfaceName, ProxyAddress: r.options.GuestProxyAddress, ProxyPort: r.options.ProxyPort,
			RawPacketIsolation: rawPacketVerifier, WorkloadIPv6Address: resolution.WorkloadIPv6Address,
			GatewayIPv6Address: resolution.GatewayIPv6Address, IPv6PrefixBits: resolution.IPv6PrefixBits})
		if err != nil {
			state := &reconcileState{target: targetIdentity, resolution: resolution, validationFailed: true}
			r.pending = state
			if closeErr := state.resolution.Close.Close(); closeErr != nil {
				return errors.Join(ErrNamespaceUnverified, ErrCleanupIncomplete)
			}
			state.closed = true
			r.pending = nil
			return ErrNamespaceUnverified
		}
		r.pending = &reconcileState{target: targetIdentity, resolution: resolution, expected: expected}
	}
	state := r.pending
	if state.validationFailed {
		if !state.closed {
			if err := state.resolution.Close.Close(); err != nil {
				return errors.Join(ErrNamespaceUnverified, ErrCleanupIncomplete)
			}
			state.closed = true
		}
		r.pending = nil
		return ErrNamespaceUnverified
	}
	if !state.quarantined {
		if err := r.options.Rules.Quarantine(ctx, state.expected); err != nil {
			return errors.Join(ErrQuarantineFailed, ErrCleanupIncomplete)
		}
		state.quarantined = true
	}
	if !state.stopped {
		if err := r.options.Runtime.Stop(ctx, request); err != nil {
			return ErrCleanupIncomplete
		}
		state.stopped = true
	}
	if !state.rulesCleaned {
		if err := r.options.Rules.Cleanup(ctx, state.expected); err != nil {
			return ErrCleanupIncomplete
		}
		state.rulesCleaned = true
	}
	if !state.closed {
		if err := state.resolution.Close.Close(); err != nil {
			return ErrCleanupIncomplete
		}
		state.closed = true
	}
	if err := r.options.Runtime.Delete(ctx, request); err != nil {
		return ErrCleanupIncomplete
	}
	r.pending = nil
	r.retired = targetIdentity
	r.done = true
	return nil
}

func reconcileTargetFromRequest(request rootlesspodman.NetworkTopologyTargetRequest) reconcileTargetIdentity {
	target := request.Target
	if !safeID(target.ID) || !safeID(target.Name) || target.ID != target.Runtime.RuntimeID || target.Runtime.Driver != rootlesspodman.DriverID {
		return reconcileTargetIdentity{}
	}
	return reconcileTargetIdentity{id: target.ID, name: target.Name, provider: target.Provider, driver: target.Runtime.Driver, runtimeID: target.Runtime.RuntimeID}
}
