package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/sshrelay"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const l8JobCredentialSSHRelayValuePlaceholder = "[firecracker-l8-job-credential-ssh-relay]"

var (
	ErrL8JobCredentialSSHRelayInvalid       = errors.New("Firecracker L8 SSH-agent credential activator invalid")
	ErrL8JobCredentialSSHRelayUnavailable   = errors.New("Firecracker L8 SSH-agent credential activator unavailable")
	ErrL8JobCredentialSSHRelaySerialization = errors.New("Firecracker L8 SSH-agent credential activator serialization denied")
)

type l8JobCredentialSSHRelayRegistry interface {
	Acquire(context.Context, sshrelay.AcquireRequest) (sshrelay.Lease, error)
}

type l8JobCredentialSSHRelayLiveValue struct{}

func (l8JobCredentialSSHRelayLiveValue) MarshalJSON() ([]byte, error) {
	return nil, ErrL8JobCredentialSSHRelaySerialization
}
func (l8JobCredentialSSHRelayLiveValue) MarshalText() ([]byte, error) {
	return nil, ErrL8JobCredentialSSHRelaySerialization
}
func (l8JobCredentialSSHRelayLiveValue) MarshalBinary() ([]byte, error) {
	return nil, ErrL8JobCredentialSSHRelaySerialization
}
func (l8JobCredentialSSHRelayLiveValue) UnmarshalJSON([]byte) error {
	return ErrL8JobCredentialSSHRelaySerialization
}
func (l8JobCredentialSSHRelayLiveValue) UnmarshalText([]byte) error {
	return ErrL8JobCredentialSSHRelaySerialization
}
func (l8JobCredentialSSHRelayLiveValue) UnmarshalBinary([]byte) error {
	return ErrL8JobCredentialSSHRelaySerialization
}
func (l8JobCredentialSSHRelayLiveValue) String() string {
	return l8JobCredentialSSHRelayValuePlaceholder
}
func (l8JobCredentialSSHRelayLiveValue) GoString() string {
	return l8JobCredentialSSHRelayValuePlaceholder
}
func (l8JobCredentialSSHRelayLiveValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(l8JobCredentialSSHRelayValuePlaceholder))
}

// ProductionL8JobCredentialSSHRelayActivator is the explicit, default-off host
// SSH-agent credential activator. It wraps one injected daemon-local sshrelay
// registry and never opens ambient agents.
type ProductionL8JobCredentialSSHRelayActivator struct {
	l8JobCredentialSSHRelayLiveValue
	registry l8JobCredentialSSHRelayRegistry
	config   sshrelay.ConfigIdentity
}

type productionL8JobCredentialSSHRelayHandle struct {
	l8JobCredentialSSHRelayLiveValue
	mu       sync.Mutex
	lease    sshrelay.Lease
	config   sshrelay.ConfigIdentity
	policyID string
	revision uint64
}

// NewProductionL8JobCredentialSSHRelayActivator constructs the production
// SSH-agent activator. It is never invoked by sandboxd, run, auto, factory,
// worker, or NewProductionL8JobCredentialRuntime unless injected.
func NewProductionL8JobCredentialSSHRelayActivator(registry *sshrelay.Registry, config sshrelay.ConfigIdentity) (*ProductionL8JobCredentialSSHRelayActivator, error) {
	return newProductionL8JobCredentialSSHRelayActivator(registry, config)
}

func newProductionL8JobCredentialSSHRelayActivator(registry l8JobCredentialSSHRelayRegistry, config sshrelay.ConfigIdentity) (*ProductionL8JobCredentialSSHRelayActivator, error) {
	if l8JobCredentialRuntimeValueIsNil(registry) || !sshrelay.ConfigIdentityEqual(config, config) {
		return nil, ErrL8JobCredentialSSHRelayInvalid
	}
	return &ProductionL8JobCredentialSSHRelayActivator{registry: registry, config: config}, nil
}

func (activator *ProductionL8JobCredentialSSHRelayActivator) Activate(ctx context.Context, identity sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest) (handle l8JobCredentialSSHRelayHandle, err error) {
	defer func() {
		if recover() != nil {
			if handle == nil {
				err = ErrL8JobCredentialSSHRelayUnavailable
			} else if err == nil {
				err = ErrL8JobCredentialSSHRelayUnavailable
			}
		}
	}()
	if activator == nil || l8JobCredentialRuntimeValueIsNil(activator.registry) || l8JobCredentialRuntimeValueIsNil(ctx) {
		return nil, ErrL8JobCredentialSSHRelayInvalid
	}
	if binding.Mode != sandboxruntime.JobCredentialDeliveryModeSSHAgent ||
		sandboxruntime.ValidateJobCredentialIdentity(identity) != nil ||
		!l8JobCredentialSSHRelayBindingMatches(identity, binding) {
		return nil, ErrL8JobCredentialSSHRelayInvalid
	}
	request, requestErr := sshrelay.NewAcquireRequest(
		activator.config,
		credentialprotocol.SafeID(identity.RuntimeGeneration),
		credentialprotocol.SafeID(identity.FirecrackerProcessGeneration),
		credentialprotocol.SafeID(identity.VsockGeneration),
		credentialprotocol.SafeID(identity.WorkerJobID),
		credentialprotocol.SafeID(identity.ActivationGeneration),
		credentialprotocol.SafeID(identity.CredentialGeneration),
	)
	if requestErr != nil {
		return nil, ErrL8JobCredentialSSHRelayInvalid
	}
	lease, acquireErr := callL8JobCredentialSSHRelayAcquire(activator.registry, ctx, request)
	owned := newProductionL8JobCredentialSSHRelayHandle(lease, activator.config)
	if !l8JobCredentialRuntimeValueIsNil(lease) {
		handle = owned
	}
	if acquireErr != nil {
		return handle, sanitizeL8JobCredentialSSHRelayError(acquireErr)
	}
	if l8JobCredentialRuntimeValueIsNil(lease) {
		return nil, ErrL8JobCredentialSSHRelayInvalid
	}
	policyID, revision, policyErr := callL8JobCredentialSSHRelayPolicy(lease)
	if policyErr != nil {
		return handle, policyErr
	}
	if !validL8JobCredentialRuntimeToken(policyID) || revision == 0 {
		return handle, ErrL8JobCredentialSSHRelayInvalid
	}
	owned.policyID = policyID
	owned.revision = revision
	return owned, nil
}

func (handle *productionL8JobCredentialSSHRelayHandle) PolicyID() string {
	if handle == nil {
		return ""
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.policyID
}

func (handle *productionL8JobCredentialSSHRelayHandle) PolicyRevision() uint64 {
	if handle == nil {
		return 0
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.revision
}

func (handle *productionL8JobCredentialSSHRelayHandle) Renew(ctx context.Context) error {
	if handle == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return ErrL8JobCredentialSSHRelayInvalid
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if l8JobCredentialRuntimeValueIsNil(handle.lease) {
		return ErrL8JobCredentialSSHRelayInvalid
	}
	if ctx.Err() != nil {
		return ErrL8JobCredentialSSHRelayUnavailable
	}
	if !sshrelay.ConfigIdentityEqual(handle.lease.Identity(), handle.config) {
		return ErrL8JobCredentialSSHRelayUnavailable
	}
	policyID, revision, err := callL8JobCredentialSSHRelayPolicy(handle.lease)
	if err != nil {
		return err
	}
	if policyID != handle.policyID || revision != handle.revision || revision == 0 {
		return ErrL8JobCredentialSSHRelayUnavailable
	}
	return nil
}

func (handle *productionL8JobCredentialSSHRelayHandle) Revoke(ctx context.Context) error {
	if handle == nil || l8JobCredentialRuntimeValueIsNil(ctx) {
		return ErrL8JobCredentialSSHRelayInvalid
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if l8JobCredentialRuntimeValueIsNil(handle.lease) {
		return nil
	}
	if err := callL8JobCredentialSSHRelayLeaseClose(handle.lease, ctx); err != nil {
		return sanitizeL8JobCredentialSSHRelayError(err)
	}
	handle.lease = nil
	return nil
}

func newProductionL8JobCredentialSSHRelayHandle(lease sshrelay.Lease, config sshrelay.ConfigIdentity) *productionL8JobCredentialSSHRelayHandle {
	return &productionL8JobCredentialSSHRelayHandle{lease: lease, config: config}
}

func l8JobCredentialSSHRelayBindingMatches(identity sandboxruntime.JobCredentialIdentity, binding sandboxruntime.JobCredentialBindingRequest) bool {
	if binding.Mode != sandboxruntime.JobCredentialDeliveryModeSSHAgent || binding.ID == "" {
		return false
	}
	for index, bindingID := range identity.BindingIDs {
		if bindingID != binding.ID {
			continue
		}
		return index < len(identity.DeliveryModes) && identity.DeliveryModes[index] == sandboxruntime.JobCredentialDeliveryModeSSHAgent
	}
	return false
}

func callL8JobCredentialSSHRelayAcquire(registry l8JobCredentialSSHRelayRegistry, ctx context.Context, request sshrelay.AcquireRequest) (lease sshrelay.Lease, err error) {
	defer func() {
		if recover() != nil {
			err = ErrL8JobCredentialSSHRelayUnavailable
		}
	}()
	return registry.Acquire(ctx, request)
}

func callL8JobCredentialSSHRelayPolicy(lease sshrelay.Lease) (policyID string, revision uint64, err error) {
	defer func() {
		if recover() != nil {
			policyID, revision = "", 0
			err = ErrL8JobCredentialSSHRelayUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(lease) {
		return "", 0, ErrL8JobCredentialSSHRelayInvalid
	}
	identity := lease.PolicyIdentity()
	return string(identity.ID()), identity.Revision(), nil
}

func callL8JobCredentialSSHRelayLeaseClose(lease sshrelay.Lease, ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrL8JobCredentialSSHRelayUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(lease) {
		return nil
	}
	return lease.Close(ctx)
}

func sanitizeL8JobCredentialSSHRelayError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrL8JobCredentialSSHRelayInvalid),
		errors.Is(err, sshrelay.ErrInvalidArgument),
		errors.Is(err, sshrelay.ErrIdentityMismatch),
		errors.Is(err, sshrelay.ErrPolicyInvalid),
		errors.Is(err, sshrelay.ErrDependencyRequired),
		errors.Is(err, sshrelay.ErrDuplicateEntry):
		return ErrL8JobCredentialSSHRelayInvalid
	case errors.Is(err, ErrL8JobCredentialSSHRelayUnavailable),
		errors.Is(err, ErrL8JobCredentialSSHRelaySerialization),
		errors.Is(err, sshrelay.ErrSerialization):
		return err
	default:
		return ErrL8JobCredentialSSHRelayUnavailable
	}
}

var (
	_ l8JobCredentialSSHRelayActivator = (*ProductionL8JobCredentialSSHRelayActivator)(nil)
	_ l8JobCredentialSSHRelayHandle    = (*productionL8JobCredentialSSHRelayHandle)(nil)
	_ l8JobCredentialSSHRelayRegistry  = (*sshrelay.Registry)(nil)
)
