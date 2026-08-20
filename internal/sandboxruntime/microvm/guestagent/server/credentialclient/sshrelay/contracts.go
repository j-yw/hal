// Package sshrelay owns the unprivileged credential-client SSH relay
// extension. It depends only on the neutral client and memory seams; D6
// supplies the authenticated relay implementation explicitly.
package sshrelay

import (
	"context"
	"errors"
	"fmt"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrInvalidArgument   = errors.New("credential client SSH relay argument is invalid")
	ErrLifecycle         = errors.New("credential client SSH relay lifecycle is invalid")
	ErrDependency        = errors.New("credential client SSH relay dependency failed")
	ErrPumpFailed        = errors.New("credential client SSH relay pump failed")
	ErrCleanupIncomplete = errors.New("credential client SSH relay cleanup is incomplete")
	ErrSerialization     = errors.New("credential client SSH relay serialization is denied")
)

type liveValue struct{}

func (liveValue) MarshalJSON() ([]byte, error)   { return nil, ErrSerialization }
func (liveValue) MarshalText() ([]byte, error)   { return nil, ErrSerialization }
func (liveValue) MarshalBinary() ([]byte, error) { return nil, ErrSerialization }
func (liveValue) UnmarshalJSON([]byte) error     { return ErrSerialization }
func (liveValue) UnmarshalText([]byte) error     { return ErrSerialization }
func (liveValue) UnmarshalBinary([]byte) error   { return ErrSerialization }
func (liveValue) String() string                 { return "credentialclient.sshrelay.live[redacted]" }
func (liveValue) GoString() string               { return "credentialclient.sshrelay.live[redacted]" }
func (liveValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.sshrelay.live[redacted]"))
}

// ClientOptions carries the sole process-local authenticated relay authority.
// No default or global registration exists.
type ClientOptions struct {
	liveValue
	Relay Relay
}

// Relay opens one runtime/job-bound authenticated stream for one already
// authenticated guest connection. It exposes no endpoint or host identity.
type Relay interface {
	Open(context.Context, RelayOpenRequest) (RelayConnection, error)
}

// RelayConnection performs exactly one request/response transaction per call.
// The extension serializes calls and supplies only ephemeral locked-memory
// views and sinks.
type RelayConnection interface {
	RoundTrip(context.Context, credentialmemory.BorrowedView, credentialmemory.CredentialSink) error
	Close(context.Context) error
}

// RelayOpenRequest is safe correlation metadata for one accepted connection.
// Its private fields prevent callers from forging a request without going
// through the authenticated ExtensionPacket arm.
type RelayOpenRequest struct {
	liveValue
	revision         uint64
	bindingIndex     uint16
	ordinal          uint8
	capabilitySHA256 [32]byte
}

func (request RelayOpenRequest) Revision() uint64 { return request.revision }

func (request RelayOpenRequest) BindingIndex() uint16 { return request.bindingIndex }

func (request RelayOpenRequest) Ordinal() uint8 { return request.ordinal }

func (request RelayOpenRequest) CapabilitySHA256() [32]byte { return request.capabilitySHA256 }

func validRelayOpenRequest(request RelayOpenRequest) bool {
	return request.revision > 0 &&
		request.bindingIndex < credentialprotocol.MaxHelperBindings &&
		request.ordinal > 0 && request.ordinal <= credentialprotocol.SSHAgentRelayMaxLifetimeConnections &&
		request.capabilitySHA256 != ([32]byte{})
}
