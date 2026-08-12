// Package credentialhelper defines the frozen privileged-helper extension
// seam. Live helper behavior is supplied by later, explicitly composed slices.
package credentialhelper

import (
	"context"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

// ExtensionFactory opens service-lifetime extension state.
type ExtensionFactory interface {
	Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error)
}

// ExtensionOpenRequest carries the frozen descriptor and the only host
// capabilities available to an extension.
type ExtensionOpenRequest struct {
	liveValue
	descriptor credentialprotocol.ExtensionDescriptor
	host       ExtensionHost
}

// ExtensionSession owns one extension's transitions for a helper service.
type ExtensionSession interface {
	Prepare(context.Context, ExtensionPrepareRequest) (ExtensionPrepareResult, error)
	BindExec(context.Context, ExtensionExecRequest) (ExtensionExecResult, error)
	Renew(context.Context, ExtensionRenewRequest) error
	Revoke(context.Context, ExtensionRevokeRequest) (ExtensionCleanupResult, error)
	Close(context.Context) error
}

// ExtensionHost is the narrow D4-owned capability exposed to extensions.
type ExtensionHost interface {
	CreateSSHAgentEndpoint(context.Context, SSHAgentEndpointRequest) (SSHAgentEndpoint, error)
	PublishSSHAcceptedConnection(context.Context, SSHAcceptedPublication, SSHAgentConnection) error
}

// SSHAgentEndpoint is one job-scoped guest endpoint.
type SSHAgentEndpoint interface {
	ExecBinding() ExecBindingCapability
	Accept(context.Context) (SSHAgentConnection, error)
	Close(context.Context) (ExtensionCleanupResult, error)
}

// SSHAgentConnection is a bounded mutable-memory SSH byte stream.
type SSHAgentConnection interface {
	Read(context.Context, credentialmemory.CredentialSink) (SSHIOResult, error)
	Write(context.Context, credentialmemory.BorrowedView) (SSHIOResult, error)
	Shutdown(context.Context, SSHShutdownDirection) error
	Close(context.Context) error
}

type ExtensionPrepareRequest struct {
	liveValue
	identityDigest  [32]byte
	revision        uint64
	expiresUnixNano int64
	bindingID       credentialprotocol.SafeID
	bindingIndex    uint16
	mode            credentialprotocol.DeliveryMode
	execBinding     ExecBindingCapability
}

type ExtensionPrepareResult struct {
	liveValue
	execBinding ExecBindingCapability
}

type ExtensionExecRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	execBindingID  credentialprotocol.SafeID
	execBinding    ExecBindingCapability
}

type ExtensionExecResult struct {
	liveValue
	execBinding ExecBindingCapability
}

type ExtensionRenewRequest struct {
	liveValue
	identityDigest  [32]byte
	revision        uint64
	expiresUnixNano int64
}

type ExtensionRevokeRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	reason         credentialprotocol.RevokeReason
}

type SSHAgentEndpointRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	bindingID      credentialprotocol.SafeID
	bindingIndex   uint16
	execBinding    ExecBindingCapability
}

type SSHAcceptedPublication struct {
	liveValue
	identityDigest   [32]byte
	revision         uint64
	bindingIndex     uint16
	ordinal          uint8
	capabilitySHA256 [32]byte
	execBinding      ExecBindingCapability
}
