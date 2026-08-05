// Package credentialhelper defines the frozen privileged-helper extension
// seam. Live helper behavior is supplied by later, explicitly composed slices.
package credentialhelper

import (
	"context"
	"time"

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
	Descriptor credentialprotocol.ExtensionDescriptor
	Host       ExtensionHost
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
	IdentityDigest [32]byte
	Revision       uint64
	ExpiresAt      time.Time
	BindingID      credentialprotocol.SafeID
	BindingIndex   uint16
	Mode           credentialprotocol.DeliveryMode
}

type ExtensionPrepareResult struct {
	ExecBinding ExecBindingCapability
}

type ExtensionExecRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	ExecBindingID  credentialprotocol.SafeID
}

type ExtensionExecResult struct {
	ExecBinding ExecBindingCapability
}

type ExtensionRenewRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	ExpiresAt      time.Time
}

type ExtensionRevokeRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	Reason         credentialprotocol.RevokeReason
}

type SSHAgentEndpointRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	BindingID      credentialprotocol.SafeID
	BindingIndex   uint16
}

type SSHAcceptedPublication struct {
	IdentityDigest   [32]byte
	Revision         uint64
	BindingIndex     uint16
	Ordinal          uint8
	CapabilitySHA256 [32]byte
}
