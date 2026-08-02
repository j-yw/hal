package firecracker

import (
	"context"
	"io"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// GuestTransport is the injected boundary for Firecracker guest command and
// file transport. Implementations live outside this contract package.
type GuestTransport interface {
	Exec(context.Context, GuestExecRequest) (*sandboxruntime.ExecResult, error)
	CopyIn(context.Context, GuestCopyRequest) error
	CopyOut(context.Context, GuestCopyRequest) error
}

// ProductionVsockSessionRequest binds a host-owned vsock bridge to one exact
// accepted Firecracker process and its private host-side UDS. SocketPath is a
// process-boundary value and must never be copied to durable target metadata.
type ProductionVsockSessionRequest struct {
	Handle     ProcessHandleMetadata `json:"-"`
	RuntimeID  string                `json:"-"`
	SocketPath string                `json:"-"`
}

// ProductionVsockBridge is the host-owned L5 composition boundary. Unlike the
// compatibility GuestReadinessWaiter and GuestTransport injections, it owns
// post-launch socket validation, peer-process correlation, guest readiness,
// per-start generation, operation routing, and invalidation.
type ProductionVsockBridge interface {
	GuestTransport
	ActivateSession(context.Context, ProductionVsockSessionRequest) (GuestReadinessResult, string, error)
	SessionActive(ProductionVsockSessionRequest, string) bool
	InvalidateSession(ProductionVsockSessionRequest, string)
}

// GuestCopyPublicationError marks a copy-in result for which the destination
// is visible but crash durability is not proven. Callers must not treat this
// outcome as an ordinary retry-safe transport failure.
type GuestCopyPublicationError interface {
	error
	CopyPublicationDurabilityUncertain() bool
}

// GuestExecRequest is the raw guest command request shape passed only to an
// explicitly injected guest transport boundary.
type GuestExecRequest struct {
	Target  sandboxruntime.Target `json:"-"`
	Args    []string              `json:"-"`
	Env     map[string]string     `json:"-"`
	WorkDir string                `json:"-"`
	Stdin   io.Reader             `json:"-"`
	Stdout  io.Writer             `json:"-"`
	Stderr  io.Writer             `json:"-"`
}

// GuestCopyRequest is the raw guest file transfer request shape passed only to
// an explicitly injected guest transport boundary.
type GuestCopyRequest struct {
	Target          sandboxruntime.Target `json:"-"`
	SourcePath      string                `json:"-"`
	DestinationPath string                `json:"-"`
}
