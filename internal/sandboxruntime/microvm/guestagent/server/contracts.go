package server

import (
	"context"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

const (
	DefaultMaxRequestBytes     int64 = 1 << 20
	DefaultMaxResponseBytes    int64 = 1 << 20
	MinimumMaxResponseBytes    int64 = 512
	MaximumEncodedMessageBytes int64 = 8 << 20

	DefaultMaxConcurrent = 1
	MaximumMaxConcurrent = 64

	DefaultMaxOperationTime = 24 * time.Hour
	MaximumMaxOperationTime = 24 * time.Hour
	DefaultMaxShutdownTime  = 30 * time.Second
	MaximumMaxShutdownTime  = 2 * time.Minute

	MaximumJSONNestingDepth = 32

	DefaultExecStdinBytes  int64 = 512 << 10
	DefaultExecStdoutBytes int64 = 256 << 10
	DefaultExecStderrBytes int64 = 256 << 10
	DefaultCopyBytes       int64 = 512 << 10

	MaximumResolvedEnvironmentValueBytes int64 = 64 << 10
	MaximumResolvedEnvironmentBytes      int64 = 256 << 10
)

// State is the lifecycle state of a guest-agent server.
type State string

const (
	StateNew      State = "new"
	StateServing  State = "serving"
	StateDraining State = "draining"
	StateStopped  State = "stopped"
	StateFailed   State = "failed"
)

// Limits are the encoded frame limits supplied to an injected transport.
type Limits struct {
	MaxRequestBytes  int64
	MaxResponseBytes int64
}

// Transport accepts bounded byte frames and dispatches them through Handler.
// Cancellation-only errors must have only the supplied context error as their
// causal leaf; every other non-nil return is an independent transport failure.
type Transport interface {
	Serve(context.Context, Limits, Handler) error
}

// Request contains one encoded protocol request.
type Request struct {
	Encoded []byte
}

// Response contains one encoded protocol response.
type Response struct {
	Encoded []byte
}

// Handler handles one encoded request.
type Handler interface {
	Handle(context.Context, Request) Response
}

// Backend executes decoded live plans without exposing them as wire contracts.
type Backend interface {
	Ready(context.Context) error
	Exec(context.Context, ExecPlan) (ExecResult, error)
	CopyIn(context.Context, CopyInPlan) (CopyResult, error)
	CopyOut(context.Context, CopyOutPlan) (CopyResult, error)
	Close(context.Context) error
}

// EnvironmentResolver resolves one value in memory for an exec request.
type EnvironmentResolver interface {
	Resolve(context.Context, guestagent.EnvironmentEntry) (string, error)
}

// ExecPlan is a decoded, bounded live execution request.
type ExecPlan struct {
	Args           []string
	Environment    []string
	WorkDir        string
	Stdin          []byte
	StdoutMaxBytes int64
	StderrMaxBytes int64
}

// ExecResult is a bounded live execution result.
type ExecResult struct {
	ExitCode        int
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
}

// CopyInPlan is a decoded, bounded copy-in request.
type CopyInPlan struct {
	DestinationPath string
	Data            []byte
	MaxBytes        int64
	Digest          string
}

// CopyOutPlan is a decoded, bounded copy-out request.
type CopyOutPlan struct {
	SourcePath string
	MaxBytes   int64
}

// CopyResult is a bounded copy result.
type CopyResult struct {
	Data []byte
	// Published is set only by CopyIn after the destination rename succeeds.
	// It remains true when a later durability step fails so callers never
	// misreport a visible mutation as a retry-safe cancellation or copy failure.
	Published bool
	SizeBytes int64
	Digest    string
}

// LinuxBackendOptions configure the Linux backend implementation owned by the
// platform-specific backend layer.
type LinuxBackendOptions struct {
	// WorkspaceRoot must be the unaliased root of a distinct filesystem in the
	// guest agent's mount namespace.
	WorkspaceRoot   string
	GuestRoot       string
	BaseEnvironment []string
	ExecutablePaths []string
	TermGrace       time.Duration
}

// Options configure a guest-agent server.
type Options struct {
	Transport           Transport
	Backend             Backend
	EnvironmentResolver EnvironmentResolver
	MaxRequestBytes     int64
	MaxResponseBytes    int64
	MaxConcurrent       int
	MaxOperationTime    time.Duration
	MaxShutdownTime     time.Duration
}
