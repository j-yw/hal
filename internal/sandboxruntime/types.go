package sandboxruntime

import (
	"context"
	"io"
)

const (
	DriverSSHMachine     = "ssh_machine"
	DriverRootlessPodman = "rootless_podman"
	DriverMicroVM        = "microvm"
)

// Driver is the complete sandbox runtime boundary used by orchestration code.
type Driver interface {
	ID() string
	LifecycleDriver
	ExecDriver
	FileTransport
}

// LifecycleDriver manages sandbox target lifecycle operations.
type LifecycleDriver interface {
	Create(context.Context, CreateRequest) (*Target, error)
	Start(context.Context, LifecycleRequest) (*Target, error)
	Stop(context.Context, LifecycleRequest) (*Target, error)
	Delete(context.Context, LifecycleRequest) error
	Inspect(context.Context, InspectRequest) (*Target, error)
}

// ExecDriver runs commands inside a sandbox target with streaming I/O.
type ExecDriver interface {
	Exec(context.Context, ExecRequest) (*ExecResult, error)
}

// FileTransport copies files between the host and sandbox target.
type FileTransport interface {
	CopyIn(context.Context, CopyRequest) error
	CopyOut(context.Context, CopyRequest) error
}

// Target describes a resolved runtime target without exposing legacy provider
// types or command-layer durable records.
type Target struct {
	ID         string
	Name       string
	Provider   string
	Status     string
	Runtime    RuntimeState
	Connection ConnectionInfo
}

// RuntimeState captures runtime-driver metadata for a target.
type RuntimeState struct {
	Driver         string
	RuntimeID      string
	Image          string
	WorkerID       string
	IsolationLevel string
	Metadata       *RuntimeMetadata `json:"metadata,omitempty"`
}

// RuntimeMetadata captures optional runtime-specific target metadata using only
// redaction-safe labels.
type RuntimeMetadata struct {
	Backend          string                         `json:"backend,omitempty"`
	CapabilityLabels []string                       `json:"capabilityLabels,omitempty"`
	PathRoles        []string                       `json:"pathRoles,omitempty"`
	OperationPlan    *RuntimeOperationPlan          `json:"operationPlan,omitempty"`
	ProcessLaunch    *RuntimeProcessLaunchMetadata  `json:"processLaunch,omitempty"`
	GuestReadiness   *RuntimeGuestReadinessMetadata `json:"guestReadiness,omitempty"`
}

// RuntimeProcessLaunchMetadata captures sanitized process-launch state labels.
// It intentionally does not describe guest readiness, networking, credential
// delivery, exec support, copy support, or raw host process details.
type RuntimeProcessLaunchMetadata struct {
	State           string   `json:"state,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	ProcessID       string   `json:"processId,omitempty"`
	ProcessIDSource string   `json:"processIdSource,omitempty"`
}

// RuntimeGuestReadinessMetadata captures sanitized guest readiness state
// labels. It intentionally carries no paths, endpoints, process details,
// credentials, IP addresses, raw transport configuration, or guest command
// payloads.
type RuntimeGuestReadinessMetadata struct {
	State     RuntimeGuestReadinessState `json:"state,omitempty"`
	Transport string                     `json:"transport,omitempty"`
	Labels    []string                   `json:"labels,omitempty"`
}

// RuntimeOperationPlan is a sanitized runtime-operation plan. It carries only
// role, label, and explicitly safe digest metadata so backends can expose
// launch preparation without raw host paths, endpoints, credentials, or command
// payload bodies.
type RuntimeOperationPlan struct {
	Action            string                        `json:"action,omitempty"`
	Environment       []RuntimeOperationEnvironment `json:"environment,omitempty"`
	PathRoles         []string                      `json:"pathRoles,omitempty"`
	Payloads          []RuntimeOperationPayload     `json:"payloads,omitempty"`
	ProcessDescriptor *RuntimeProcessDescriptor     `json:"processDescriptor,omitempty"`
}

// RuntimeProcessDescriptor describes a process-boundary command without raw
// argv values that contain host paths.
type RuntimeProcessDescriptor struct {
	Action         string                        `json:"action,omitempty"`
	ExecutableRole string                        `json:"executableRole,omitempty"`
	Argv           []RuntimeOperationArgument    `json:"argv"`
	Environment    []RuntimeOperationEnvironment `json:"environment"`
	PathRoles      []string                      `json:"pathRoles"`
	Payloads       []RuntimeOperationPayload     `json:"payloads"`
}

// RuntimeOperationArgument is the public argv shape for runtime operation
// planning. Literal flags appear as Value; path arguments appear by role only.
type RuntimeOperationArgument struct {
	Value    string `json:"value,omitempty"`
	PathRole string `json:"pathRole,omitempty"`
}

// RuntimeOperationEnvironment describes an environment entry without exposing
// environment values.
type RuntimeOperationEnvironment struct {
	Name   string `json:"name,omitempty"`
	Source string `json:"source,omitempty"`
}

// RuntimeOperationPayload identifies a backend payload by role, safe API path,
// and optional redaction-safe immutable asset metadata. It never carries host
// paths, endpoints, credentials, or payload bodies.
type RuntimeOperationPayload struct {
	Role    string                         `json:"role,omitempty"`
	APIPath string                         `json:"apiPath,omitempty"`
	Assets  []RuntimeOperationPayloadAsset `json:"assets,omitempty"`
}

// RuntimeOperationPayloadAsset carries public immutable launch asset metadata.
// Values must already be safe IDs, labels, roles, and digest metadata.
type RuntimeOperationPayloadAsset struct {
	AssetRole string                         `json:"assetRole,omitempty"`
	ID        string                         `json:"id,omitempty"`
	Labels    []string                       `json:"labels,omitempty"`
	Digest    *RuntimeOperationPayloadDigest `json:"digest,omitempty"`
}

// RuntimeOperationPayloadDigest carries digest lock metadata without exposing
// any host path or file resolution details.
type RuntimeOperationPayloadDigest struct {
	Algorithm string `json:"algorithm,omitempty"`
	Value     string `json:"value,omitempty"`
}

// ConnectionInfo captures command-agnostic connection metadata for a target.
type ConnectionInfo struct {
	Address           string
	PublicIP          string
	TailscaleIP       string
	TailscaleHostname string
	TailscaleLockdown bool
	WorkspaceID       string
}

// CreateRequest describes a target provisioning request.
type CreateRequest struct {
	Name   string
	Env    map[string]string
	Stdout io.Writer
	Stderr io.Writer
}

// LifecycleRequest describes an operation on an existing target.
type LifecycleRequest struct {
	Target Target
	Stdout io.Writer
	Stderr io.Writer
}

// InspectRequest describes a target inspection request.
type InspectRequest struct {
	Target Target
}

// ExecRequest describes a command that should run inside a target.
type ExecRequest struct {
	Target  Target
	Args    []string
	Stdout  io.Writer
	Stderr  io.Writer
	Stdin   io.Reader
	Env     map[string]string
	WorkDir string
}

// ExecResult describes a completed command execution.
type ExecResult struct {
	ExitCode int
}

// CopyRequest describes one file transfer direction for a target.
type CopyRequest struct {
	Target          Target
	SourcePath      string
	DestinationPath string
}
