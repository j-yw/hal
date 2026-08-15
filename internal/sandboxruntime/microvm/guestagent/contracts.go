package guestagent

const (
	// ProtocolVersionV1 is the first stable guest-agent protocol contract.
	ProtocolVersionV1 ProtocolVersion = "guest-agent-v1"
)

const (
	OperationReadiness Operation = "readiness"
	OperationExec      Operation = "exec"
	OperationCopyIn    Operation = "copy_in"
	OperationCopyOut   Operation = "copy_out"
)

const (
	EnvironmentSourceLiteral   EnvironmentSource = "literal"
	EnvironmentSourceSecret    EnvironmentSource = "secret"
	EnvironmentSourceInherited EnvironmentSource = "inherited"
	EnvironmentSourceGenerated EnvironmentSource = "generated"
)

const (
	PayloadEncodingRaw     PayloadEncoding = "raw"
	PayloadEncodingBase64  PayloadEncoding = "base64"
	PayloadEncodingChunked PayloadEncoding = "chunked"
)

const (
	ReadinessStatusReady    ReadinessStatus = "ready"
	ReadinessStatusNotReady ReadinessStatus = "not_ready"
)

const (
	IsolationProofStatusVerified    IsolationProofStatus = "verified"
	IsolationProofStatusUnavailable IsolationProofStatus = "unavailable"
	IsolationProofStatusFailed      IsolationProofStatus = "failed"
)

const (
	ErrorCodeUnsupportedProtocolVersion ErrorCode = "unsupported_protocol_version"
	ErrorCodeUnknownOperation           ErrorCode = "unknown_operation"
	ErrorCodeOperationMismatch          ErrorCode = "operation_mismatch"
	ErrorCodeMissingRequiredField       ErrorCode = "missing_required_field"
	ErrorCodeMalformedPath              ErrorCode = "malformed_path"
	ErrorCodeInvalidTimeout             ErrorCode = "invalid_timeout"
	ErrorCodeInvalidDeadline            ErrorCode = "invalid_deadline"
	ErrorCodeOversizedPayloadMetadata   ErrorCode = "oversized_payload_metadata"
	ErrorCodeInvalidMetadata            ErrorCode = "invalid_metadata"
	ErrorCodeMalformedResponse          ErrorCode = "malformed_response"
	ErrorCodeOversizedRequest           ErrorCode = "oversized_request"
	ErrorCodeOversizedResponse          ErrorCode = "oversized_response"
	ErrorCodeRequestCanceled            ErrorCode = "request_canceled"
	ErrorCodeRequestTimeout             ErrorCode = "request_timeout"
	ErrorCodeTransportFailure           ErrorCode = "transport_failure"
	ErrorCodeMalformedRequest           ErrorCode = "malformed_request"
	ErrorCodeServerNotReady             ErrorCode = "server_not_ready"
	ErrorCodeServerBusy                 ErrorCode = "server_busy"
	ErrorCodeEnvironmentUnavailable     ErrorCode = "environment_unavailable"
	ErrorCodeExecutionFailed            ErrorCode = "execution_failed"
	ErrorCodeCopyFailed                 ErrorCode = "copy_failed"
	ErrorCodeDigestMismatch             ErrorCode = "digest_mismatch"
	ErrorCodeResourceChanged            ErrorCode = "resource_changed"
	ErrorCodeDurabilityUncertain        ErrorCode = "durability_uncertain"
	ErrorCodeBackendUnavailable         ErrorCode = "backend_unavailable"
	ErrorCodeUnsupportedPlatform        ErrorCode = "unsupported_platform"
	ErrorCodeInternalFailure            ErrorCode = "internal_failure"
)

const (
	MaxCommandArgs                   = 128
	MaxCommandArgBytes               = 8192
	MaxEnvironmentEntries            = 256
	MaxGuestPathBytes                = 4096
	MaxStreamMetadataBytes           = 4 * 1024 * 1024
	MaxCopyPayloadMetadataBytes      = 64 * 1024 * 1024
	MaxTimeoutMillis                 = 24 * 60 * 60 * 1000
	MinDeadlineUnixMillis            = 946684800000
	MaxDeadlineUnixMillis            = 4102444800000
	MaxIsolationProofGenerationBytes = 128
)

// ProtocolVersion names the guest-agent wire contract version.
type ProtocolVersion string

// Operation names one bounded guest-agent operation.
type Operation string

// EnvironmentSource identifies where an environment entry comes from without
// carrying an environment value.
type EnvironmentSource string

// PayloadEncoding identifies how a bounded payload is framed.
type PayloadEncoding string

// ReadinessStatus is a redaction-safe readiness state label.
type ReadinessStatus string

// IsolationProofStatus is a redaction-safe live proof state.
type IsolationProofStatus string

// ErrorCode identifies a stable protocol validation or dispatch failure.
type ErrorCode string

// TimingMetadata bounds a request by timeout or absolute deadline. Callers
// should provide at most one of TimeoutMillis or DeadlineUnixMillis.
type TimingMetadata struct {
	TimeoutMillis      int64 `json:"timeoutMillis,omitempty"`
	DeadlineUnixMillis int64 `json:"deadlineUnixMillis,omitempty"`
}

// StreamMetadata describes bounded command I/O. Data is optional bounded
// stream content used only when a protocol operation returns captured output.
type StreamMetadata struct {
	SizeBytes int64           `json:"sizeBytes,omitempty"`
	MaxBytes  int64           `json:"maxBytes,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
	Data      string          `json:"data,omitempty"`
	Encoding  PayloadEncoding `json:"encoding,omitempty"`
}

// PayloadMetadata describes a bounded copy payload without carrying host-local
// paths. Data, when present, is encoded according to Encoding for JSON wire
// safety; SizeBytes always describes decoded payload bytes.
type PayloadMetadata struct {
	SizeBytes int64           `json:"sizeBytes,omitempty"`
	MaxBytes  int64           `json:"maxBytes,omitempty"`
	Digest    string          `json:"digest,omitempty"`
	Encoding  PayloadEncoding `json:"encoding,omitempty"`
	Data      string          `json:"data,omitempty"`
}

// EnvironmentEntry describes an environment variable by name and source only.
// It intentionally does not carry environment values.
type EnvironmentEntry struct {
	Name   string            `json:"name"`
	Source EnvironmentSource `json:"source,omitempty"`
}

// ReadinessRequest asks the guest agent whether it is ready for protocol
// operations.
type ReadinessRequest struct {
	ProtocolVersion ProtocolVersion        `json:"protocolVersion"`
	Operation       Operation              `json:"operation"`
	Timing          *TimingMetadata        `json:"timing,omitempty"`
	IsolationProof  *IsolationProofRequest `json:"isolationProof,omitempty"`
}

// IsolationProofRequest binds an optional live process proof to this
// readiness request and, when supplied, to one sanitized runtime generation.
type IsolationProofRequest struct {
	Generation          string `json:"generation"`
	RuntimeGeneration   string `json:"runtimeGeneration,omitempty"`
	RequireNetworkProof bool   `json:"requireNetworkProof,omitempty"`
}

// NetworkIsolationProof reports only fixed, sanitized topology outcomes.
// It intentionally carries no interfaces, addresses, routes, or endpoints.
type NetworkIsolationProof struct {
	Status          IsolationProofStatus `json:"status"`
	SingleInterface bool                 `json:"singleInterface,omitempty"`
	StaticRoutes    bool                 `json:"staticRoutes,omitempty"`
	ProxyReachable  bool                 `json:"proxyReachable,omitempty"`
}

// IsolationProof is the sanitized result of inspecting the exact running
// guest-agent process and, when available, its injected network verifier.
type IsolationProof struct {
	Generation                 string                 `json:"generation"`
	RuntimeGeneration          string                 `json:"runtimeGeneration,omitempty"`
	Status                     IsolationProofStatus   `json:"status"`
	RestrictedIdentity         bool                   `json:"restrictedIdentity,omitempty"`
	CapabilitiesCleared        bool                   `json:"capabilitiesCleared,omitempty"`
	NoNewPrivileges            bool                   `json:"noNewPrivileges,omitempty"`
	SupplementaryGroupsCleared bool                   `json:"supplementaryGroupsCleared,omitempty"`
	RawPacketSocketDenied      bool                   `json:"rawPacketSocketDenied,omitempty"`
	Network                    *NetworkIsolationProof `json:"network,omitempty"`
}

// ReadinessResponse is the guest-agent readiness result.
type ReadinessResponse struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	Operation       Operation       `json:"operation"`
	Ready           bool            `json:"ready"`
	Status          ReadinessStatus `json:"status,omitempty"`
	Error           *ProtocolError  `json:"error,omitempty"`
	IsolationProof  *IsolationProof `json:"isolationProof,omitempty"`
}

// ErrorResponse is the generic v1 error envelope used when no successful
// operation-specific response can be returned.
type ErrorResponse struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	Operation       Operation       `json:"operation,omitempty"`
	Error           *ProtocolError  `json:"error"`
}

// ExecRequest asks the guest agent to run a bounded command in the guest.
type ExecRequest struct {
	ProtocolVersion ProtocolVersion    `json:"protocolVersion"`
	Operation       Operation          `json:"operation"`
	Args            []string           `json:"args"`
	Env             []EnvironmentEntry `json:"env,omitempty"`
	WorkDir         string             `json:"workDir"`
	Stdin           *StreamMetadata    `json:"stdin,omitempty"`
	Stdout          StreamMetadata     `json:"stdout"`
	Stderr          StreamMetadata     `json:"stderr"`
	Timing          *TimingMetadata    `json:"timing,omitempty"`
}

// ExecResponse is the bounded command result from the guest agent.
type ExecResponse struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	Operation       Operation       `json:"operation"`
	ExitCode        int             `json:"exitCode"`
	Stdout          StreamMetadata  `json:"stdout"`
	Stderr          StreamMetadata  `json:"stderr"`
	Error           *ProtocolError  `json:"error,omitempty"`
}

// CopyInRequest asks the guest agent to receive a bounded payload at a guest
// destination path.
type CopyInRequest struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	Operation       Operation       `json:"operation"`
	DestinationPath string          `json:"destinationPath"`
	Payload         PayloadMetadata `json:"payload"`
	Timing          *TimingMetadata `json:"timing,omitempty"`
}

// CopyInResponse acknowledges a bounded copy-in payload.
type CopyInResponse struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	Operation       Operation       `json:"operation"`
	Written         PayloadMetadata `json:"written"`
	Error           *ProtocolError  `json:"error,omitempty"`
}

// CopyOutRequest asks the guest agent to produce a bounded payload from a
// guest source path.
type CopyOutRequest struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	Operation       Operation       `json:"operation"`
	SourcePath      string          `json:"sourcePath"`
	Payload         PayloadMetadata `json:"payload"`
	Timing          *TimingMetadata `json:"timing,omitempty"`
}

// CopyOutResponse returns bounded copy-out payload metadata.
type CopyOutResponse struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	Operation       Operation       `json:"operation"`
	Payload         PayloadMetadata `json:"payload"`
	Error           *ProtocolError  `json:"error,omitempty"`
}
