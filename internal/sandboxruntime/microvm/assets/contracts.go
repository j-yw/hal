package assets

const (
	AssetRoleKernel           AssetRole = "kernel"
	AssetRoleRootfs           AssetRole = "rootfs"
	AssetRoleInitrd           AssetRole = "initrd"
	AssetRoleGuestInitConfig  AssetRole = "guest_init_config"
	AssetRoleGuestAgentConfig AssetRole = "guest_agent_config"
)

const (
	AssetKindKernelImage AssetKind = "kernel_image"
	AssetKindRootfsImage AssetKind = "rootfs_image"
	AssetKindInitrdImage AssetKind = "initrd_image"
	AssetKindGuestConfig AssetKind = "guest_config"
	AssetKindAgentConfig AssetKind = "agent_config"
)

const (
	SourceTypeLocalFile SourceType = "local_file"
	SourceTypeGenerated SourceType = "generated"
	SourceTypeEmbedded  SourceType = "embedded"
)

const (
	DigestAlgorithmSHA256 DigestAlgorithm = "sha256"
	DigestAlgorithmSHA384 DigestAlgorithm = "sha384"
	DigestAlgorithmSHA512 DigestAlgorithm = "sha512"
)

const (
	HostPathRoleLaunchInput        HostPathRole = "launch_input"
	HostPathRoleResolvedLocalAsset HostPathRole = "resolved_local_asset"
)

const (
	ValidationMissingRequiredField     ValidationCode = "missing_required_field"
	ValidationMissingRequiredRole      ValidationCode = "missing_required_role"
	ValidationUnsupportedRole          ValidationCode = "unsupported_role"
	ValidationDuplicateRequiredRole    ValidationCode = "duplicate_required_role"
	ValidationUnsupportedKind          ValidationCode = "unsupported_kind"
	ValidationUnsupportedSourceType    ValidationCode = "unsupported_source_type"
	ValidationUnsupportedHostPathRole  ValidationCode = "unsupported_host_path_role"
	ValidationMalformedDigestAlgorithm ValidationCode = "malformed_digest_algorithm"
	ValidationMalformedDigestValue     ValidationCode = "malformed_digest_value"
	ValidationUnsafeID                 ValidationCode = "unsafe_id"
	ValidationUnsafeLabel              ValidationCode = "unsafe_label"
	ValidationInvalidMetadata          ValidationCode = "invalid_metadata"
)

// SafeID is a redaction-safe durable identifier. Validation restricts values to
// small identifier tokens and rejects URL-like, path-like, or secret-like input.
type SafeID string

// SafeLabel is bounded enum-like metadata suitable for public records.
type SafeLabel string

// AssetRole identifies the launch-time purpose of an immutable asset.
type AssetRole string

// AssetKind identifies the backend-neutral asset shape.
type AssetKind string

// SourceType identifies where an already-described asset came from without
// resolving files, contacting networks, or invoking a runtime.
type SourceType string

// DigestAlgorithm names the digest algorithm for immutable lock metadata.
type DigestAlgorithm string

// HostPathRole identifies why a host path is present without implying that this
// package resolved, opened, or trusted it.
type HostPathRole string

// ValidationCode identifies a sanitized launch asset validation failure.
type ValidationCode string

// LaunchDescriptor is the backend-neutral immutable microVM launch asset set.
type LaunchDescriptor struct {
	ID     SafeID        `json:"id,omitempty"`
	Labels []SafeLabel   `json:"labels,omitempty"`
	Assets []LaunchAsset `json:"assets,omitempty"`
}

// LaunchAsset describes one immutable launch input or guest config artifact.
type LaunchAsset struct {
	ID          SafeID               `json:"id"`
	Role        AssetRole            `json:"role"`
	Kind        AssetKind            `json:"kind"`
	Labels      []SafeLabel          `json:"labels,omitempty"`
	Source      AssetSource          `json:"source"`
	Lock        LockMetadata         `json:"lock"`
	InitConfig  *InitConfigMetadata  `json:"initConfig,omitempty"`
	AgentConfig *AgentConfigMetadata `json:"agentConfig,omitempty"`
	Resources   []ResourceMetadata   `json:"resources,omitempty"`
}

// AssetSource records source metadata only. Local-file path validation and
// digesting are owned by later resolver code.
type AssetSource struct {
	Type     SourceType        `json:"type"`
	HostPath *HostPathMetadata `json:"hostPath,omitempty"`
}

// HostPathMetadata carries a host path plus a safe role label. The path value is
// intentionally not interpreted by this package.
type HostPathMetadata struct {
	Path string       `json:"path,omitempty"`
	Role HostPathRole `json:"role"`
}

// LockMetadata carries immutable digest lock data and optional bounded resource
// facts copied from a resolver.
type LockMetadata struct {
	Digest             DigestMetadata `json:"digest"`
	SizeBytes          int64          `json:"sizeBytes,omitempty"`
	LockedAtUnixMillis int64          `json:"lockedAtUnixMillis,omitempty"`
}

// DigestMetadata separates algorithm identity from the raw hex digest value.
type DigestMetadata struct {
	Algorithm DigestAlgorithm `json:"algorithm"`
	Value     string          `json:"value"`
}

// InitConfigMetadata describes optional guest-init config metadata only.
type InitConfigMetadata struct {
	Format     SafeLabel   `json:"format,omitempty"`
	EntryPoint SafeLabel   `json:"entryPoint,omitempty"`
	Labels     []SafeLabel `json:"labels,omitempty"`
}

// AgentConfigMetadata describes optional guest-agent config metadata only.
type AgentConfigMetadata struct {
	Protocol SafeLabel   `json:"protocol,omitempty"`
	Version  SafeLabel   `json:"version,omitempty"`
	Features []SafeLabel `json:"features,omitempty"`
}

// ResourceMetadata carries safe resource facts associated with an asset.
type ResourceMetadata struct {
	ID        SafeID      `json:"id,omitempty"`
	Kind      SafeLabel   `json:"kind,omitempty"`
	SizeBytes int64       `json:"sizeBytes,omitempty"`
	Labels    []SafeLabel `json:"labels,omitempty"`
}

// ValidationError identifies invalid launch asset metadata by safe field names
// and fixed messages only. It never carries rejected input values.
type ValidationError struct {
	Code    ValidationCode `json:"code"`
	Field   string         `json:"field,omitempty"`
	Message string         `json:"message,omitempty"`
}

// ValidationResult is the deterministic output of pure descriptor validation.
type ValidationResult struct {
	Valid      bool              `json:"valid"`
	Normalized *LaunchDescriptor `json:"normalized,omitempty"`
	Errors     []ValidationError `json:"errors,omitempty"`
}

// ValidationErrors adapts validation failures to the error interface for
// callers that only need a pass/fail boundary.
type ValidationErrors []ValidationError
