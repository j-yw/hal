// Package sandboxtemplate defines portable sandbox runtime template contracts.
//
// These contracts are distinct from Hal project templates in internal/template:
// they describe sandbox runtime requirements and metadata only. They do not
// fetch artifacts, build images, start runtimes, contact networks, or deliver
// credentials.
package sandboxtemplate

import launchassets "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"

const (
	TemplateAPIVersionV1 TemplateAPIVersion = "sandbox-template.hal.dev/v1"
	TemplateKindSandbox  TemplateKind       = "SandboxTemplate"
)

const (
	RuntimeDriverSSHMachine     RuntimeDriver = "ssh_machine"
	RuntimeDriverRootlessPodman RuntimeDriver = "rootless_podman"
	RuntimeDriverMicroVM        RuntimeDriver = "microvm"
)

const (
	IsolationLevelHost      IsolationLevel = "host"
	IsolationLevelContainer IsolationLevel = "container"
	IsolationLevelVM        IsolationLevel = "vm"
)

const (
	WorkspaceModeClone  WorkspaceMode = "clone"
	WorkspaceModeCopy   WorkspaceMode = "copy"
	WorkspaceModeDirect WorkspaceMode = "direct"
)

const (
	WorkspaceInputRemoteRef WorkspaceInputSource = "remote_ref"
	WorkspaceInputGitBundle WorkspaceInputSource = "git_bundle"
	WorkspaceInputCopy      WorkspaceInputSource = "copy"
)

const (
	NetworkProfileDenyByDefault NetworkPolicyProfile = "deny_by_default"
	NetworkProfileAllowListed   NetworkPolicyProfile = "allow_listed"
	NetworkProfileBestEffort    NetworkPolicyProfile = "best_effort"
	NetworkProfileDisabled      NetworkPolicyProfile = "disabled"
)

const (
	NetworkRuleCategoryDomain         NetworkRuleCategory = "domain"
	NetworkRuleCategoryService        NetworkRuleCategory = "service"
	NetworkRuleCategoryPackageMirror  NetworkRuleCategory = "package_mirror"
	NetworkRuleCategoryPolicySnapshot NetworkRuleCategory = "policy_snapshot"
)

const (
	CredentialDeliveryModeHTTPProxy      CredentialDeliveryMode = "http_proxy"
	CredentialDeliveryModeSSHAgent       CredentialDeliveryMode = "ssh_agent"
	CredentialDeliveryModeFileTmpfs      CredentialDeliveryMode = "file_tmpfs"
	CredentialDeliveryModeEnv            CredentialDeliveryMode = "env"
	CredentialDeliveryModeLegacyAuthSync CredentialDeliveryMode = "legacy_auth_sync"
)

const (
	ReferenceKindOCIImage    ReferenceKind = "oci_image"
	ReferenceKindOCIArtifact ReferenceKind = "oci_artifact"
	ReferenceKindGit         ReferenceKind = "git"
	ReferenceKindLocal       ReferenceKind = "local"
	ReferenceKindInline      ReferenceKind = "inline"
)

const (
	DigestAlgorithmSHA256 DigestAlgorithm = "sha256"
	DigestAlgorithmSHA384 DigestAlgorithm = "sha384"
	DigestAlgorithmSHA512 DigestAlgorithm = "sha512"
)

type TemplateAPIVersion string
type TemplateKind string
type RuntimeDriver string
type IsolationLevel string
type WorkspaceMode string
type WorkspaceInputSource string
type NetworkPolicyProfile string
type NetworkRuleCategory string
type CredentialDeliveryMode string
type ReferenceKind string
type DigestAlgorithm string

// Template is the top-level portable sandbox template definition.
type Template struct {
	APIVersion  TemplateAPIVersion      `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind        TemplateKind            `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata    TemplateMetadata        `json:"metadata" yaml:"metadata"`
	Runtime     *RuntimeRequirements    `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	Workspace   *WorkspaceRequirements  `json:"workspace,omitempty" yaml:"workspace,omitempty"`
	Network     *NetworkRequirements    `json:"network,omitempty" yaml:"network,omitempty"`
	Credentials *CredentialRequirements `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	Setup       []SetupCommandMetadata  `json:"setup,omitempty" yaml:"setup,omitempty"`
}

// TemplateMetadata identifies a sandbox template using safe durable metadata.
type TemplateMetadata struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name,omitempty" yaml:"name,omitempty"`
	Version     string            `json:"version,omitempty" yaml:"version,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Reference   *ImmutableRef     `json:"reference,omitempty" yaml:"reference,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Digest      *DigestMetadata   `json:"digest,omitempty" yaml:"digest,omitempty"`
}

// ImmutableRef describes an immutable or externally addressable template input
// without fetching, resolving, or trusting that reference.
type ImmutableRef struct {
	Kind   ReferenceKind   `json:"kind,omitempty" yaml:"kind,omitempty"`
	Ref    string          `json:"ref,omitempty" yaml:"ref,omitempty"`
	Digest *DigestMetadata `json:"digest,omitempty" yaml:"digest,omitempty"`
}

// DigestMetadata records immutable digest identity using safe algorithm labels.
type DigestMetadata struct {
	Algorithm DigestAlgorithm `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Value     string          `json:"value,omitempty" yaml:"value,omitempty"`
}

// RuntimeRequirements describes the requested sandbox runtime shape.
type RuntimeRequirements struct {
	Driver         RuntimeDriver       `json:"driver,omitempty" yaml:"driver,omitempty"`
	IsolationLevel IsolationLevel      `json:"isolationLevel,omitempty" yaml:"isolationLevel,omitempty"`
	Image          *ImmutableRef       `json:"image,omitempty" yaml:"image,omitempty"`
	Launch         *LaunchRequirements `json:"launch,omitempty" yaml:"launch,omitempty"`
	Resources      *ResourceHints      `json:"resources,omitempty" yaml:"resources,omitempty"`
	Labels         map[string]string   `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// LaunchRequirements can embed or reference Phase 41 microVM launch assets.
type LaunchRequirements struct {
	Descriptor    *launchassets.LaunchDescriptor `json:"descriptor,omitempty" yaml:"descriptor,omitempty"`
	DescriptorRef *ImmutableRef                  `json:"descriptorRef,omitempty" yaml:"descriptorRef,omitempty"`
}

// ResourceHints carries requested resource metadata only.
type ResourceHints struct {
	CPUCores int `json:"cpuCores,omitempty" yaml:"cpuCores,omitempty"`
	MemoryMB int `json:"memoryMb,omitempty" yaml:"memoryMb,omitempty"`
	DiskGB   int `json:"diskGb,omitempty" yaml:"diskGb,omitempty"`
}

// WorkspaceRequirements describes workspace materialization intent.
type WorkspaceRequirements struct {
	Mode        WorkspaceMode        `json:"mode,omitempty" yaml:"mode,omitempty"`
	InputSource WorkspaceInputSource `json:"inputSource,omitempty" yaml:"inputSource,omitempty"`
	Ref         *ImmutableRef        `json:"ref,omitempty" yaml:"ref,omitempty"`
	ReadOnly    bool                 `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
}

// NetworkRequirements describes policy requirements without live enforcement.
type NetworkRequirements struct {
	Profile                 NetworkPolicyProfile `json:"profile,omitempty" yaml:"profile,omitempty"`
	Allow                   []NetworkRule        `json:"allow,omitempty" yaml:"allow,omitempty"`
	BlockPrivateNetworks    *bool                `json:"blockPrivateNetworks,omitempty" yaml:"blockPrivateNetworks,omitempty"`
	BlockMetadataEndpoints  *bool                `json:"blockMetadataEndpoints,omitempty" yaml:"blockMetadataEndpoints,omitempty"`
	RouteHTTPSThroughProxy  *bool                `json:"routeHttpsThroughProxy,omitempty" yaml:"routeHttpsThroughProxy,omitempty"`
	RequireFirewallSupport  *bool                `json:"requireFirewallSupport,omitempty" yaml:"requireFirewallSupport,omitempty"`
	PolicySnapshotReference *ImmutableRef        `json:"policySnapshotReference,omitempty" yaml:"policySnapshotReference,omitempty"`
}

// NetworkRule carries safe allowlist metadata only.
type NetworkRule struct {
	ID       string              `json:"id,omitempty" yaml:"id,omitempty"`
	Kind     NetworkRuleCategory `json:"kind,omitempty" yaml:"kind,omitempty"`
	Value    string              `json:"value,omitempty" yaml:"value,omitempty"`
	Port     int                 `json:"port,omitempty" yaml:"port,omitempty"`
	Protocol string              `json:"protocol,omitempty" yaml:"protocol,omitempty"`
}

// CredentialRequirements describes credential planning requirements.
type CredentialRequirements struct {
	DeliveryModes []CredentialDeliveryMode `json:"deliveryModes,omitempty" yaml:"deliveryModes,omitempty"`
	Services      []CredentialService      `json:"services,omitempty" yaml:"services,omitempty"`
}

// CredentialService describes one brokered service requirement.
type CredentialService struct {
	ID            string                   `json:"id" yaml:"id"`
	Domains       []string                 `json:"domains,omitempty" yaml:"domains,omitempty"`
	DeliveryModes []CredentialDeliveryMode `json:"deliveryModes,omitempty" yaml:"deliveryModes,omitempty"`
	Header        string                   `json:"header,omitempty" yaml:"header,omitempty"`
	Format        string                   `json:"format,omitempty" yaml:"format,omitempty"`
	Required      bool                     `json:"required,omitempty" yaml:"required,omitempty"`
}

// SetupCommandMetadata describes setup expectations without executing them.
type SetupCommandMetadata struct {
	ID              string   `json:"id" yaml:"id"`
	Description     string   `json:"description,omitempty" yaml:"description,omitempty"`
	Command         []string `json:"command,omitempty" yaml:"command,omitempty"`
	WorkDir         string   `json:"workDir,omitempty" yaml:"workDir,omitempty"`
	RequiresNetwork bool     `json:"requiresNetwork,omitempty" yaml:"requiresNetwork,omitempty"`
	TimeoutSeconds  int      `json:"timeoutSeconds,omitempty" yaml:"timeoutSeconds,omitempty"`
}
