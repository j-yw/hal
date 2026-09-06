package sandboxtemplate

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	launchassets "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

// Projection is the data-only result of applying a sandbox template to
// existing sandbox runtime v2 metadata surfaces.
type Projection struct {
	Runtime        sandboxruntime.RuntimeState
	Workspace      sandbox.SandboxWorkspace
	WorkspaceTrust WorkspaceTrustMetadata
	Security       sandbox.SandboxSecurity
	NetworkPolicy  *sandbox.SandboxNetworkPolicyIntent
	SecretDelivery *sandbox.SandboxSecretDeliveryIntent
}

// WorkspaceTrustMetadata carries direct-workspace safety labels that do not yet
// have a durable field on sandbox.SandboxWorkspace.
type WorkspaceTrustMetadata struct {
	Trusted bool `json:"trusted,omitempty"`
	Unsafe  bool `json:"unsafe,omitempty"`
}

// ProjectTemplate maps sanitized template metadata into existing sandbox DTOs.
func ProjectTemplate(tmpl Template, base Projection) Projection {
	safe := SanitizeTemplate(tmpl)
	base.Runtime = ProjectRuntimeState(safe, base.Runtime)
	base.Workspace, base.WorkspaceTrust = ProjectWorkspace(safe, base.Workspace)
	base.NetworkPolicy = ProjectNetworkPolicyIntent(safe)
	base.SecretDelivery = ProjectSecretDeliveryIntent(safe)
	base.Security = ProjectSecurity(safe, base.Security)
	return base
}

// ProjectRuntimeState maps runtime and launch intent into sandboxruntime
// metadata only. It never selects, starts, or inspects a runtime.
func ProjectRuntimeState(tmpl Template, base sandboxruntime.RuntimeState) sandboxruntime.RuntimeState {
	if tmpl.Runtime == nil {
		return base
	}
	if driver := sandboxRuntimeDriver(tmpl.Runtime.Driver); driver != "" {
		base.Driver = driver
	}
	if isolation := sandboxIsolationLevel(tmpl.Runtime.IsolationLevel); isolation != "" {
		base.IsolationLevel = isolation
	}
	if image := referenceDisplay(tmpl.Runtime.Image); image != "" {
		base.Image = image
	}
	metadata := cloneRuntimeMetadata(base.Metadata)
	metadata.Backend = base.Driver
	if metadata.Backend == "" {
		metadata.Backend = sandboxRuntimeDriver(tmpl.Runtime.Driver)
	}
	if tmpl.Runtime.Launch != nil {
		metadata.OperationPlan = projectLaunchOperationPlan(tmpl.Runtime.Launch)
	}
	if metadata.Backend != "" || metadata.OperationPlan != nil {
		base.Metadata = metadata
	}
	return base
}

// ProjectWorkspace maps workspace intent into durable sandbox workspace
// metadata without applying, syncing, cloning, copying, or mutating files.
func ProjectWorkspace(tmpl Template, base sandbox.SandboxWorkspace) (sandbox.SandboxWorkspace, WorkspaceTrustMetadata) {
	var trust WorkspaceTrustMetadata
	if tmpl.Workspace == nil {
		return base, trust
	}
	if mode := sandboxWorkspaceMode(tmpl.Workspace.Mode); mode != "" {
		base.Mode = mode
	}
	if source := sandboxWorkspaceInputSource(tmpl.Workspace.InputSource); source != "" {
		base.InputSource = source
	}
	trust.Trusted = tmpl.Workspace.Trusted
	trust.Unsafe = tmpl.Workspace.Unsafe
	if tmpl.Workspace.Mode == WorkspaceModeDirect && !tmpl.Workspace.Trusted {
		trust.Unsafe = true
	}
	if tmpl.Workspace.Mode == WorkspaceModeClone || tmpl.Workspace.Mode == WorkspaceModeCopy {
		trust.Unsafe = false
	}
	return base, trust
}

// ProjectNetworkPolicyIntent maps safe network requirements to sandbox network
// policy intent. It does not claim live enforcement.
func ProjectNetworkPolicyIntent(tmpl Template) *sandbox.SandboxNetworkPolicyIntent {
	if tmpl.Network == nil {
		return nil
	}
	intent := sandbox.SandboxNetworkPolicyIntent{
		Preset: sandboxNetworkPolicyPreset(tmpl.Network.Profile),
	}
	for _, rule := range tmpl.Network.Allow {
		if rule.Kind != NetworkRuleCategoryDomain || rule.Value == "" {
			continue
		}
		intent.Rules = append(intent.Rules, sandbox.SandboxNetworkPolicyRule{
			Kind:     sandbox.SandboxNetworkPolicyRuleKindDomain,
			Value:    rule.Value,
			Decision: sandbox.SandboxNetworkPolicyDecisionAllow,
		})
	}
	return &intent
}

// ProjectSecretDeliveryIntent maps credential requirements to requested secret
// delivery modes only. Active modes are intentionally left empty.
func ProjectSecretDeliveryIntent(tmpl Template) *sandbox.SandboxSecretDeliveryIntent {
	if tmpl.Credentials == nil {
		return nil
	}
	var requested []string
	for _, mode := range tmpl.Credentials.DeliveryModes {
		requested = appendSandboxString(requested, sandboxSecretMode(mode))
	}
	for _, service := range tmpl.Credentials.Services {
		for _, mode := range service.DeliveryModes {
			requested = appendSandboxString(requested, sandboxSecretMode(mode))
		}
	}
	return &sandbox.SandboxSecretDeliveryIntent{RequestedModes: requested}
}

// ProjectSecurity maps template security requirements into sandbox security
// metadata while keeping enforcement and credential delivery claims honest.
func ProjectSecurity(tmpl Template, base sandbox.SandboxSecurity) sandbox.SandboxSecurity {
	if network := ProjectNetworkPolicyIntent(tmpl); network != nil {
		base.Network = &sandbox.SandboxNetworkSecurity{
			PolicyRequested: string(network.Preset),
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
		}
	}
	if secrets := ProjectSecretDeliveryIntent(tmpl); secrets != nil {
		base.Secrets = &sandbox.SandboxSecretSecurity{
			RequestedModes: append([]string(nil), secrets.RequestedModes...),
		}
	}
	return base
}

func projectLaunchOperationPlan(launch *LaunchRequirements) *sandboxruntime.RuntimeOperationPlan {
	if launch == nil {
		return nil
	}
	plan := &sandboxruntime.RuntimeOperationPlan{Action: "template_launch_metadata"}
	if launch.Descriptor != nil {
		plan.Payloads = append(plan.Payloads, sandboxruntime.RuntimeOperationPayload{
			Role:   "launch_descriptor",
			Assets: projectLaunchAssets(launch.Descriptor.Assets),
		})
	}
	if launch.DescriptorRef != nil {
		payload := sandboxruntime.RuntimeOperationPayload{Role: "launch_descriptor_ref"}
		if ReferenceDigestPinned(launch.DescriptorRef) {
			payload.Assets = []sandboxruntime.RuntimeOperationPayloadAsset{{
				ID: "launch-descriptor-ref",
				Digest: &sandboxruntime.RuntimeOperationPayloadDigest{
					Algorithm: string(launch.DescriptorRef.Digest.Algorithm),
					Value:     launch.DescriptorRef.Digest.Value,
				},
			}}
		}
		plan.Payloads = append(plan.Payloads, payload)
	}
	if len(plan.Payloads) == 0 {
		return nil
	}
	return plan
}

func projectLaunchAssets(assets []launchassets.LaunchAsset) []sandboxruntime.RuntimeOperationPayloadAsset {
	if assets == nil {
		return nil
	}
	out := make([]sandboxruntime.RuntimeOperationPayloadAsset, 0, len(assets))
	for _, asset := range assets {
		projected := sandboxruntime.RuntimeOperationPayloadAsset{
			AssetRole: string(asset.Role),
			ID:        string(asset.ID),
			Labels:    launchLabels(asset.Labels),
		}
		if asset.Lock.Digest.Algorithm != "" && asset.Lock.Digest.Value != "" {
			projected.Digest = &sandboxruntime.RuntimeOperationPayloadDigest{
				Algorithm: string(asset.Lock.Digest.Algorithm),
				Value:     asset.Lock.Digest.Value,
			}
		}
		out = append(out, projected)
	}
	return out
}

func launchLabels(labels []launchassets.SafeLabel) []string {
	if labels == nil {
		return nil
	}
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		if trimmed := strings.TrimSpace(string(label)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func cloneRuntimeMetadata(metadata *sandboxruntime.RuntimeMetadata) *sandboxruntime.RuntimeMetadata {
	if metadata == nil {
		return &sandboxruntime.RuntimeMetadata{}
	}
	out := *metadata
	out.CapabilityLabels = append([]string(nil), metadata.CapabilityLabels...)
	out.PathRoles = append([]string(nil), metadata.PathRoles...)
	return &out
}

func referenceDisplay(ref *ImmutableRef) string {
	if ref == nil || strings.TrimSpace(ref.Ref) == "" {
		return ""
	}
	if ReferenceDigestPinned(ref) {
		return ref.Ref + "@" + string(ref.Digest.Algorithm) + ":" + ref.Digest.Value
	}
	return ref.Ref
}

func sandboxRuntimeDriver(driver RuntimeDriver) string {
	switch driver {
	case RuntimeDriverSSHMachine:
		return sandboxruntime.DriverSSHMachine
	case RuntimeDriverRootlessPodman:
		return sandboxruntime.DriverRootlessPodman
	case RuntimeDriverMicroVM:
		return sandboxruntime.DriverMicroVM
	default:
		return ""
	}
}

func sandboxIsolationLevel(level IsolationLevel) string {
	switch level {
	case IsolationLevelHost:
		return sandbox.SandboxIsolationLevelHost
	case IsolationLevelContainer:
		return sandbox.SandboxIsolationLevelContainer
	case IsolationLevelVM:
		return sandbox.SandboxIsolationLevelVM
	default:
		return ""
	}
}

func sandboxWorkspaceMode(mode WorkspaceMode) string {
	switch mode {
	case WorkspaceModeClone:
		return sandbox.SandboxWorkspaceModeClone
	case WorkspaceModeCopy:
		return sandbox.SandboxWorkspaceModeCopy
	case WorkspaceModeDirect:
		return sandbox.SandboxWorkspaceModeDirect
	default:
		return ""
	}
}

func sandboxWorkspaceInputSource(source WorkspaceInputSource) string {
	switch source {
	case WorkspaceInputRemoteRef:
		return sandbox.SandboxWorkspaceInputSourceRemoteRef
	case WorkspaceInputGitBundle:
		return sandbox.SandboxWorkspaceInputSourceGitBundle
	case WorkspaceInputCopy:
		return sandbox.SandboxWorkspaceInputSourceCopy
	default:
		return ""
	}
}

func sandboxNetworkPolicyPreset(profile NetworkPolicyProfile) sandbox.SandboxNetworkPolicyPreset {
	switch profile {
	case NetworkProfileDenyByDefault:
		return sandbox.SandboxNetworkPolicyPresetDenyByDefault
	case NetworkProfileAllowListed:
		return sandbox.SandboxNetworkPolicyPresetAllowListed
	case NetworkProfileDisabled:
		return sandbox.SandboxNetworkPolicyPresetDisabled
	case NetworkProfileBestEffort:
		return sandbox.SandboxNetworkPolicyPresetLegacyDefault
	default:
		return ""
	}
}

func sandboxSecretMode(mode CredentialDeliveryMode) string {
	switch mode {
	case CredentialDeliveryModeHTTPProxy:
		return sandbox.SandboxSecretModeHTTPProxy
	case CredentialDeliveryModeSSHAgent:
		return sandbox.SandboxSecretModeSSHAgent
	case CredentialDeliveryModeFileTmpfs:
		return sandbox.SandboxSecretModeFileTmpfs
	case CredentialDeliveryModeEnv:
		return sandbox.SandboxSecretModeEnv
	case CredentialDeliveryModeLegacyAuthSync:
		return sandbox.SandboxSecretModeLegacyAuthSync
	default:
		return ""
	}
}

func appendSandboxString(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
