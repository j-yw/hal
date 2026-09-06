package sandboxtemplate

import (
	"sort"
	"strings"

	launchassets "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

// NormalizeTemplate returns a normalized deep copy of tmpl.
func NormalizeTemplate(tmpl Template) Template {
	return Template{
		APIVersion:  TemplateAPIVersion(strings.TrimSpace(string(tmpl.APIVersion))),
		Kind:        TemplateKind(strings.TrimSpace(string(tmpl.Kind))),
		Metadata:    normalizeTemplateMetadata(tmpl.Metadata),
		Runtime:     normalizeRuntimeRequirements(tmpl.Runtime),
		Workspace:   normalizeWorkspaceRequirements(tmpl.Workspace),
		Network:     normalizeNetworkRequirements(tmpl.Network),
		Credentials: normalizeCredentialRequirements(tmpl.Credentials),
		Setup:       normalizeSetupCommandMetadataSlice(tmpl.Setup),
	}
}

func normalizeTemplateMetadata(metadata TemplateMetadata) TemplateMetadata {
	return TemplateMetadata{
		ID:          strings.TrimSpace(metadata.ID),
		Name:        strings.TrimSpace(metadata.Name),
		Version:     strings.TrimSpace(metadata.Version),
		Description: strings.TrimSpace(metadata.Description),
		Labels:      normalizeStringMap(metadata.Labels),
		Reference:   normalizeImmutableRef(metadata.Reference),
		Annotations: normalizeStringMap(metadata.Annotations),
		Digest:      normalizeDigestMetadata(metadata.Digest),
	}
}

func normalizeImmutableRef(ref *ImmutableRef) *ImmutableRef {
	if ref == nil {
		return nil
	}
	return &ImmutableRef{
		Kind:   normalizeReferenceKind(ref.Kind),
		Ref:    strings.TrimSpace(ref.Ref),
		Digest: normalizeDigestMetadata(ref.Digest),
	}
}

func normalizeDigestMetadata(digest *DigestMetadata) *DigestMetadata {
	if digest == nil {
		return nil
	}
	return &DigestMetadata{
		Algorithm: normalizeDigestAlgorithm(digest.Algorithm),
		Value:     strings.ToLower(strings.TrimSpace(digest.Value)),
	}
}

func normalizeRuntimeRequirements(runtime *RuntimeRequirements) *RuntimeRequirements {
	if runtime == nil {
		return nil
	}
	return &RuntimeRequirements{
		Driver:         normalizeRuntimeDriver(runtime.Driver),
		IsolationLevel: normalizeIsolationLevel(runtime.IsolationLevel),
		Image:          normalizeImmutableRef(runtime.Image),
		Launch:         normalizeLaunchRequirements(runtime.Launch),
		Resources:      normalizeResourceHints(runtime.Resources),
		Labels:         normalizeStringMap(runtime.Labels),
	}
}

func normalizeLaunchRequirements(launch *LaunchRequirements) *LaunchRequirements {
	if launch == nil {
		return nil
	}
	return &LaunchRequirements{
		Descriptor:    cloneLaunchDescriptor(launch.Descriptor),
		DescriptorRef: normalizeImmutableRef(launch.DescriptorRef),
	}
}

func normalizeResourceHints(resources *ResourceHints) *ResourceHints {
	if resources == nil {
		return nil
	}
	return &ResourceHints{
		CPUCores: resources.CPUCores,
		MemoryMB: resources.MemoryMB,
		DiskGB:   resources.DiskGB,
	}
}

func normalizeWorkspaceRequirements(workspace *WorkspaceRequirements) *WorkspaceRequirements {
	if workspace == nil {
		return nil
	}
	return &WorkspaceRequirements{
		Mode:        normalizeWorkspaceMode(workspace.Mode),
		InputSource: normalizeWorkspaceInputSource(workspace.InputSource),
		Ref:         normalizeImmutableRef(workspace.Ref),
		ReadOnly:    workspace.ReadOnly,
		Trusted:     workspace.Trusted,
		Unsafe:      workspace.Unsafe,
	}
}

func normalizeNetworkRequirements(network *NetworkRequirements) *NetworkRequirements {
	if network == nil {
		return nil
	}
	return &NetworkRequirements{
		Profile:                 normalizeNetworkPolicyProfile(network.Profile),
		Allow:                   normalizeNetworkRuleSlice(network.Allow),
		BlockPrivateNetworks:    cloneBool(network.BlockPrivateNetworks),
		BlockMetadataEndpoints:  cloneBool(network.BlockMetadataEndpoints),
		RouteHTTPSThroughProxy:  cloneBool(network.RouteHTTPSThroughProxy),
		RequireFirewallSupport:  cloneBool(network.RequireFirewallSupport),
		PolicySnapshotReference: normalizeImmutableRef(network.PolicySnapshotReference),
	}
}

func normalizeNetworkRuleSlice(rules []NetworkRule) []NetworkRule {
	if rules == nil {
		return nil
	}
	normalized := make([]NetworkRule, len(rules))
	for i, rule := range rules {
		normalized[i] = NetworkRule{
			ID:    strings.TrimSpace(rule.ID),
			Kind:  normalizeNetworkRuleCategory(rule.Kind),
			Value: strings.TrimSpace(rule.Value),
		}
	}
	return normalized
}

func normalizeCredentialRequirements(credentials *CredentialRequirements) *CredentialRequirements {
	if credentials == nil {
		return nil
	}
	return &CredentialRequirements{
		DeliveryModes: normalizeCredentialDeliveryModeSlice(credentials.DeliveryModes),
		Services:      normalizeCredentialServiceSlice(credentials.Services),
	}
}

func normalizeCredentialDeliveryModeSlice(modes []CredentialDeliveryMode) []CredentialDeliveryMode {
	if modes == nil {
		return nil
	}
	normalized := make([]CredentialDeliveryMode, len(modes))
	for i, mode := range modes {
		normalized[i] = normalizeCredentialDeliveryMode(mode)
	}
	return normalized
}

func normalizeCredentialServiceSlice(services []CredentialService) []CredentialService {
	if services == nil {
		return nil
	}
	normalized := make([]CredentialService, len(services))
	for i, service := range services {
		normalized[i] = CredentialService{
			ID:            strings.TrimSpace(service.ID),
			Domains:       trimStringSlice(service.Domains),
			DeliveryModes: normalizeCredentialDeliveryModeSlice(service.DeliveryModes),
			Required:      service.Required,
		}
	}
	return normalized
}

func normalizeSetupCommandMetadataSlice(setup []SetupCommandMetadata) []SetupCommandMetadata {
	if setup == nil {
		return nil
	}
	normalized := make([]SetupCommandMetadata, len(setup))
	for i, command := range setup {
		normalized[i] = SetupCommandMetadata{
			ID:              strings.TrimSpace(command.ID),
			DisplayName:     strings.TrimSpace(command.DisplayName),
			Description:     strings.TrimSpace(command.Description),
			Tools:           trimStringSlice(command.Tools),
			Command:         cloneStringSlice(command.Command),
			WorkDir:         strings.TrimSpace(command.WorkDir),
			RequiresNetwork: command.RequiresNetwork,
			TimeoutSeconds:  command.TimeoutSeconds,
		}
	}
	return normalized
}

func normalizeRuntimeDriver(driver RuntimeDriver) RuntimeDriver {
	switch normalizeToken(string(driver)) {
	case "sshmachine":
		return RuntimeDriverSSHMachine
	case string(RuntimeDriverRootlessPodman):
		return RuntimeDriverRootlessPodman
	case string(RuntimeDriverMicroVM):
		return RuntimeDriverMicroVM
	default:
		return RuntimeDriver(normalizeToken(string(driver)))
	}
}

func normalizeIsolationLevel(level IsolationLevel) IsolationLevel {
	switch normalizeToken(string(level)) {
	case string(IsolationLevelHost):
		return IsolationLevelHost
	case string(IsolationLevelContainer):
		return IsolationLevelContainer
	case string(IsolationLevelVM):
		return IsolationLevelVM
	default:
		return IsolationLevel(normalizeToken(string(level)))
	}
}

func normalizeWorkspaceMode(mode WorkspaceMode) WorkspaceMode {
	switch normalizeToken(string(mode)) {
	case string(WorkspaceModeClone):
		return WorkspaceModeClone
	case string(WorkspaceModeCopy):
		return WorkspaceModeCopy
	case string(WorkspaceModeDirect):
		return WorkspaceModeDirect
	default:
		return WorkspaceMode(normalizeToken(string(mode)))
	}
}

func normalizeWorkspaceInputSource(source WorkspaceInputSource) WorkspaceInputSource {
	switch normalizeToken(string(source)) {
	case string(WorkspaceInputRemoteRef):
		return WorkspaceInputRemoteRef
	case string(WorkspaceInputGitBundle):
		return WorkspaceInputGitBundle
	case string(WorkspaceInputCopy):
		return WorkspaceInputCopy
	default:
		return WorkspaceInputSource(normalizeToken(string(source)))
	}
}

func normalizeNetworkPolicyProfile(profile NetworkPolicyProfile) NetworkPolicyProfile {
	switch normalizeToken(string(profile)) {
	case string(NetworkProfileDenyByDefault):
		return NetworkProfileDenyByDefault
	case string(NetworkProfileAllowListed):
		return NetworkProfileAllowListed
	case string(NetworkProfileBestEffort):
		return NetworkProfileBestEffort
	case string(NetworkProfileDisabled):
		return NetworkProfileDisabled
	default:
		return NetworkPolicyProfile(normalizeToken(string(profile)))
	}
}

func normalizeNetworkRuleCategory(category NetworkRuleCategory) NetworkRuleCategory {
	switch normalizeToken(string(category)) {
	case string(NetworkRuleCategoryDomain):
		return NetworkRuleCategoryDomain
	case string(NetworkRuleCategoryService):
		return NetworkRuleCategoryService
	case string(NetworkRuleCategoryPackageMirror):
		return NetworkRuleCategoryPackageMirror
	case string(NetworkRuleCategoryPolicySnapshot):
		return NetworkRuleCategoryPolicySnapshot
	default:
		return NetworkRuleCategory(normalizeToken(string(category)))
	}
}

func normalizeCredentialDeliveryMode(mode CredentialDeliveryMode) CredentialDeliveryMode {
	switch normalizeToken(string(mode)) {
	case string(CredentialDeliveryModeHTTPProxy):
		return CredentialDeliveryModeHTTPProxy
	case string(CredentialDeliveryModeSSHAgent):
		return CredentialDeliveryModeSSHAgent
	case string(CredentialDeliveryModeFileTmpfs):
		return CredentialDeliveryModeFileTmpfs
	case string(CredentialDeliveryModeEnv):
		return CredentialDeliveryModeEnv
	case string(CredentialDeliveryModeLegacyAuthSync):
		return CredentialDeliveryModeLegacyAuthSync
	default:
		return CredentialDeliveryMode(normalizeToken(string(mode)))
	}
}

func normalizeReferenceKind(kind ReferenceKind) ReferenceKind {
	switch normalizeToken(string(kind)) {
	case string(ReferenceKindOCIImage):
		return ReferenceKindOCIImage
	case string(ReferenceKindOCIArtifact):
		return ReferenceKindOCIArtifact
	case string(ReferenceKindGit):
		return ReferenceKindGit
	case string(ReferenceKindLocal):
		return ReferenceKindLocal
	case string(ReferenceKindInline):
		return ReferenceKindInline
	default:
		return ReferenceKind(normalizeToken(string(kind)))
	}
}

func normalizeDigestAlgorithm(algorithm DigestAlgorithm) DigestAlgorithm {
	switch normalizeToken(string(algorithm)) {
	case "sha_256":
		return DigestAlgorithmSHA256
	case "sha_384":
		return DigestAlgorithmSHA384
	case "sha_512":
		return DigestAlgorithmSHA512
	case string(DigestAlgorithmSHA256):
		return DigestAlgorithmSHA256
	case string(DigestAlgorithmSHA384):
		return DigestAlgorithmSHA384
	case string(DigestAlgorithmSHA512):
		return DigestAlgorithmSHA512
	default:
		return DigestAlgorithm(normalizeToken(string(algorithm)))
	}
}

func normalizeStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	normalized := make(map[string]string, len(values))
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		normalized[strings.TrimSpace(key)] = strings.TrimSpace(values[key])
	}
	return normalized
}

func normalizeToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func trimStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	normalized := make([]string, len(values))
	for i, value := range values {
		normalized[i] = strings.TrimSpace(value)
	}
	return normalized
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

func cloneLaunchDescriptor(descriptor *launchassets.LaunchDescriptor) *launchassets.LaunchDescriptor {
	if descriptor == nil {
		return nil
	}
	return &launchassets.LaunchDescriptor{
		ID:     descriptor.ID,
		Labels: cloneLaunchSafeLabels(descriptor.Labels),
		Assets: cloneLaunchAssets(descriptor.Assets),
	}
}

func cloneLaunchAssets(assets []launchassets.LaunchAsset) []launchassets.LaunchAsset {
	if assets == nil {
		return nil
	}
	clone := make([]launchassets.LaunchAsset, len(assets))
	for i, asset := range assets {
		clone[i] = launchassets.LaunchAsset{
			ID:          asset.ID,
			Role:        asset.Role,
			Kind:        asset.Kind,
			Labels:      cloneLaunchSafeLabels(asset.Labels),
			Source:      cloneLaunchAssetSource(asset.Source),
			Lock:        asset.Lock,
			InitConfig:  cloneLaunchInitConfig(asset.InitConfig),
			AgentConfig: cloneLaunchAgentConfig(asset.AgentConfig),
			Resources:   cloneLaunchResources(asset.Resources),
		}
	}
	return clone
}

func cloneLaunchAssetSource(source launchassets.AssetSource) launchassets.AssetSource {
	return launchassets.AssetSource{
		Type:     source.Type,
		HostPath: cloneLaunchHostPath(source.HostPath),
	}
}

func cloneLaunchHostPath(hostPath *launchassets.HostPathMetadata) *launchassets.HostPathMetadata {
	if hostPath == nil {
		return nil
	}
	return &launchassets.HostPathMetadata{
		Path: hostPath.Path,
		Role: hostPath.Role,
	}
}

func cloneLaunchInitConfig(config *launchassets.InitConfigMetadata) *launchassets.InitConfigMetadata {
	if config == nil {
		return nil
	}
	return &launchassets.InitConfigMetadata{
		Format:     config.Format,
		EntryPoint: config.EntryPoint,
		Labels:     cloneLaunchSafeLabels(config.Labels),
	}
}

func cloneLaunchAgentConfig(config *launchassets.AgentConfigMetadata) *launchassets.AgentConfigMetadata {
	if config == nil {
		return nil
	}
	return &launchassets.AgentConfigMetadata{
		Protocol: config.Protocol,
		Version:  config.Version,
		Features: cloneLaunchSafeLabels(config.Features),
	}
}

func cloneLaunchResources(resources []launchassets.ResourceMetadata) []launchassets.ResourceMetadata {
	if resources == nil {
		return nil
	}
	clone := make([]launchassets.ResourceMetadata, len(resources))
	for i, resource := range resources {
		clone[i] = launchassets.ResourceMetadata{
			ID:        resource.ID,
			Kind:      resource.Kind,
			SizeBytes: resource.SizeBytes,
			Labels:    cloneLaunchSafeLabels(resource.Labels),
		}
	}
	return clone
}

func cloneLaunchSafeLabels(labels []launchassets.SafeLabel) []launchassets.SafeLabel {
	if labels == nil {
		return nil
	}
	clone := make([]launchassets.SafeLabel, len(labels))
	copy(clone, labels)
	return clone
}
