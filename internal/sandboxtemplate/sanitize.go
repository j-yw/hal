package sandboxtemplate

// SanitizeTemplate returns durable-safe sandbox template metadata. Unsafe
// optional metadata is removed; records with unsafe required identifiers are
// omitted. No redaction placeholders are inserted.
func SanitizeTemplate(input Template) Template {
	normalized := NormalizeTemplate(input)
	applyWorkspaceSafetyDefaults(&normalized)

	var out Template
	if normalized.APIVersion == TemplateAPIVersionV1 {
		out.APIVersion = normalized.APIVersion
	}
	if normalized.Kind == TemplateKindSandbox {
		out.Kind = normalized.Kind
	}
	out.Metadata = sanitizeTemplateMetadata(normalized.Metadata)
	if out.Metadata.ID == "" {
		return Template{}
	}
	out.Runtime = sanitizeRuntimeRequirements(normalized.Runtime)
	out.Workspace = sanitizeWorkspaceRequirements(normalized.Workspace)
	out.Network = sanitizeNetworkRequirements(normalized.Network)
	out.Credentials = sanitizeCredentialRequirements(normalized.Credentials)
	out.Setup = sanitizeSetupCommands(normalized.Setup)
	return out
}

func sanitizeTemplateMetadata(metadata TemplateMetadata) TemplateMetadata {
	out := TemplateMetadata{
		ID:          sanitizeID(metadata.ID),
		Name:        sanitizeFreeText(metadata.Name),
		Version:     sanitizeVersion(metadata.Version),
		Description: sanitizeFreeText(metadata.Description),
		Labels:      sanitizeStringMap(metadata.Labels),
		Reference:   sanitizeReference(metadata.Reference),
		Annotations: sanitizeStringMap(metadata.Annotations),
		Digest:      sanitizeDigest(metadata.Digest),
	}
	if out.ID == "" {
		return TemplateMetadata{}
	}
	return out
}

func sanitizeRuntimeRequirements(runtime *RuntimeRequirements) *RuntimeRequirements {
	if runtime == nil {
		return nil
	}
	out := RuntimeRequirements{
		Image:     sanitizeReference(runtime.Image),
		Launch:    sanitizeLaunchRequirements(runtime.Launch),
		Resources: sanitizeResourceHints(runtime.Resources),
		Labels:    sanitizeStringMap(runtime.Labels),
	}
	if validRuntimeDriver(runtime.Driver) {
		out.Driver = runtime.Driver
	}
	if validIsolationLevel(runtime.IsolationLevel) {
		out.IsolationLevel = runtime.IsolationLevel
	}
	return &out
}

func sanitizeLaunchRequirements(launch *LaunchRequirements) *LaunchRequirements {
	if launch == nil {
		return nil
	}
	out := LaunchRequirements{
		Descriptor:    cloneLaunchDescriptor(launch.Descriptor),
		DescriptorRef: sanitizeReference(launch.DescriptorRef),
	}
	if out.Descriptor == nil && out.DescriptorRef == nil {
		return nil
	}
	return &out
}

func sanitizeResourceHints(resources *ResourceHints) *ResourceHints {
	if resources == nil {
		return nil
	}
	out := *resources
	if out.CPUCores < 0 {
		out.CPUCores = 0
	}
	if out.MemoryMB < 0 {
		out.MemoryMB = 0
	}
	if out.DiskGB < 0 {
		out.DiskGB = 0
	}
	return &out
}

func sanitizeWorkspaceRequirements(workspace *WorkspaceRequirements) *WorkspaceRequirements {
	if workspace == nil {
		return nil
	}
	out := WorkspaceRequirements{
		Ref:      sanitizeReference(workspace.Ref),
		ReadOnly: workspace.ReadOnly,
		Trusted:  workspace.Trusted,
		Unsafe:   workspace.Unsafe,
	}
	if validWorkspaceMode(workspace.Mode) {
		out.Mode = workspace.Mode
	}
	if validWorkspaceInputSource(workspace.InputSource) {
		out.InputSource = workspace.InputSource
	}
	if out.Mode == WorkspaceModeDirect && !out.Trusted {
		out.Unsafe = true
	}
	if out.Mode == WorkspaceModeClone || out.Mode == WorkspaceModeCopy {
		out.Unsafe = false
	}
	return &out
}

func sanitizeNetworkRequirements(network *NetworkRequirements) *NetworkRequirements {
	if network == nil {
		return nil
	}
	out := NetworkRequirements{
		Allow:                   sanitizeNetworkRules(network.Allow),
		BlockPrivateNetworks:    cloneBool(network.BlockPrivateNetworks),
		BlockMetadataEndpoints:  cloneBool(network.BlockMetadataEndpoints),
		RouteHTTPSThroughProxy:  cloneBool(network.RouteHTTPSThroughProxy),
		RequireFirewallSupport:  cloneBool(network.RequireFirewallSupport),
		PolicySnapshotReference: sanitizeReference(network.PolicySnapshotReference),
	}
	if validNetworkProfile(network.Profile) {
		out.Profile = network.Profile
	}
	return &out
}

func sanitizeNetworkRules(rules []NetworkRule) []NetworkRule {
	if rules == nil {
		return nil
	}
	out := make([]NetworkRule, 0, len(rules))
	for _, rule := range rules {
		clean := NetworkRule{
			ID: sanitizeID(rule.ID),
		}
		if validNetworkRuleCategory(rule.Kind) {
			clean.Kind = rule.Kind
		}
		if safeNetworkRuleValue(clean.Kind, rule.Value) {
			clean.Value = rule.Value
		}
		if clean.ID == "" || clean.Kind == "" || clean.Value == "" {
			continue
		}
		out = append(out, clean)
	}
	if len(out) == 0 && len(rules) > 0 {
		return nil
	}
	return out
}

func sanitizeCredentialRequirements(credentials *CredentialRequirements) *CredentialRequirements {
	if credentials == nil {
		return nil
	}
	return &CredentialRequirements{
		DeliveryModes: sanitizeCredentialModes(credentials.DeliveryModes),
		Services:      sanitizeCredentialServices(credentials.Services),
	}
}

func sanitizeCredentialModes(modes []CredentialDeliveryMode) []CredentialDeliveryMode {
	if modes == nil {
		return nil
	}
	out := make([]CredentialDeliveryMode, 0, len(modes))
	for _, mode := range modes {
		if validCredentialDeliveryMode(mode) && !credentialModeContains(out, mode) {
			out = append(out, mode)
		}
	}
	if len(out) == 0 && len(modes) > 0 {
		return nil
	}
	return out
}

func sanitizeCredentialServices(services []CredentialService) []CredentialService {
	if services == nil {
		return nil
	}
	out := make([]CredentialService, 0, len(services))
	for _, service := range services {
		clean := CredentialService{
			ID:            sanitizeID(service.ID),
			Domains:       sanitizeDomains(service.Domains),
			DeliveryModes: sanitizeCredentialModes(service.DeliveryModes),
			Required:      service.Required,
		}
		if clean.ID == "" {
			continue
		}
		out = append(out, clean)
	}
	if len(out) == 0 && len(services) > 0 {
		return nil
	}
	return out
}

func sanitizeSetupCommands(commands []SetupCommandMetadata) []SetupCommandMetadata {
	if commands == nil {
		return nil
	}
	out := make([]SetupCommandMetadata, 0, len(commands))
	for _, command := range commands {
		clean := SetupCommandMetadata{
			ID:              sanitizeID(command.ID),
			DisplayName:     sanitizeFreeText(command.DisplayName),
			Description:     sanitizeFreeText(command.Description),
			Tools:           sanitizeTools(command.Tools),
			Command:         sanitizeCommandParts(command.Command),
			WorkDir:         sanitizeWorkDir(command.WorkDir),
			RequiresNetwork: command.RequiresNetwork,
		}
		if command.TimeoutSeconds > 0 {
			clean.TimeoutSeconds = command.TimeoutSeconds
		}
		if clean.ID == "" {
			continue
		}
		out = append(out, clean)
	}
	if len(out) == 0 && len(commands) > 0 {
		return nil
	}
	return out
}

func sanitizeReference(ref *ImmutableRef) *ImmutableRef {
	if ref == nil {
		return nil
	}
	out := ImmutableRef{
		Digest: sanitizeDigest(ref.Digest),
	}
	if validReferenceKind(ref.Kind) {
		out.Kind = ref.Kind
	}
	if safeReferenceValue(ref.Ref, out.Kind) {
		out.Ref = ref.Ref
	}
	if out.Kind == "" && out.Ref == "" && out.Digest == nil {
		return nil
	}
	return &out
}

func sanitizeDigest(digest *DigestMetadata) *DigestMetadata {
	if digest == nil {
		return nil
	}
	if !validDigestAlgorithm(digest.Algorithm) || !validDigestValue(digest.Algorithm, digest.Value) {
		return nil
	}
	out := *digest
	return &out
}

func sanitizeStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		cleanKey := sanitizeID(key)
		cleanValue := sanitizeFreeText(value)
		if cleanKey == "" || cleanValue == "" {
			continue
		}
		out[cleanKey] = cleanValue
	}
	if len(out) == 0 && len(values) > 0 {
		return nil
	}
	return out
}

func sanitizeDomains(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if safeDomain(value) {
			out = append(out, value)
		}
	}
	if len(out) == 0 && len(values) > 0 {
		return nil
	}
	return out
}

func sanitizeTools(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if safeToolName(value) {
			out = append(out, value)
		}
	}
	if len(out) == 0 && len(values) > 0 {
		return nil
	}
	return out
}

func sanitizeCommandParts(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if safeCommandPart(value) {
			out = append(out, value)
		}
	}
	if len(out) == 0 && len(values) > 0 {
		return nil
	}
	return out
}

func sanitizeWorkDir(value string) string {
	if value == "" || !safeRelativeWorkDir(value) {
		return ""
	}
	return value
}

func sanitizeID(value string) string {
	if !safeID(value) {
		return ""
	}
	return value
}

func sanitizeVersion(value string) string {
	if value == "" || !safeVersion(value) {
		return ""
	}
	return value
}

func sanitizeFreeText(value string) string {
	if value == "" || unsafeFreeText(value) || rawHostPathLike(value) || credentialBearingURL(value) {
		return ""
	}
	return value
}

func credentialModeContains(values []CredentialDeliveryMode, want CredentialDeliveryMode) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
