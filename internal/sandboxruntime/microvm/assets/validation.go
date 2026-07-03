package assets

import "strings"

const (
	maxSafeIDBytes    = 128
	maxSafeLabelBytes = 128
)

// ValidateLaunchDescriptor returns nil only when descriptor metadata is
// structurally valid and has the required kernel/rootfs launch roles.
func ValidateLaunchDescriptor(descriptor LaunchDescriptor) error {
	result := ValidateAndNormalizeLaunchDescriptor(descriptor)
	if result.Valid {
		return nil
	}
	return ValidationErrors(append([]ValidationError(nil), result.Errors...))
}

// ValidateAndNormalizeLaunchDescriptor validates backend-neutral launch asset
// metadata without resolving paths, hashing files, contacting networks, or
// invoking a runtime.
func ValidateAndNormalizeLaunchDescriptor(descriptor LaunchDescriptor) ValidationResult {
	normalized := normalizeLaunchDescriptor(descriptor)
	result := ValidationResult{Valid: true}

	if normalized.ID != "" && !safeLaunchAssetID(normalized.ID) {
		result.addError("id", ValidationUnsafeID, "descriptor id must be a safe identifier")
	}
	validateSafeLabels(&result, "labels", normalized.Labels, "descriptor label must be safe metadata")

	roleCounts := map[AssetRole]int{}
	for i, asset := range normalized.Assets {
		validateLaunchAsset(&result, i, asset)
		if validAssetRole(asset.Role) {
			roleCounts[asset.Role]++
			if requiredAssetRole(asset.Role) && roleCounts[asset.Role] > 1 {
				result.addError(assetField(i, "role"), ValidationDuplicateRequiredRole, "required asset role must be unique")
			}
		}
	}

	if roleCounts[AssetRoleKernel] == 0 {
		result.addError("assets", ValidationMissingRequiredRole, "kernel asset is required")
	}
	if roleCounts[AssetRoleRootfs] == 0 {
		result.addError("assets", ValidationMissingRequiredRole, "rootfs asset is required")
	}

	if len(result.Errors) > 0 {
		result.Valid = false
		return result
	}
	result.Normalized = &normalized
	return result
}

func validateLaunchAsset(result *ValidationResult, index int, asset LaunchAsset) {
	if asset.ID == "" {
		result.addError(assetField(index, "id"), ValidationMissingRequiredField, "asset id is required")
	} else if !safeLaunchAssetID(asset.ID) {
		result.addError(assetField(index, "id"), ValidationUnsafeID, "asset id must be a safe identifier")
	}

	if asset.Role == "" {
		result.addError(assetField(index, "role"), ValidationMissingRequiredField, "asset role is required")
	} else if !validAssetRole(asset.Role) {
		result.addError(assetField(index, "role"), ValidationUnsupportedRole, "asset role is unsupported")
	}

	if asset.Kind == "" {
		result.addError(assetField(index, "kind"), ValidationMissingRequiredField, "asset kind is required")
	} else if !validAssetKind(asset.Kind) {
		result.addError(assetField(index, "kind"), ValidationUnsupportedKind, "asset kind is unsupported")
	}

	validateSafeLabels(result, assetField(index, "labels"), asset.Labels, "asset label must be safe metadata")
	validateAssetSource(result, index, asset.Source)
	validateLockMetadata(result, index, asset.Lock)
	validateInitConfigMetadata(result, index, asset.InitConfig)
	validateAgentConfigMetadata(result, index, asset.AgentConfig)
	validateResourceMetadata(result, index, asset.Resources)
}

func validateAssetSource(result *ValidationResult, index int, source AssetSource) {
	if source.Type == "" {
		result.addError(assetField(index, "source.type"), ValidationMissingRequiredField, "asset source type is required")
	} else if !validSourceType(source.Type) {
		result.addError(assetField(index, "source.type"), ValidationUnsupportedSourceType, "asset source type is unsupported")
	}

	if source.Type == SourceTypeLocalFile && source.HostPath == nil {
		result.addError(assetField(index, "source.hostPath"), ValidationMissingRequiredField, "local file asset host path is required")
	}
	if source.HostPath == nil {
		return
	}
	if strings.TrimSpace(source.HostPath.Path) == "" {
		result.addError(assetField(index, "source.hostPath.path"), ValidationMissingRequiredField, "asset host path is required")
	}
	if source.HostPath.Role == "" {
		result.addError(assetField(index, "source.hostPath.role"), ValidationMissingRequiredField, "asset host path role is required")
	} else if !validHostPathRole(source.HostPath.Role) {
		result.addError(assetField(index, "source.hostPath.role"), ValidationUnsupportedHostPathRole, "asset host path role is unsupported")
	}
}

func validateLockMetadata(result *ValidationResult, index int, lock LockMetadata) {
	algorithm := lock.Digest.Algorithm
	switch {
	case algorithm == "":
		result.addError(assetField(index, "lock.digest.algorithm"), ValidationMalformedDigestAlgorithm, "digest algorithm is required")
	case !validDigestAlgorithm(algorithm):
		result.addError(assetField(index, "lock.digest.algorithm"), ValidationMalformedDigestAlgorithm, "digest algorithm is unsupported")
	}

	value := lock.Digest.Value
	if strings.TrimSpace(value) == "" {
		result.addError(assetField(index, "lock.digest.value"), ValidationMalformedDigestValue, "digest value is required")
	} else if expected := digestValueLength(algorithm); expected > 0 && len(value) != expected {
		result.addError(assetField(index, "lock.digest.value"), ValidationMalformedDigestValue, "digest value length does not match algorithm")
	} else if !lowerHexDigestValue(value) {
		result.addError(assetField(index, "lock.digest.value"), ValidationMalformedDigestValue, "digest value must be lowercase hexadecimal")
	}

	if lock.SizeBytes < 0 {
		result.addError(assetField(index, "lock.sizeBytes"), ValidationInvalidMetadata, "lock size must be non-negative")
	}
	if lock.LockedAtUnixMillis < 0 {
		result.addError(assetField(index, "lock.lockedAtUnixMillis"), ValidationInvalidMetadata, "lock timestamp must be non-negative")
	}
}

func validateInitConfigMetadata(result *ValidationResult, index int, initConfig *InitConfigMetadata) {
	if initConfig == nil {
		return
	}
	if initConfig.Format != "" && !safeLaunchAssetLabel(initConfig.Format) {
		result.addError(assetField(index, "initConfig.format"), ValidationUnsafeLabel, "init config format must be safe metadata")
	}
	if initConfig.EntryPoint != "" && !safeLaunchAssetLabel(initConfig.EntryPoint) {
		result.addError(assetField(index, "initConfig.entryPoint"), ValidationUnsafeLabel, "init config entry point must be safe metadata")
	}
	validateSafeLabels(result, assetField(index, "initConfig.labels"), initConfig.Labels, "init config label must be safe metadata")
}

func validateAgentConfigMetadata(result *ValidationResult, index int, agentConfig *AgentConfigMetadata) {
	if agentConfig == nil {
		return
	}
	if agentConfig.Protocol != "" && !safeLaunchAssetLabel(agentConfig.Protocol) {
		result.addError(assetField(index, "agentConfig.protocol"), ValidationUnsafeLabel, "agent config protocol must be safe metadata")
	}
	if agentConfig.Version != "" && !safeLaunchAssetLabel(agentConfig.Version) {
		result.addError(assetField(index, "agentConfig.version"), ValidationUnsafeLabel, "agent config version must be safe metadata")
	}
	validateSafeLabels(result, assetField(index, "agentConfig.features"), agentConfig.Features, "agent config feature must be safe metadata")
}

func validateResourceMetadata(result *ValidationResult, index int, resources []ResourceMetadata) {
	for i, resource := range resources {
		prefix := assetField(index, "resources["+itoa(i)+"]")
		if resource.ID != "" && !safeLaunchAssetID(resource.ID) {
			result.addError(prefix+".id", ValidationUnsafeID, "resource id must be a safe identifier")
		}
		if resource.Kind != "" && !safeLaunchAssetLabel(resource.Kind) {
			result.addError(prefix+".kind", ValidationUnsafeLabel, "resource kind must be safe metadata")
		}
		if resource.SizeBytes < 0 {
			result.addError(prefix+".sizeBytes", ValidationInvalidMetadata, "resource size must be non-negative")
		}
		validateSafeLabels(result, prefix+".labels", resource.Labels, "resource label must be safe metadata")
	}
}

func validateSafeLabels(result *ValidationResult, field string, labels []SafeLabel, message string) {
	for _, label := range labels {
		if !safeLaunchAssetLabel(label) {
			result.addError(field, ValidationUnsafeLabel, message)
			return
		}
	}
}

func normalizeLaunchDescriptor(descriptor LaunchDescriptor) LaunchDescriptor {
	normalized := LaunchDescriptor{
		ID: SafeID(strings.TrimSpace(string(descriptor.ID))),
	}
	if descriptor.Labels != nil {
		normalized.Labels = normalizeSafeLabels(descriptor.Labels)
	}
	if descriptor.Assets != nil {
		normalized.Assets = make([]LaunchAsset, len(descriptor.Assets))
		for i, asset := range descriptor.Assets {
			normalized.Assets[i] = normalizeLaunchAsset(asset)
		}
	}
	return normalized
}

func normalizeLaunchAsset(asset LaunchAsset) LaunchAsset {
	normalized := LaunchAsset{
		ID:     SafeID(strings.TrimSpace(string(asset.ID))),
		Role:   AssetRole(normalizeEnum(string(asset.Role))),
		Kind:   AssetKind(normalizeEnum(string(asset.Kind))),
		Source: normalizeAssetSource(asset.Source),
		Lock:   normalizeLockMetadata(asset.Lock),
	}
	if asset.Labels != nil {
		normalized.Labels = normalizeSafeLabels(asset.Labels)
	}
	if asset.InitConfig != nil {
		normalized.InitConfig = normalizeInitConfigMetadata(asset.InitConfig)
	}
	if asset.AgentConfig != nil {
		normalized.AgentConfig = normalizeAgentConfigMetadata(asset.AgentConfig)
	}
	if asset.Resources != nil {
		normalized.Resources = make([]ResourceMetadata, len(asset.Resources))
		for i, resource := range asset.Resources {
			normalized.Resources[i] = normalizeResourceMetadata(resource)
		}
	}
	return normalized
}

func normalizeAssetSource(source AssetSource) AssetSource {
	normalized := AssetSource{
		Type: SourceType(normalizeEnum(string(source.Type))),
	}
	if source.HostPath != nil {
		normalized.HostPath = &HostPathMetadata{
			Path: strings.TrimSpace(source.HostPath.Path),
			Role: HostPathRole(normalizeEnum(string(source.HostPath.Role))),
		}
	}
	return normalized
}

func normalizeLockMetadata(lock LockMetadata) LockMetadata {
	return LockMetadata{
		Digest: DigestMetadata{
			Algorithm: DigestAlgorithm(normalizeEnum(string(lock.Digest.Algorithm))),
			Value:     strings.ToLower(strings.TrimSpace(lock.Digest.Value)),
		},
		SizeBytes:          lock.SizeBytes,
		LockedAtUnixMillis: lock.LockedAtUnixMillis,
	}
}

func normalizeInitConfigMetadata(initConfig *InitConfigMetadata) *InitConfigMetadata {
	normalized := &InitConfigMetadata{
		Format:     SafeLabel(strings.TrimSpace(string(initConfig.Format))),
		EntryPoint: SafeLabel(strings.TrimSpace(string(initConfig.EntryPoint))),
	}
	if initConfig.Labels != nil {
		normalized.Labels = normalizeSafeLabels(initConfig.Labels)
	}
	return normalized
}

func normalizeAgentConfigMetadata(agentConfig *AgentConfigMetadata) *AgentConfigMetadata {
	normalized := &AgentConfigMetadata{
		Protocol: SafeLabel(strings.TrimSpace(string(agentConfig.Protocol))),
		Version:  SafeLabel(strings.TrimSpace(string(agentConfig.Version))),
	}
	if agentConfig.Features != nil {
		normalized.Features = normalizeSafeLabels(agentConfig.Features)
	}
	return normalized
}

func normalizeResourceMetadata(resource ResourceMetadata) ResourceMetadata {
	normalized := ResourceMetadata{
		ID:        SafeID(strings.TrimSpace(string(resource.ID))),
		Kind:      SafeLabel(strings.TrimSpace(string(resource.Kind))),
		SizeBytes: resource.SizeBytes,
	}
	if resource.Labels != nil {
		normalized.Labels = normalizeSafeLabels(resource.Labels)
	}
	return normalized
}

func normalizeSafeLabels(labels []SafeLabel) []SafeLabel {
	normalized := make([]SafeLabel, len(labels))
	for i, label := range labels {
		normalized[i] = SafeLabel(strings.TrimSpace(string(label)))
	}
	return normalized
}

func validAssetRole(role AssetRole) bool {
	switch role {
	case AssetRoleKernel,
		AssetRoleRootfs,
		AssetRoleInitrd,
		AssetRoleGuestInitConfig,
		AssetRoleGuestAgentConfig:
		return true
	default:
		return false
	}
}

func requiredAssetRole(role AssetRole) bool {
	return role == AssetRoleKernel || role == AssetRoleRootfs
}

func validAssetKind(kind AssetKind) bool {
	switch kind {
	case AssetKindKernelImage,
		AssetKindRootfsImage,
		AssetKindInitrdImage,
		AssetKindGuestConfig,
		AssetKindAgentConfig:
		return true
	default:
		return false
	}
}

func validSourceType(source SourceType) bool {
	switch source {
	case SourceTypeLocalFile,
		SourceTypeGenerated,
		SourceTypeEmbedded:
		return true
	default:
		return false
	}
}

func validHostPathRole(role HostPathRole) bool {
	switch role {
	case HostPathRoleLaunchInput,
		HostPathRoleResolvedLocalAsset:
		return true
	default:
		return false
	}
}

func validDigestAlgorithm(algorithm DigestAlgorithm) bool {
	switch algorithm {
	case DigestAlgorithmSHA256,
		DigestAlgorithmSHA384,
		DigestAlgorithmSHA512:
		return true
	default:
		return false
	}
}

func digestValueLength(algorithm DigestAlgorithm) int {
	switch algorithm {
	case DigestAlgorithmSHA256:
		return 64
	case DigestAlgorithmSHA384:
		return 96
	case DigestAlgorithmSHA512:
		return 128
	default:
		return 0
	}
}

func lowerHexDigestValue(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func safeLaunchAssetID(value SafeID) bool {
	raw := string(value)
	if raw == "" || len(raw) > maxSafeIDBytes || unsafeLaunchAssetMetadata(raw) || launchAssetAllDigits(raw) {
		return false
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func safeLaunchAssetLabel(value SafeLabel) bool {
	raw := string(value)
	if raw == "" || len(raw) > maxSafeLabelBytes || unsafeLaunchAssetMetadata(raw) {
		return false
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func unsafeLaunchAssetMetadata(value string) bool {
	if value != strings.TrimSpace(value) || launchAssetContainsControl(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"@",
		"authorization",
		"bearer",
		"token",
		"secret",
		"credential",
		"password",
		"api_key",
		"apikey",
		"access_key",
		"private_key",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.ContainsAny(value, "/\\?#\r\n\t \"'`{}[]()<>|;&=$:")
}

func launchAssetContainsControl(value string) bool {
	for _, r := range value {
		if r < 32 || r == 127 {
			return true
		}
	}
	return false
}

func launchAssetAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func normalizeEnum(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func assetField(index int, field string) string {
	return "assets[" + itoa(index) + "]." + field
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for value > 0 {
		i--
		digits[i] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[i:])
}

func (result *ValidationResult) addError(field string, code ValidationCode, message string) {
	result.Errors = append(result.Errors, ValidationError{
		Code:    code,
		Field:   field,
		Message: message,
	})
}

func (err ValidationError) Error() string {
	if err.Code == "" {
		return ""
	}
	message := "launch asset validation failed (" + string(err.Code) + ")"
	if err.Field != "" {
		message += " field=" + err.Field
	}
	if err.Message != "" {
		message += ": " + err.Message
	}
	return message
}

func (errs ValidationErrors) Error() string {
	if len(errs) == 0 {
		return ""
	}
	return errs[0].Error()
}
