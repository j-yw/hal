package sandboxtemplate

import "strings"

const (
	ValidationMissingRequiredField ValidationCode = "missing_required_field"
	ValidationUnsupportedValue     ValidationCode = "unsupported_value"
	ValidationUnsafeID             ValidationCode = "unsafe_id"
	ValidationUnsafeReference      ValidationCode = "unsafe_reference"
	ValidationUnsafeDomain         ValidationCode = "unsafe_domain"
	ValidationUnsafePath           ValidationCode = "unsafe_path"
	ValidationSecretLikeValue      ValidationCode = "secret_like_value"
	ValidationMalformedDigest      ValidationCode = "malformed_digest"
	ValidationUnsafeCommand        ValidationCode = "unsafe_command"
)

// ValidationCode identifies a sanitized sandbox-template validation failure.
type ValidationCode string

// ValidationError points at invalid metadata without echoing rejected values.
type ValidationError struct {
	Code    ValidationCode `json:"code"`
	Field   string         `json:"field,omitempty"`
	Index   *int           `json:"index,omitempty"`
	Message string         `json:"message,omitempty"`
}

// ValidationResult is the pure validation result for sandbox templates.
type ValidationResult struct {
	Valid      bool              `json:"valid"`
	Normalized *Template         `json:"normalized,omitempty"`
	Errors     []ValidationError `json:"errors,omitempty"`
}

// ValidateTemplate normalizes and validates sandbox-template metadata without
// fetching references, inspecting hosts, executing commands, or contacting
// runtimes.
func ValidateTemplate(input Template) ValidationResult {
	normalized := NormalizeTemplate(input)
	applyWorkspaceSafetyDefaults(&normalized)
	var result ValidationResult

	validateTemplateIdentity(&result, normalized)
	validateReference(&result, "metadata.reference", normalized.Metadata.Reference)
	validateDigest(&result, "metadata.digest", normalized.Metadata.Digest)
	validateRuntime(&result, normalized.Runtime)
	validateWorkspace(&result, normalized.Workspace)
	validateNetwork(&result, normalized.Network)
	validateCredentials(&result, normalized.Credentials)
	validateSetup(&result, normalized.Setup)

	result.Valid = len(result.Errors) == 0
	if result.Valid {
		copy := normalized
		result.Normalized = &copy
	}
	return result
}

// ReferenceDigestPinned reports whether reference metadata is already locked by
// a syntactically valid digest. It does not fetch, resolve, rewrite, or infer
// remote digests.
func ReferenceDigestPinned(ref *ImmutableRef) bool {
	if ref == nil || ref.Digest == nil {
		return false
	}
	return validDigestAlgorithm(ref.Digest.Algorithm) && validDigestValue(ref.Digest.Algorithm, ref.Digest.Value)
}

func validateTemplateIdentity(result *ValidationResult, tmpl Template) {
	if strings.TrimSpace(tmpl.Metadata.ID) == "" {
		result.addError("metadata.id", nil, ValidationMissingRequiredField, "template id is required")
	} else if !safeID(tmpl.Metadata.ID) {
		result.addError("metadata.id", nil, ValidationUnsafeID, "template id must be safe metadata")
	}
	if tmpl.APIVersion != "" && tmpl.APIVersion != TemplateAPIVersionV1 {
		result.addError("apiVersion", nil, ValidationUnsupportedValue, "api version is unsupported")
	}
	if tmpl.Kind != "" && tmpl.Kind != TemplateKindSandbox {
		result.addError("kind", nil, ValidationUnsupportedValue, "template kind is unsupported")
	}
	if tmpl.Metadata.Version != "" && !safeVersion(tmpl.Metadata.Version) {
		result.addError("metadata.version", nil, ValidationUnsafeID, "template version must be safe metadata")
	}
	for key, value := range tmpl.Metadata.Labels {
		if !safeMapKey(key) || unsafeFreeText(value) {
			result.addError("metadata.labels", nil, ValidationUnsafeID, "template label must be safe metadata")
			break
		}
	}
	for key, value := range tmpl.Metadata.Annotations {
		if !safeMapKey(key) || unsafeFreeText(value) {
			result.addError("metadata.annotations", nil, ValidationUnsafeID, "template annotation must be safe metadata")
			break
		}
	}
}

func validateRuntime(result *ValidationResult, runtime *RuntimeRequirements) {
	if runtime == nil {
		return
	}
	if runtime.Driver != "" && !validRuntimeDriver(runtime.Driver) {
		result.addError("runtime.driver", nil, ValidationUnsupportedValue, "runtime driver is unsupported")
	}
	if runtime.IsolationLevel != "" && !validIsolationLevel(runtime.IsolationLevel) {
		result.addError("runtime.isolationLevel", nil, ValidationUnsupportedValue, "runtime isolation level is unsupported")
	}
	validateReference(result, "runtime.image", runtime.Image)
	if runtime.Launch != nil {
		validateReference(result, "runtime.launch.descriptorRef", runtime.Launch.DescriptorRef)
	}
	if runtime.Resources != nil {
		if runtime.Resources.CPUCores < 0 {
			result.addError("runtime.resources.cpuCores", nil, ValidationUnsupportedValue, "cpu core hint must be non-negative")
		}
		if runtime.Resources.MemoryMB < 0 {
			result.addError("runtime.resources.memoryMb", nil, ValidationUnsupportedValue, "memory hint must be non-negative")
		}
		if runtime.Resources.DiskGB < 0 {
			result.addError("runtime.resources.diskGb", nil, ValidationUnsupportedValue, "disk hint must be non-negative")
		}
	}
}

func validateWorkspace(result *ValidationResult, workspace *WorkspaceRequirements) {
	if workspace == nil {
		return
	}
	if workspace.Mode != "" && !validWorkspaceMode(workspace.Mode) {
		result.addError("workspace.mode", nil, ValidationUnsupportedValue, "workspace mode is unsupported")
	}
	if workspace.InputSource != "" && !validWorkspaceInputSource(workspace.InputSource) {
		result.addError("workspace.inputSource", nil, ValidationUnsupportedValue, "workspace input source is unsupported")
	}
	validateReference(result, "workspace.ref", workspace.Ref)
}

func validateNetwork(result *ValidationResult, network *NetworkRequirements) {
	if network == nil {
		return
	}
	if network.Profile != "" && !validNetworkProfile(network.Profile) {
		result.addError("network.profile", nil, ValidationUnsupportedValue, "network profile is unsupported")
	}
	validateReference(result, "network.policySnapshotReference", network.PolicySnapshotReference)
	for i, rule := range network.Allow {
		index := i
		if rule.ID != "" && !safeID(rule.ID) {
			result.addError("network.allow.id", &index, ValidationUnsafeID, "network rule id must be safe metadata")
		}
		if rule.Kind != "" && !validNetworkRuleCategory(rule.Kind) {
			result.addError("network.allow.kind", &index, ValidationUnsupportedValue, "network rule kind is unsupported")
		}
		if rule.Value != "" && !safeNetworkRuleValue(rule.Kind, rule.Value) {
			result.addError("network.allow.value", &index, ValidationUnsafeDomain, "network rule value must be safe metadata")
		}
	}
}

func validateCredentials(result *ValidationResult, credentials *CredentialRequirements) {
	if credentials == nil {
		return
	}
	for i, mode := range credentials.DeliveryModes {
		if !validCredentialDeliveryMode(mode) {
			index := i
			result.addError("credentials.deliveryModes", &index, ValidationUnsupportedValue, "credential delivery mode is unsupported")
		}
	}
	for i, service := range credentials.Services {
		index := i
		if service.ID == "" {
			result.addError("credentials.services.id", &index, ValidationMissingRequiredField, "credential service id is required")
		} else if !safeID(service.ID) {
			result.addError("credentials.services.id", &index, ValidationUnsafeID, "credential service id must be safe metadata")
		}
		for _, domain := range service.Domains {
			if !safeDomain(domain) {
				result.addError("credentials.services.domains", &index, ValidationUnsafeDomain, "credential service domain must be safe metadata")
				break
			}
		}
		for _, mode := range service.DeliveryModes {
			if !validCredentialDeliveryMode(mode) {
				result.addError("credentials.services.deliveryModes", &index, ValidationUnsupportedValue, "credential delivery mode is unsupported")
				break
			}
		}
	}
}

func validateSetup(result *ValidationResult, setup []SetupCommandMetadata) {
	for i, command := range setup {
		index := i
		if command.ID == "" {
			result.addError("setup.id", &index, ValidationMissingRequiredField, "setup command id is required")
		} else if !safeID(command.ID) {
			result.addError("setup.id", &index, ValidationUnsafeID, "setup command id must be safe metadata")
		}
		if unsafeFreeText(command.DisplayName) {
			result.addError("setup.displayName", &index, ValidationSecretLikeValue, "setup display name must be safe metadata")
		}
		if unsafeFreeText(command.Description) {
			result.addError("setup.description", &index, ValidationSecretLikeValue, "setup description must be safe metadata")
		}
		for _, tool := range command.Tools {
			if !safeToolName(tool) {
				result.addError("setup.tools", &index, ValidationUnsafeID, "setup tool must be safe metadata")
				break
			}
		}
		if command.WorkDir != "" && !safeRelativeWorkDir(command.WorkDir) {
			result.addError("setup.workDir", &index, ValidationUnsafePath, "setup workdir must be safe relative metadata")
		}
		for _, part := range command.Command {
			if !safeCommandPart(part) {
				result.addError("setup.command", &index, ValidationUnsafeCommand, "setup command descriptor must be safe metadata")
				break
			}
		}
		if command.TimeoutSeconds < 0 {
			result.addError("setup.timeoutSeconds", &index, ValidationUnsupportedValue, "setup timeout must be non-negative")
		}
	}
}

func validateReference(result *ValidationResult, field string, ref *ImmutableRef) {
	if ref == nil {
		return
	}
	if ref.Kind != "" && !validReferenceKind(ref.Kind) {
		result.addError(field+".kind", nil, ValidationUnsupportedValue, "reference kind is unsupported")
	}
	if ref.Ref != "" && !safeReferenceValue(ref.Ref, ref.Kind) {
		result.addError(field+".ref", nil, ValidationUnsafeReference, "reference value must be safe metadata")
	}
	validateDigest(result, field+".digest", ref.Digest)
}

func validateDigest(result *ValidationResult, field string, digest *DigestMetadata) {
	if digest == nil {
		return
	}
	if !validDigestAlgorithm(digest.Algorithm) {
		result.addError(field+".algorithm", nil, ValidationMalformedDigest, "digest algorithm is unsupported")
		return
	}
	if !validDigestValue(digest.Algorithm, digest.Value) {
		result.addError(field+".value", nil, ValidationMalformedDigest, "digest value is malformed")
	}
}

func (r *ValidationResult) addError(field string, index *int, code ValidationCode, message string) {
	err := ValidationError{Code: code, Field: field, Message: message}
	if index != nil {
		value := *index
		err.Index = &value
	}
	r.Errors = append(r.Errors, err)
}

func applyWorkspaceSafetyDefaults(tmpl *Template) {
	if tmpl == nil || tmpl.Workspace == nil {
		return
	}
	switch tmpl.Workspace.Mode {
	case WorkspaceModeDirect:
		if !tmpl.Workspace.Trusted {
			tmpl.Workspace.Unsafe = true
		}
	case WorkspaceModeClone, WorkspaceModeCopy:
		tmpl.Workspace.Unsafe = false
	}
}

func validRuntimeDriver(driver RuntimeDriver) bool {
	switch driver {
	case RuntimeDriverSSHMachine, RuntimeDriverRootlessPodman, RuntimeDriverMicroVM:
		return true
	default:
		return false
	}
}

func validIsolationLevel(level IsolationLevel) bool {
	switch level {
	case IsolationLevelHost, IsolationLevelContainer, IsolationLevelVM:
		return true
	default:
		return false
	}
}

func validWorkspaceMode(mode WorkspaceMode) bool {
	switch mode {
	case WorkspaceModeClone, WorkspaceModeCopy, WorkspaceModeDirect:
		return true
	default:
		return false
	}
}

func validWorkspaceInputSource(source WorkspaceInputSource) bool {
	switch source {
	case WorkspaceInputRemoteRef, WorkspaceInputGitBundle, WorkspaceInputCopy:
		return true
	default:
		return false
	}
}

func validNetworkProfile(profile NetworkPolicyProfile) bool {
	switch profile {
	case NetworkProfileDenyByDefault, NetworkProfileAllowListed, NetworkProfileBestEffort, NetworkProfileDisabled:
		return true
	default:
		return false
	}
}

func validNetworkRuleCategory(kind NetworkRuleCategory) bool {
	switch kind {
	case NetworkRuleCategoryDomain, NetworkRuleCategoryService, NetworkRuleCategoryPackageMirror, NetworkRuleCategoryPolicySnapshot:
		return true
	default:
		return false
	}
}

func validCredentialDeliveryMode(mode CredentialDeliveryMode) bool {
	switch mode {
	case CredentialDeliveryModeHTTPProxy, CredentialDeliveryModeSSHAgent, CredentialDeliveryModeFileTmpfs, CredentialDeliveryModeEnv, CredentialDeliveryModeLegacyAuthSync:
		return true
	default:
		return false
	}
}

func validReferenceKind(kind ReferenceKind) bool {
	switch kind {
	case ReferenceKindOCIImage, ReferenceKindOCIArtifact, ReferenceKindGit, ReferenceKindLocal, ReferenceKindInline:
		return true
	default:
		return false
	}
}

func validDigestAlgorithm(algorithm DigestAlgorithm) bool {
	switch algorithm {
	case DigestAlgorithmSHA256, DigestAlgorithmSHA384, DigestAlgorithmSHA512:
		return true
	default:
		return false
	}
}

func validDigestValue(algorithm DigestAlgorithm, value string) bool {
	expected := map[DigestAlgorithm]int{
		DigestAlgorithmSHA256: 64,
		DigestAlgorithmSHA384: 96,
		DigestAlgorithmSHA512: 128,
	}[algorithm]
	if expected == 0 || len(value) != expected {
		return false
	}
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 || unsafeFreeText(value) {
		return false
	}
	return allRunes(value, func(ch rune) bool {
		return (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.'
	})
}

func safeVersion(value string) bool {
	return safeID(value)
}

func safeMapKey(value string) bool {
	return safeID(value)
}

func safeToolName(value string) bool {
	return safeID(value)
}

func safeReferenceValue(value string, kind ReferenceKind) bool {
	if strings.TrimSpace(value) == "" || unsafeFreeText(value) || rawHostPathLike(value) || credentialBearingURL(value) || strings.ContainsAny(value, "?#") {
		return false
	}
	if strings.Contains(value, "://") {
		return kind == ReferenceKindGit && strings.HasPrefix(value, "https://")
	}
	return true
}

func safeNetworkRuleValue(kind NetworkRuleCategory, value string) bool {
	if unsafeFreeText(value) || rawHostPathLike(value) || strings.Contains(value, "://") || strings.ContainsAny(value, "?#") || rawIPAddressLike(value) {
		return false
	}
	switch kind {
	case NetworkRuleCategoryDomain:
		return safeDomain(value)
	case NetworkRuleCategoryService, NetworkRuleCategoryPackageMirror, NetworkRuleCategoryPolicySnapshot:
		return safeID(value)
	default:
		return safeID(value) || safeDomain(value)
	}
}

func safeDomain(value string) bool {
	if value == "" || len(value) > 253 || unsafeFreeText(value) || rawIPAddressLike(value) || strings.ContainsAny(value, "/:@?#\\") {
		return false
	}
	if !strings.Contains(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		if !allRunes(label, func(ch rune) bool {
			return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-'
		}) {
			return false
		}
	}
	return true
}

func safeRelativeWorkDir(value string) bool {
	if value == "." {
		return true
	}
	if value == "" || rawHostPathLike(value) || strings.Contains(value, "\\") || strings.Contains(value, "..") || strings.Contains(value, "://") || unsafeFreeText(value) {
		return false
	}
	return allRunes(value, func(ch rune) bool {
		return (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '/'
	})
}

func safeCommandPart(value string) bool {
	if value == "" || unsafeFreeText(value) || rawHostPathLike(value) || credentialBearingURL(value) {
		return false
	}
	for _, marker := range []string{"&&", "||", ";", "|", "$(", "`", ">", "<", "\n", "\r"} {
		if strings.Contains(value, marker) {
			return false
		}
	}
	lower := strings.ToLower(value)
	return lower != "sh" && lower != "bash" && lower != "zsh" && lower != "fish" && lower != "-c"
}

func unsafeFreeText(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, marker := range []string{
		"bearer ", "authorization:", "password", "passwd", "private key",
		"-----begin", "token=", "secret=", "api_key", "apikey", "client_secret",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.HasPrefix(lower, "sk-") ||
		strings.HasPrefix(lower, "ghp_") ||
		strings.HasPrefix(lower, "github_pat_")
}

func rawHostPathLike(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, "../") || strings.HasPrefix(trimmed, "./") || strings.Contains(trimmed, "\\") {
		return true
	}
	if len(trimmed) >= 3 && ((trimmed[0] >= 'A' && trimmed[0] <= 'Z') || (trimmed[0] >= 'a' && trimmed[0] <= 'z')) && trimmed[1] == ':' && (trimmed[2] == '/' || trimmed[2] == '\\') {
		return true
	}
	return false
}

func credentialBearingURL(value string) bool {
	schemeIndex := strings.Index(value, "://")
	if schemeIndex < 0 {
		return false
	}
	authority := value[schemeIndex+3:]
	if slash := strings.Index(authority, "/"); slash >= 0 {
		authority = authority[:slash]
	}
	return strings.Contains(authority, "@")
}

func rawIPAddressLike(value string) bool {
	if value == "" {
		return false
	}
	hasDot := strings.Contains(value, ".")
	hasColon := strings.Contains(value, ":")
	if !hasDot && !hasColon {
		return false
	}
	if hasColon {
		return allRunes(value, func(ch rune) bool {
			return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') || ch == ':'
		})
	}
	return allRunes(value, func(ch rune) bool {
		return (ch >= '0' && ch <= '9') || ch == '.'
	})
}

func allRunes(value string, allow func(rune) bool) bool {
	for _, ch := range value {
		if !allow(ch) {
			return false
		}
	}
	return true
}
