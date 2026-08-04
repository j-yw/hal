package credentialsource

import (
	"crypto/sha256"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	MaxKeyctlDescribeBytes   = 4096
	MaxProductionSecretBytes = 64 << 10
	maxRegistryEntries       = 64
)

var (
	ErrCredentialAdmissionDenied     error = errors.New("credential_admission_denied")
	ErrCredentialSourceDescriptor    error = errors.New("credential source descriptor rejected")
	ErrCredentialSourceRegistration  error = errors.New("credential source registration rejected")
	ErrCredentialSourceSerialization error = errors.New("credential source serialization is denied")
	ErrCredentialSourceUnavailable   error = errors.New("credential_source_unavailable")
	ErrCredentialSourceUnsupported   error = errors.New("credential source is unsupported")
)

type KeyPermission uint32

const (
	KeyPermissionPossessorView    KeyPermission = 0x01000000
	KeyPermissionPossessorRead    KeyPermission = 0x02000000
	KeyPermissionPossessorWrite   KeyPermission = 0x04000000
	KeyPermissionPossessorSearch  KeyPermission = 0x08000000
	KeyPermissionPossessorLink    KeyPermission = 0x10000000
	KeyPermissionPossessorSetattr KeyPermission = 0x20000000
	KeyPermissionUserView         KeyPermission = 0x00010000
	KeyPermissionUserRead         KeyPermission = 0x00020000
	KeyPermissionUserWrite        KeyPermission = 0x00040000
	KeyPermissionUserSearch       KeyPermission = 0x00080000
	KeyPermissionUserLink         KeyPermission = 0x00100000
	KeyPermissionUserSetattr      KeyPermission = 0x00200000
	KeyPermissionGroupView        KeyPermission = 0x00000100
	KeyPermissionGroupRead        KeyPermission = 0x00000200
	KeyPermissionGroupWrite       KeyPermission = 0x00000400
	KeyPermissionGroupSearch      KeyPermission = 0x00000800
	KeyPermissionGroupLink        KeyPermission = 0x00001000
	KeyPermissionGroupSetattr     KeyPermission = 0x00002000
	KeyPermissionOtherView        KeyPermission = 0x00000001
	KeyPermissionOtherRead        KeyPermission = 0x00000002
	KeyPermissionOtherWrite       KeyPermission = 0x00000004
	KeyPermissionOtherSearch      KeyPermission = 0x00000008
	KeyPermissionOtherLink        KeyPermission = 0x00000010
	KeyPermissionOtherSetattr     KeyPermission = 0x00000020
)

type KeyIdentity struct {
	serial      int32
	keyType     string
	ownerUID    uint32
	ownerGID    uint32
	permissions KeyPermission
	description string
}

type KeyDescriptor struct {
	keyType     string
	ownerUID    uint32
	ownerGID    uint32
	permissions KeyPermission
	description string
}

type SourceRegistration struct {
	referenceID string
	identity    KeyIdentity
}

type AdmissionGrantRegistration struct {
	authority          *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	principal          sandboxruntime.AuthenticatedWorkerPrincipal
	request            sandboxruntime.JobCredentialAdmissionRequest
	sourceReferenceIDs []string
}

type RegistryConfig struct {
	authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority
	ownerUID  uint32
	ownerGID  uint32
	sources   []SourceRegistration
	grants    []AdmissionGrantRegistration
}

func NewKeyIdentity(serial int32, keyType string, ownerUID, ownerGID uint32, permissions KeyPermission, description string) (KeyIdentity, error) {
	if serial <= 0 || !validKeyDescriptor(keyType, permissions, description) {
		return KeyIdentity{}, ErrCredentialSourceRegistration
	}
	return KeyIdentity{
		serial: encodeInt32(serial), keyType: safeDigest(keyType), ownerUID: encodeUint32(ownerUID), ownerGID: encodeUint32(ownerGID),
		permissions: KeyPermission(encodeUint32(uint32(permissions))), description: safeDigest(description),
	}, nil
}

func NewKeyDescriptor(keyType string, ownerUID, ownerGID uint32, permissions KeyPermission, description string) (KeyDescriptor, error) {
	if !validKeyDescriptor(keyType, permissions, description) {
		return KeyDescriptor{}, ErrCredentialSourceDescriptor
	}
	return KeyDescriptor{
		keyType: safeDigest(keyType), ownerUID: encodeUint32(ownerUID), ownerGID: encodeUint32(ownerGID),
		permissions: KeyPermission(encodeUint32(uint32(permissions))), description: safeDigest(description),
	}, nil
}

func NewSourceRegistration(referenceID string, identity KeyIdentity) (SourceRegistration, error) {
	if !validSafeID(referenceID) || !validKeyIdentity(identity) {
		return SourceRegistration{}, ErrCredentialSourceRegistration
	}
	return SourceRegistration{referenceID: safeDigest(referenceID), identity: identity}, nil
}

func NewAdmissionGrantRegistration(authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority, principal sandboxruntime.AuthenticatedWorkerPrincipal, request sandboxruntime.JobCredentialAdmissionRequest, sourceReferenceIDs []string) (AdmissionGrantRegistration, error) {
	if authority == nil || authority.ValidateAuthenticatedWorkerPrincipal(principal) != nil || !validAdmissionRequest(request) ||
		len(sourceReferenceIDs) == 0 || len(sourceReferenceIDs) > maxRegistryEntries || !validUniqueIDs(sourceReferenceIDs) {
		return AdmissionGrantRegistration{}, ErrCredentialSourceRegistration
	}
	return AdmissionGrantRegistration{
		authority: authority, principal: principal, request: sealAdmissionRequest(request),
		sourceReferenceIDs: sealIDs(sourceReferenceIDs),
	}, nil
}

func NewRegistryConfig(authority *sandboxruntime.AuthenticatedWorkerPrincipalAuthority, ownerUID, ownerGID uint32, sources []SourceRegistration, grants []AdmissionGrantRegistration) (RegistryConfig, error) {
	if authority == nil || !validRegistryConfigCardinality(sources, grants) {
		return RegistryConfig{}, ErrCredentialSourceRegistration
	}
	config := RegistryConfig{authority: authority, ownerUID: encodeUint32(ownerUID), ownerGID: encodeUint32(ownerGID), sources: append([]SourceRegistration(nil), sources...), grants: cloneAdmissionGrants(grants)}
	if !validRegistryConfig(config) {
		return RegistryConfig{}, ErrCredentialSourceRegistration
	}
	return config, nil
}

func validKeyDescriptor(keyType string, permissions KeyPermission, description string) bool {
	return keyType == "user" && permissions == KeyPermissionUserView|KeyPermissionUserRead && validSafeID(description)
}

func validKeyIdentity(identity KeyIdentity) bool {
	return decodeInt32(identity.serial) > 0 && identity.keyType == safeDigest("user") &&
		decodeUint32(uint32(identity.permissions)) == uint32(KeyPermissionUserView|KeyPermissionUserRead) && validSafeDigest(identity.description)
}

func validSafeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validUniqueIDs(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validSafeID(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validAdmissionRequest(request sandboxruntime.JobCredentialAdmissionRequest) bool {
	identity := request.Identity
	identities := []string{
		identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.HostID, identity.RuntimeDriver,
		identity.RuntimeID, identity.RuntimeGeneration, identity.FirecrackerProcessGeneration, identity.VsockGeneration,
		identity.WorkerJobID, identity.SubmissionID, identity.PlanID, identity.ActivationGeneration,
		identity.CredentialGeneration, identity.NetworkPlanID, identity.PolicySnapshotID, identity.ProxySessionID,
		identity.ProxyGenerationID, identity.TopologyGenerationID, identity.RuleGenerationID,
		request.GrantID, request.PlanID, request.TemplatePolicyID, request.WorkspacePolicyID,
	}
	if !validIDs(identities) || identity.IssuedAt.IsZero() || request.GrantRevision == 0 ||
		request.PlanID != identity.PlanID || len(request.SourceReferenceIDs) == 0 || len(request.SourceReferenceIDs) > maxRegistryEntries ||
		!validUniqueIDs(request.SourceReferenceIDs) || len(request.Bindings) == 0 || len(request.Bindings) > maxRegistryEntries {
		return false
	}
	sourceReferenceIDs := make(map[string]struct{}, len(request.SourceReferenceIDs))
	for _, referenceID := range request.SourceReferenceIDs {
		sourceReferenceIDs[referenceID] = struct{}{}
	}
	bindingIDs := make(map[string]struct{}, len(request.Bindings))
	for _, binding := range request.Bindings {
		_, sourceRegistered := sourceReferenceIDs[binding.SourceReferenceID]
		if !validSafeID(binding.ID) || !validSafeID(binding.SourceReferenceID) ||
			!validDeliveryMode(binding.Mode) || binding.Mode == sandboxruntime.JobCredentialDeliveryModeHTTPProxy && !validSafeID(binding.ServiceID) ||
			binding.Mode != sandboxruntime.JobCredentialDeliveryModeHTTPProxy && binding.ServiceID != "" {
			return false
		}
		if !sourceRegistered {
			return false
		}
		if _, duplicate := bindingIDs[binding.ID]; duplicate {
			return false
		}
		bindingIDs[binding.ID] = struct{}{}
	}
	return true
}

func validIDs(values []string) bool {
	for _, value := range values {
		if !validSafeID(value) {
			return false
		}
	}
	return true
}

func validDeliveryMode(mode sandboxruntime.JobCredentialDeliveryMode) bool {
	switch mode {
	case sandboxruntime.JobCredentialDeliveryModeHTTPProxy, sandboxruntime.JobCredentialDeliveryModeFileTmpfs, sandboxruntime.JobCredentialDeliveryModeSSHAgent:
		return true
	default:
		return false
	}
}

func validRegistryConfig(config RegistryConfig) bool {
	if config.authority == nil || !validRegistryConfigCardinality(config.sources, config.grants) {
		return false
	}
	sourceReferenceIDs := make(map[string]struct{}, len(config.sources))
	sourceSerials := make(map[int32]struct{}, len(config.sources))
	for _, source := range config.sources {
		if !validSafeDigest(source.referenceID) || !validKeyIdentity(source.identity) || source.identity.ownerUID != config.ownerUID || source.identity.ownerGID != config.ownerGID {
			return false
		}
		if _, duplicate := sourceReferenceIDs[source.referenceID]; duplicate {
			return false
		}
		if _, duplicate := sourceSerials[source.identity.serial]; duplicate {
			return false
		}
		sourceReferenceIDs[source.referenceID] = struct{}{}
		sourceSerials[source.identity.serial] = struct{}{}
	}
	grantIDs := make(map[string]struct{}, len(config.grants))
	for _, grant := range config.grants {
		if grant.authority != config.authority || config.authority.ValidateAuthenticatedWorkerPrincipal(grant.principal) != nil ||
			encodeUint32(grant.principal.UID()) != config.ownerUID || encodeUint32(grant.principal.GID()) != config.ownerGID || !validSealedAdmissionRequest(grant.request) ||
			len(grant.sourceReferenceIDs) == 0 || len(grant.sourceReferenceIDs) > maxRegistryEntries || !validUniqueDigests(grant.sourceReferenceIDs) {
			return false
		}
		for _, referenceID := range grant.sourceReferenceIDs {
			if _, registered := sourceReferenceIDs[referenceID]; !registered {
				return false
			}
		}
		if _, duplicate := grantIDs[grant.request.GrantID]; duplicate {
			return false
		}
		grantIDs[grant.request.GrantID] = struct{}{}
	}
	return true
}

func validRegistryConfigCardinality(sources []SourceRegistration, grants []AdmissionGrantRegistration) bool {
	return len(sources) > 0 && len(sources) <= maxRegistryEntries && len(grants) > 0 && len(grants) <= maxRegistryEntries
}

func cloneAdmissionRequest(request sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.JobCredentialAdmissionRequest {
	request.SourceReferenceIDs = append([]string(nil), request.SourceReferenceIDs...)
	request.Bindings = append([]sandboxruntime.JobCredentialBindingRequest(nil), request.Bindings...)
	return request
}

func cloneAdmissionGrants(grants []AdmissionGrantRegistration) []AdmissionGrantRegistration {
	cloned := make([]AdmissionGrantRegistration, len(grants))
	for index, grant := range grants {
		cloned[index] = grant
		cloned[index].request = cloneAdmissionRequest(grant.request)
		cloned[index].sourceReferenceIDs = append([]string(nil), grant.sourceReferenceIDs...)
	}
	return cloned
}

func cloneRegistryConfig(config RegistryConfig) RegistryConfig {
	config.sources = append([]SourceRegistration(nil), config.sources...)
	config.grants = cloneAdmissionGrants(config.grants)
	return config
}

func sealAdmissionRequest(request sandboxruntime.JobCredentialAdmissionRequest) sandboxruntime.JobCredentialAdmissionRequest {
	identity := &request.Identity
	identity.SandboxID = safeDigest(identity.SandboxID)
	identity.ExecutionID = safeDigest(identity.ExecutionID)
	identity.WorkerID = safeDigest(identity.WorkerID)
	identity.HostID = safeDigest(identity.HostID)
	identity.RuntimeDriver = safeDigest(identity.RuntimeDriver)
	identity.RuntimeID = safeDigest(identity.RuntimeID)
	identity.RuntimeGeneration = safeDigest(identity.RuntimeGeneration)
	identity.FirecrackerProcessGeneration = safeDigest(identity.FirecrackerProcessGeneration)
	identity.VsockGeneration = safeDigest(identity.VsockGeneration)
	identity.WorkerJobID = safeDigest(identity.WorkerJobID)
	identity.SubmissionID = safeDigest(identity.SubmissionID)
	identity.PlanID = safeDigest(identity.PlanID)
	identity.ActivationGeneration = safeDigest(identity.ActivationGeneration)
	identity.CredentialGeneration = safeDigest(identity.CredentialGeneration)
	identity.NetworkPlanID = safeDigest(identity.NetworkPlanID)
	identity.PolicySnapshotID = safeDigest(identity.PolicySnapshotID)
	identity.ProxySessionID = safeDigest(identity.ProxySessionID)
	identity.ProxyGenerationID = safeDigest(identity.ProxyGenerationID)
	identity.TopologyGenerationID = safeDigest(identity.TopologyGenerationID)
	identity.RuleGenerationID = safeDigest(identity.RuleGenerationID)
	request.GrantID = safeDigest(request.GrantID)
	request.PlanID = safeDigest(request.PlanID)
	request.TemplatePolicyID = safeDigest(request.TemplatePolicyID)
	request.WorkspacePolicyID = safeDigest(request.WorkspacePolicyID)
	request.SourceReferenceIDs = sealIDs(request.SourceReferenceIDs)
	request.Bindings = append([]sandboxruntime.JobCredentialBindingRequest(nil), request.Bindings...)
	for index := range request.Bindings {
		request.Bindings[index].ID = safeDigest(request.Bindings[index].ID)
		request.Bindings[index].SourceReferenceID = safeDigest(request.Bindings[index].SourceReferenceID)
		if request.Bindings[index].ServiceID != "" {
			request.Bindings[index].ServiceID = safeDigest(request.Bindings[index].ServiceID)
		}
	}
	return request
}

func sealIDs(values []string) []string {
	sealed := make([]string, len(values))
	for index, value := range values {
		sealed[index] = safeDigest(value)
	}
	return sealed
}

func validSealedAdmissionRequest(request sandboxruntime.JobCredentialAdmissionRequest) bool {
	if !validAdmissionRequest(request) {
		return false
	}
	identity := request.Identity
	values := []string{
		identity.SandboxID, identity.ExecutionID, identity.WorkerID, identity.HostID, identity.RuntimeDriver,
		identity.RuntimeID, identity.RuntimeGeneration, identity.FirecrackerProcessGeneration, identity.VsockGeneration,
		identity.WorkerJobID, identity.SubmissionID, identity.PlanID, identity.ActivationGeneration,
		identity.CredentialGeneration, identity.NetworkPlanID, identity.PolicySnapshotID, identity.ProxySessionID,
		identity.ProxyGenerationID, identity.TopologyGenerationID, identity.RuleGenerationID,
		request.GrantID, request.PlanID, request.TemplatePolicyID, request.WorkspacePolicyID,
	}
	if !validDigests(values) || !validUniqueDigests(request.SourceReferenceIDs) {
		return false
	}
	for _, binding := range request.Bindings {
		if !validSafeDigest(binding.ID) || !validSafeDigest(binding.SourceReferenceID) || binding.ServiceID != "" && !validSafeDigest(binding.ServiceID) {
			return false
		}
	}
	return true
}

func validDigests(values []string) bool {
	for _, value := range values {
		if !validSafeDigest(value) {
			return false
		}
	}
	return true
}

func validUniqueDigests(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validSafeDigest(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validSafeDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'p' {
			return false
		}
	}
	return true
}

func safeDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	encoded := make([]byte, len(digest)*2)
	for index, value := range digest {
		encoded[index*2] = 'a' + value>>4
		encoded[index*2+1] = 'a' + value&15
	}
	return string(encoded)
}

func encodeUint32(value uint32) uint32 {
	return value ^ 0xdeadbeef
}

func decodeUint32(value uint32) uint32 {
	return encodeUint32(value)
}

func encodeInt32(value int32) int32 {
	return int32(uint32(value) ^ 0xdeadbeef)
}

func decodeInt32(value int32) int32 {
	return int32(uint32(value) ^ 0xdeadbeef)
}

func containsID(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func sourceIndex(sources []SourceRegistration, referenceID string) int {
	return sourceIndexStored(sources, safeDigest(referenceID))
}

func sourceIndexStored(sources []SourceRegistration, referenceID string) int {
	for index := range sources {
		if sources[index].referenceID == referenceID {
			return index
		}
	}
	return -1
}
