package credentialsource

import (
	"context"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type keyctlReader interface {
	DescribeSize(context.Context, int32) (int, error)
	DescribeInto(context.Context, int32, []byte) (int, error)
	ReadSize(context.Context, int32) (int, error)
	ReadInto(context.Context, int32, []byte) (int, error)
}

type lockedSecretBorrowedView interface {
	WriteTo(context.Context, sandboxruntime.JobCredentialSecretSink) error
}

type lockedSecretMapping interface {
	Load(context.Context, func([]byte) (int, error)) error
	Borrow(context.Context, func(lockedSecretBorrowedView) error) error
	Destroy() error
}

type registryDeps struct {
	keyctl           keyctlReader
	newLockedMapping func(int) (lockedSecretMapping, error)
}

type Registry struct {
	deps   registryDeps
	config RegistryConfig
	self   *Registry
}

type registryAuthorization struct {
	registry *Registry
	self     *registryAuthorization
	allowed  uint64
}

type keyringLiveSecretSource struct {
	registry *Registry
	self     *keyringLiveSecretSource
	index    uint64
}

type credentialMemoryMapping []*credentialmemory.LockedMapping

type credentialMemoryBorrowedView []credentialmemory.BorrowedView

func newRegistry(config RegistryConfig, deps registryDeps) (*Registry, error) {
	config = cloneRegistryConfig(config)
	if !validRegistryConfig(config) || deps.keyctl == nil || deps.newLockedMapping == nil {
		return nil, ErrCredentialSourceRegistration
	}
	registry := &Registry{deps: deps, config: config}
	registry.self = registry
	return registry, nil
}

func (registry *Registry) AuthorizeJobCredentials(ctx context.Context, principal sandboxruntime.AuthenticatedWorkerPrincipal, request sandboxruntime.JobCredentialAdmissionRequest) (sandboxruntime.CredentialAdmissionAuthorization, error) {
	if registry == nil || registry.self != registry || ctx == nil {
		return nil, ErrCredentialAdmissionDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config := registry.config
	if config.authority == nil || config.authority.ValidateAuthenticatedWorkerPrincipal(principal) != nil || !validAdmissionRequest(request) {
		return nil, ErrCredentialAdmissionDenied
	}
	sealedRequest := sealAdmissionRequest(request)
	grantIndex := -1
	for index := range config.grants {
		if config.grants[index].request.GrantID == sealedRequest.GrantID {
			grantIndex = index
			break
		}
	}
	if grantIndex < 0 {
		return nil, ErrCredentialAdmissionDenied
	}
	grant := config.grants[grantIndex]
	if grant.authority != config.authority || config.authority.ValidateAuthenticatedWorkerPrincipal(grant.principal) != nil ||
		!samePrincipal(principal, grant.principal) || !sameAdmissionRequest(sealedRequest, grant.request) {
		return nil, ErrCredentialAdmissionDenied
	}
	var allowed uint64
	for _, referenceID := range sealedRequest.SourceReferenceIDs {
		if !containsID(grant.sourceReferenceIDs, referenceID) {
			return nil, ErrCredentialAdmissionDenied
		}
		index := sourceIndexStored(config.sources, referenceID)
		if index < 0 {
			return nil, ErrCredentialAdmissionDenied
		}
		allowed |= uint64(1) << uint(index)
	}
	if allowed == 0 {
		return nil, ErrCredentialAdmissionDenied
	}
	authorization := &registryAuthorization{registry: registry, allowed: allowed}
	authorization.self = authorization
	return authorization, nil
}

func (registry *Registry) ResolveAuthorizedSource(ctx context.Context, authorization sandboxruntime.CredentialAdmissionAuthorization, referenceID string) (sandboxruntime.LiveSecretSource, error) {
	if registry == nil || registry.self != registry || ctx == nil || !validSafeID(referenceID) {
		return nil, ErrCredentialAdmissionDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	issued, ok := authorization.(*registryAuthorization)
	if !ok || issued == nil || issued.self != issued || issued.registry != registry {
		return nil, ErrCredentialAdmissionDenied
	}
	index := sourceIndex(registry.config.sources, referenceID)
	if index < 0 || issued.allowed&(uint64(1)<<uint(index)) == 0 {
		return nil, ErrCredentialAdmissionDenied
	}
	source := &keyringLiveSecretSource{registry: registry, index: uint64(index)}
	source.self = source
	return source, nil
}

func (source *keyringLiveSecretSource) FillSecret(ctx context.Context, sink sandboxruntime.JobCredentialSecretSink) (result error) {
	if source == nil || source.self != source || source.registry == nil || source.registry.self != source.registry || ctx == nil || sink == nil {
		return ErrCredentialSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	registry := source.registry
	if source.index >= uint64(len(registry.config.sources)) {
		return ErrCredentialSourceUnavailable
	}
	identity := registry.config.sources[source.index].identity
	if inspectKeyIdentity(ctx, registry.deps.keyctl, identity) != nil {
		return contextOrUnavailable(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	serial := decodeInt32(identity.serial)
	size, err := registry.deps.keyctl.ReadSize(ctx, serial)
	if err != nil || size <= 0 || size > MaxProductionSecretBytes {
		return contextOrUnavailable(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	capacity := sink.MaxCredentialBytes()
	if capacity <= 0 || capacity > MaxProductionSecretBytes || size > capacity {
		return ErrCredentialSourceUnavailable
	}
	mapping, err := registry.deps.newLockedMapping(capacity)
	if err != nil || mapping == nil {
		return ErrCredentialSourceUnavailable
	}
	defer func() {
		if mapping.Destroy() != nil && result == nil {
			result = ErrCredentialSourceUnavailable
		}
	}()
	if inspectKeyIdentity(ctx, registry.deps.keyctl, identity) != nil {
		return contextOrUnavailable(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := mapping.Load(ctx, func(region []byte) (int, error) {
		if len(region) < size {
			return 0, ErrCredentialSourceUnavailable
		}
		read, readErr := registry.deps.keyctl.ReadInto(ctx, serial, region[:size])
		if readErr != nil || read != size {
			return 0, ErrCredentialSourceUnavailable
		}
		return read, nil
	}); err != nil {
		return contextOrUnavailable(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if inspectKeyIdentity(ctx, registry.deps.keyctl, identity) != nil {
		return contextOrUnavailable(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := mapping.Borrow(ctx, func(view lockedSecretBorrowedView) error {
		return view.WriteTo(ctx, sink)
	}); err != nil {
		return contextOrUnavailable(ctx)
	}
	return nil
}

func inspectKeyIdentity(ctx context.Context, keyctl keyctlReader, identity KeyIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	serial := decodeInt32(identity.serial)
	size, err := keyctl.DescribeSize(ctx, serial)
	if err != nil || size <= 0 || size > MaxKeyctlDescribeBytes {
		return ErrCredentialSourceUnavailable
	}
	buffer := make([]byte, size)
	defer wipe(buffer)
	read, err := keyctl.DescribeInto(ctx, serial, buffer)
	if err != nil || read != size {
		return ErrCredentialSourceUnavailable
	}
	descriptor, err := parseKeyctlDescribe(buffer)
	if err != nil || !keyDescriptorMatchesIdentity(descriptor, identity) {
		return ErrCredentialSourceUnavailable
	}
	return nil
}

func parseKeyctlDescribe(raw []byte) (KeyDescriptor, error) {
	if len(raw) == 0 || len(raw) > MaxKeyctlDescribeBytes || raw[len(raw)-1] != 0 {
		return KeyDescriptor{}, ErrCredentialSourceDescriptor
	}
	for _, value := range raw[:len(raw)-1] {
		if value == 0 {
			return KeyDescriptor{}, ErrCredentialSourceDescriptor
		}
	}
	fields := strings.Split(string(raw[:len(raw)-1]), ";")
	if len(fields) != 5 || fields[0] != "user" || len(fields[3]) != 8 {
		return KeyDescriptor{}, ErrCredentialSourceDescriptor
	}
	uid, uidErr := strconv.ParseUint(fields[1], 10, 32)
	gid, gidErr := strconv.ParseUint(fields[2], 10, 32)
	permissions, permissionErr := strconv.ParseUint(fields[3], 16, 32)
	if uidErr != nil || gidErr != nil || permissionErr != nil {
		return KeyDescriptor{}, ErrCredentialSourceDescriptor
	}
	descriptor, err := NewKeyDescriptor(fields[0], uint32(uid), uint32(gid), KeyPermission(permissions), fields[4])
	if err != nil {
		return KeyDescriptor{}, ErrCredentialSourceDescriptor
	}
	return descriptor, nil
}

func keyDescriptorsEqual(left, right KeyDescriptor) bool {
	return left.keyType == right.keyType && left.ownerUID == right.ownerUID && left.ownerGID == right.ownerGID &&
		left.permissions == right.permissions && left.description == right.description
}

func keyDescriptorMatchesIdentity(descriptor KeyDescriptor, identity KeyIdentity) bool {
	return descriptor.keyType == identity.keyType && descriptor.ownerUID == identity.ownerUID && descriptor.ownerGID == identity.ownerGID &&
		descriptor.permissions == identity.permissions && descriptor.description == identity.description
}

func samePrincipal(left, right sandboxruntime.AuthenticatedWorkerPrincipal) bool {
	return left != nil && right != nil && left == right && left.ID() == right.ID() && left.UID() == right.UID() && left.GID() == right.GID() &&
		left.AuthorityID() == right.AuthorityID() && left.AuthorityGeneration() == right.AuthorityGeneration()
}

func sameAdmissionRequest(left, right sandboxruntime.JobCredentialAdmissionRequest) bool {
	if left.GrantID != right.GrantID || left.GrantRevision != right.GrantRevision || left.PlanID != right.PlanID ||
		left.TemplatePolicyID != right.TemplatePolicyID || left.WorkspacePolicyID != right.WorkspacePolicyID ||
		!sameAdmissionIdentity(left.Identity, right.Identity) || len(left.SourceReferenceIDs) != len(right.SourceReferenceIDs) ||
		len(left.Bindings) != len(right.Bindings) {
		return false
	}
	for index := range left.SourceReferenceIDs {
		if left.SourceReferenceIDs[index] != right.SourceReferenceIDs[index] {
			return false
		}
	}
	for index := range left.Bindings {
		if left.Bindings[index] != right.Bindings[index] {
			return false
		}
	}
	return true
}

func sameAdmissionIdentity(left, right sandboxruntime.JobCredentialAdmissionIdentity) bool {
	return left.SandboxID == right.SandboxID && left.ExecutionID == right.ExecutionID && left.WorkerID == right.WorkerID &&
		left.HostID == right.HostID && left.RuntimeDriver == right.RuntimeDriver && left.RuntimeID == right.RuntimeID &&
		left.RuntimeGeneration == right.RuntimeGeneration && left.FirecrackerProcessGeneration == right.FirecrackerProcessGeneration &&
		left.VsockGeneration == right.VsockGeneration && left.WorkerJobID == right.WorkerJobID && left.SubmissionID == right.SubmissionID &&
		left.PlanID == right.PlanID && left.ActivationGeneration == right.ActivationGeneration && left.CredentialGeneration == right.CredentialGeneration &&
		left.NetworkPlanID == right.NetworkPlanID && left.PolicySnapshotID == right.PolicySnapshotID && left.ProxySessionID == right.ProxySessionID &&
		left.ProxyGenerationID == right.ProxyGenerationID && left.TopologyGenerationID == right.TopologyGenerationID &&
		left.RuleGenerationID == right.RuleGenerationID && left.IssuedAt.Equal(right.IssuedAt)
}

func contextOrUnavailable(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return ErrCredentialSourceUnavailable
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func newCredentialMemoryMapping(capacity int) (lockedSecretMapping, error) {
	mapping, err := credentialmemory.NewLockedMapping(capacity)
	if err != nil {
		return nil, ErrCredentialSourceUnavailable
	}
	return credentialMemoryMapping{mapping}, nil
}

func (mapping credentialMemoryMapping) Load(ctx context.Context, reader func([]byte) (int, error)) error {
	if len(mapping) != 1 || mapping[0] == nil {
		return ErrCredentialSourceUnavailable
	}
	return mapping[0].Load(ctx, reader)
}

func (mapping credentialMemoryMapping) Borrow(ctx context.Context, callback func(lockedSecretBorrowedView) error) error {
	if len(mapping) != 1 || mapping[0] == nil || callback == nil {
		return ErrCredentialSourceUnavailable
	}
	return mapping[0].Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		return callback(credentialMemoryBorrowedView{view})
	})
}

func (mapping credentialMemoryMapping) Destroy() error {
	if len(mapping) != 1 || mapping[0] == nil {
		return ErrCredentialSourceUnavailable
	}
	if err := mapping[0].Destroy(); err != nil {
		return ErrCredentialSourceUnavailable
	}
	return nil
}

func (view credentialMemoryBorrowedView) WriteTo(ctx context.Context, sink sandboxruntime.JobCredentialSecretSink) error {
	if len(view) != 1 || view[0] == nil || sink == nil {
		return ErrCredentialSourceUnavailable
	}
	if err := view[0].WriteTo(ctx, sink); err != nil {
		return contextOrUnavailable(ctx)
	}
	return nil
}
