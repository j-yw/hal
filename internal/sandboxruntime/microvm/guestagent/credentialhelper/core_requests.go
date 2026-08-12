package credentialhelper

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"

const coreFixedLimitSetID credentialprotocol.SafeID = "helper-limits-v1"

type CorePrepareRequest struct {
	liveValue
	correlation     requestCorrelation
	generations     CoreGenerations
	expiresUnixNano int64
	fixedLimitSetID credentialprotocol.SafeID
	manifest        ManifestCapability
	manifestSHA256  [32]byte
	preparation     CorePreparationCapability
	prepared        CorePreparedCapability
	cleanup         CoreCleanupCapability
}

type CoreFileRequest struct {
	liveValue
	correlation  requestCorrelation
	job          credentialprotocol.SafeID
	preparation  CorePreparationCapability
	bindingID    credentialprotocol.SafeID
	bindingIndex uint16
	target       RelativePathCapability
	fileLength   uint32
	fileSHA256   [32]byte
}

type CoreCommitRequest struct {
	liveValue
	correlation       requestCorrelation
	job               credentialprotocol.SafeID
	preparation       CorePreparationCapability
	manifestSHA256    [32]byte
	transactionSHA256 [32]byte
	prepared          CorePreparedCapability
}

type CoreExecRequest struct {
	liveValue
	correlation     requestCorrelation
	generations     CoreGenerations
	fixedLimitSetID credentialprotocol.SafeID
	execBindingID   credentialprotocol.SafeID
	privateLength   uint32
	privateSHA256   [32]byte
	execBodyLength  uint32
	execBodySHA256  [32]byte
	plan            ExecPlanCapability
	prepared        CorePreparedCapability
	execution       CoreExecutionCapability
	cleanup         CoreCleanupCapability
}

type CoreRenewRequest struct {
	liveValue
	correlation     requestCorrelation
	generations     CoreGenerations
	expiresUnixNano int64
	prepared        CorePreparedCapability
}

type CoreRevokeRequest struct {
	liveValue
	correlation requestCorrelation
	generations CoreGenerations
	reason      credentialprotocol.RevokeReason
	prepared    CorePreparedCapability
	cleanup     CoreCleanupCapability
}

type CoreInspectRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	generations    CoreGenerations
	prepared       CorePreparedCapability
}

type CoreOutputRequest struct {
	liveValue
	correlation requestCorrelation
	job         credentialprotocol.SafeID
	execution   CoreExecutionCapability
	kind        credentialprotocol.HelperExecStreamKind
	offset      uint64
	capacity    uint32
}

func NewCorePrepareRequest(requestID [16]byte, identityDigest [32]byte, revision uint64, generations CoreGenerations, expiresUnixNano int64, fixedLimitSetID credentialprotocol.SafeID, manifest ManifestCapability, manifestSHA256 [32]byte, preparation CorePreparationCapability, prepared CorePreparedCapability, cleanup CoreCleanupCapability) (CorePrepareRequest, error) {
	correlation := requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}
	if !validRequestCorrelation(correlation) || !validPartialCoreGenerations(generations) || expiresUnixNano <= 0 || fixedLimitSetID != coreFixedLimitSetID || manifest.count == 0 || manifestSHA256 == ([32]byte{}) || manifest.SHA256() != manifestSHA256 || !validCoreCapabilityDigest(preparation.digest) || !validCoreCapabilityDigest(prepared.digest) || !validCoreCapabilityDigest(cleanup.digest) {
		return CorePrepareRequest{}, ErrContractInvalidArgument
	}
	return CorePrepareRequest{correlation: correlation, generations: generations, expiresUnixNano: expiresUnixNano, fixedLimitSetID: fixedLimitSetID, manifest: manifest, manifestSHA256: manifestSHA256, preparation: preparation, prepared: prepared, cleanup: cleanup}, nil
}

func NewCoreFileRequest(requestID [16]byte, identityDigest [32]byte, revision uint64, job credentialprotocol.SafeID, preparation CorePreparationCapability, bindingID credentialprotocol.SafeID, bindingIndex uint16, target RelativePathCapability, fileLength uint32, fileSHA256 [32]byte) (CoreFileRequest, error) {
	correlation := requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}
	if !validRequestCorrelation(correlation) || !validSafeID(job) || !validCoreCapabilityDigest(preparation.digest) || !validSafeID(bindingID) || bindingIndex >= credentialprotocol.MaxHelperBindings || target.length == 0 || fileLength == 0 || fileLength > credentialprotocol.MaxHelperFileBytes || fileSHA256 == ([32]byte{}) {
		return CoreFileRequest{}, ErrContractInvalidArgument
	}
	return CoreFileRequest{correlation: correlation, job: job, preparation: preparation, bindingID: bindingID, bindingIndex: bindingIndex, target: target, fileLength: fileLength, fileSHA256: fileSHA256}, nil
}

func NewCoreCommitRequest(requestID [16]byte, identityDigest [32]byte, revision uint64, job credentialprotocol.SafeID, preparation CorePreparationCapability, manifestSHA256, transactionSHA256 [32]byte, prepared CorePreparedCapability) (CoreCommitRequest, error) {
	correlation := requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}
	if !validRequestCorrelation(correlation) || !validSafeID(job) || !validCoreCapabilityDigest(preparation.digest) || manifestSHA256 == ([32]byte{}) || transactionSHA256 == ([32]byte{}) || !validCoreCapabilityDigest(prepared.digest) {
		return CoreCommitRequest{}, ErrContractInvalidArgument
	}
	return CoreCommitRequest{correlation: correlation, job: job, preparation: preparation, manifestSHA256: manifestSHA256, transactionSHA256: transactionSHA256, prepared: prepared}, nil
}

func NewCoreExecRequest(requestID [16]byte, identityDigest [32]byte, revision uint64, generations CoreGenerations, fixedLimitSetID, execBindingID credentialprotocol.SafeID, privateLength uint32, privateSHA256 [32]byte, execBodyLength uint32, execBodySHA256 [32]byte, plan ExecPlanCapability, prepared CorePreparedCapability, execution CoreExecutionCapability, cleanup CoreCleanupCapability) (CoreExecRequest, error) {
	correlation := requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}
	privateValid := privateLength == 0 && privateSHA256 == ([32]byte{}) || privateLength > 0 && privateLength <= credentialprotocol.MaxHelperExecPrivateBytes && privateSHA256 != ([32]byte{})
	if !validRequestCorrelation(correlation) || !validCompleteCoreGenerations(generations) || fixedLimitSetID != coreFixedLimitSetID || !validSafeID(execBindingID) || !privateValid || execBodyLength == 0 || execBodyLength > credentialprotocol.MaxHelperPacketBodyBytes || execBodySHA256 == ([32]byte{}) || plan.EncodedLength() == 0 || plan.SHA256() == ([32]byte{}) || !validCoreCapabilityDigest(prepared.digest) || !validCoreCapabilityDigest(execution.digest) || !validCoreCapabilityDigest(cleanup.digest) {
		return CoreExecRequest{}, ErrContractInvalidArgument
	}
	return CoreExecRequest{correlation: correlation, generations: generations, fixedLimitSetID: fixedLimitSetID, execBindingID: execBindingID, privateLength: privateLength, privateSHA256: privateSHA256, execBodyLength: execBodyLength, execBodySHA256: execBodySHA256, plan: plan, prepared: prepared, execution: execution, cleanup: cleanup}, nil
}

func NewCoreRenewRequest(requestID [16]byte, identityDigest [32]byte, revision uint64, generations CoreGenerations, expiresUnixNano int64, prepared CorePreparedCapability) (CoreRenewRequest, error) {
	correlation := requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}
	if !validRequestCorrelation(correlation) || !validCompleteCoreGenerations(generations) || expiresUnixNano <= 0 || !validCoreCapabilityDigest(prepared.digest) {
		return CoreRenewRequest{}, ErrContractInvalidArgument
	}
	return CoreRenewRequest{correlation: correlation, generations: generations, expiresUnixNano: expiresUnixNano, prepared: prepared}, nil
}

func NewCoreRevokeRequest(requestID [16]byte, identityDigest [32]byte, revision uint64, generations CoreGenerations, reason credentialprotocol.RevokeReason, prepared CorePreparedCapability, cleanup CoreCleanupCapability) (CoreRevokeRequest, error) {
	correlation := requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}
	if !validRequestCorrelation(correlation) || !validCompleteCoreGenerations(generations) || credentialprotocol.ValidateRevokeReason(reason) != nil || !validCoreCapabilityDigest(prepared.digest) || !validCoreCapabilityDigest(cleanup.digest) {
		return CoreRevokeRequest{}, ErrContractInvalidArgument
	}
	return CoreRevokeRequest{correlation: correlation, generations: generations, reason: reason, prepared: prepared, cleanup: cleanup}, nil
}

func NewCoreInspectRequest(identityDigest [32]byte, revision uint64, generations CoreGenerations, prepared CorePreparedCapability) (CoreInspectRequest, error) {
	if identityDigest == ([32]byte{}) || revision == 0 || !validCompleteCoreGenerations(generations) || !validCoreCapabilityDigest(prepared.digest) {
		return CoreInspectRequest{}, ErrContractInvalidArgument
	}
	return CoreInspectRequest{identityDigest: identityDigest, revision: revision, generations: generations, prepared: prepared}, nil
}

func NewCoreOutputRequest(requestID [16]byte, identityDigest [32]byte, revision uint64, job credentialprotocol.SafeID, execution CoreExecutionCapability, kind credentialprotocol.HelperExecStreamKind, offset uint64, capacity uint32) (CoreOutputRequest, error) {
	correlation := requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}
	if !validRequestCorrelation(correlation) || !validSafeID(job) || !validCoreCapabilityDigest(execution.digest) || !validCoreOutputKind(kind) || capacity == 0 || capacity > credentialprotocol.MaxHelperExecStreamPayloadBytes {
		return CoreOutputRequest{}, ErrContractInvalidArgument
	}
	return CoreOutputRequest{correlation: correlation, job: job, execution: execution, kind: kind, offset: offset, capacity: capacity}, nil
}

func validCoreOutputKind(kind credentialprotocol.HelperExecStreamKind) bool {
	return kind == credentialprotocol.HelperExecStreamStdout || kind == credentialprotocol.HelperExecStreamStderr
}
