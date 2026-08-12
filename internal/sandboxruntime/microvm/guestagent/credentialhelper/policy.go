package credentialhelper

import (
	"crypto/sha256"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	helperPolicyID           credentialprotocol.SafeID = "helper-policy-v1"
	helperPolicyDigestDomain string                    = "hal/l8/process-policy/v1"
)

// Policy authorizes only canonical safe helper metadata. It cannot mint or
// inspect transport, process, filesystem, or other live authority.
type Policy interface {
	Authorize(PolicyRequest) (PolicyDecision, error)
	Descriptor() PolicyDescriptor
}

// PolicyOperation is the closed helper policy operation catalog.
type PolicyOperation uint8

const (
	PolicyOperationPrepare PolicyOperation = 1
	PolicyOperationExec    PolicyOperation = 2
	PolicyOperationRenew   PolicyOperation = 3
	PolicyOperationRevoke  PolicyOperation = 4
	PolicyOperationInspect PolicyOperation = 5
)

// PolicyRejectionCode is the closed safe helper policy rejection catalog.
type PolicyRejectionCode uint8

const (
	PolicyRejectionMalformed          PolicyRejectionCode = 1
	PolicyRejectionIdentityMismatch   PolicyRejectionCode = 2
	PolicyRejectionRevisionStale      PolicyRejectionCode = 3
	PolicyRejectionExpired            PolicyRejectionCode = 4
	PolicyRejectionResourceLimit      PolicyRejectionCode = 5
	PolicyRejectionManifestMismatch   PolicyRejectionCode = 6
	PolicyRejectionGenerationMismatch PolicyRejectionCode = 7
	PolicyRejectionOperationDenied    PolicyRejectionCode = 8
)

// PolicyRequest is an immutable, non-serializable projection of safe decoded
// metadata. The service separately owns all live correlation decisions.
type PolicyRequest struct {
	liveValue
	operation       PolicyOperation
	correlation     requestCorrelation
	generations     CoreGenerations
	expiresUnixNano int64
	fixedLimitSetID credentialprotocol.SafeID
	manifest        ManifestCapability
	manifestSHA256  [32]byte
	execBodyBytes   uint32
	execBodySHA256  [32]byte
	privateBytes    uint32
	privateSHA256   [32]byte
}

// PolicyDecision is exactly allow or one known nonzero safe rejection code.
type PolicyDecision struct {
	liveValue
	allow         bool
	rejectionCode PolicyRejectionCode
}

// PolicyDescriptor is the immutable, non-serializable helper policy identity.
type PolicyDescriptor struct {
	liveValue
	id     credentialprotocol.SafeID
	digest [32]byte
}

// NewPolicyRequest constructs one exact operation-specific policy value.
func NewPolicyRequest(
	operation PolicyOperation,
	requestID [16]byte,
	identityDigest [32]byte,
	revision uint64,
	generations CoreGenerations,
	expiresUnixNano int64,
	fixedLimitSetID credentialprotocol.SafeID,
	manifest ManifestCapability,
	manifestSHA256 [32]byte,
	execBodyBytes uint32,
	execBodySHA256 [32]byte,
	privateBytes uint32,
	privateSHA256 [32]byte,
) (PolicyRequest, error) {
	request := PolicyRequest{
		operation:       operation,
		correlation:     requestCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision},
		generations:     generations,
		expiresUnixNano: expiresUnixNano,
		fixedLimitSetID: fixedLimitSetID,
		manifest:        manifest,
		manifestSHA256:  manifestSHA256,
		execBodyBytes:   execBodyBytes,
		execBodySHA256:  execBodySHA256,
		privateBytes:    privateBytes,
		privateSHA256:   privateSHA256,
	}
	decision := authorizeHelperPolicyRequest(request)
	if !decision.allow {
		return PolicyRequest{}, ErrContractInvalidArgument
	}
	return request, nil
}

func (request PolicyRequest) Operation() PolicyOperation   { return request.operation }
func (request PolicyRequest) RequestID() [16]byte          { return request.correlation.requestID }
func (request PolicyRequest) IdentityDigest() [32]byte     { return request.correlation.identityDigest }
func (request PolicyRequest) Revision() uint64             { return request.correlation.revision }
func (request PolicyRequest) Generations() CoreGenerations { return request.generations }
func (request PolicyRequest) ExpiresUnixNano() int64       { return request.expiresUnixNano }
func (request PolicyRequest) FixedLimitSetID() credentialprotocol.SafeID {
	return request.fixedLimitSetID
}
func (request PolicyRequest) Manifest() ManifestCapability { return request.manifest }
func (request PolicyRequest) ManifestSHA256() [32]byte     { return request.manifestSHA256 }
func (request PolicyRequest) ExecBodyBytes() uint32        { return request.execBodyBytes }
func (request PolicyRequest) ExecBodySHA256() [32]byte     { return request.execBodySHA256 }
func (request PolicyRequest) PrivateBytes() uint32         { return request.privateBytes }
func (request PolicyRequest) PrivateSHA256() [32]byte      { return request.privateSHA256 }

// Allowed reports whether this is the sole valid allow decision shape.
func (decision PolicyDecision) Allowed() bool {
	return decision.allow && decision.rejectionCode == 0
}

// RejectionCode returns the stable safe rejection code, or zero for allow.
func (decision PolicyDecision) RejectionCode() PolicyRejectionCode {
	if decision.allow || !validPolicyRejectionCode(decision.rejectionCode) {
		return 0
	}
	return decision.rejectionCode
}

// ID returns a safe value copy of the fixed helper policy ID.
func (descriptor PolicyDescriptor) ID() credentialprotocol.SafeID { return descriptor.id }

// SHA256 returns a value copy of the fixed helper process-policy digest.
func (descriptor PolicyDescriptor) SHA256() [32]byte { return descriptor.digest }

func newPolicyAllowDecision() PolicyDecision {
	return PolicyDecision{allow: true}
}

func newPolicyRejectionDecision(code PolicyRejectionCode) PolicyDecision {
	if !validPolicyRejectionCode(code) {
		return PolicyDecision{}
	}
	return PolicyDecision{rejectionCode: code}
}

func validPolicyRejectionCode(code PolicyRejectionCode) bool {
	switch code {
	case PolicyRejectionMalformed,
		PolicyRejectionIdentityMismatch,
		PolicyRejectionRevisionStale,
		PolicyRejectionExpired,
		PolicyRejectionResourceLimit,
		PolicyRejectionManifestMismatch,
		PolicyRejectionGenerationMismatch,
		PolicyRejectionOperationDenied:
		return true
	default:
		return false
	}
}

type helperPolicy struct{ liveValue }

// NewHelperPolicy returns the sole stateless deny-by-default helper policy.
func NewHelperPolicy() Policy { return helperPolicy{} }

func (helperPolicy) Authorize(request PolicyRequest) (PolicyDecision, error) {
	return authorizeHelperPolicyRequest(request), nil
}

func (helperPolicy) Descriptor() PolicyDescriptor { return newHelperPolicyDescriptor() }

func newHelperPolicyDescriptor() PolicyDescriptor {
	var encoded [2 + len(helperPolicyDigestDomain) + 2 + len(helperPolicyID)]byte
	offset := 0
	encoded[offset] = byte(len(helperPolicyDigestDomain) >> 8)
	encoded[offset+1] = byte(len(helperPolicyDigestDomain))
	offset += 2
	offset += copy(encoded[offset:], helperPolicyDigestDomain)
	encoded[offset] = byte(len(helperPolicyID) >> 8)
	encoded[offset+1] = byte(len(helperPolicyID))
	offset += 2
	copy(encoded[offset:], helperPolicyID)
	return PolicyDescriptor{id: helperPolicyID, digest: sha256.Sum256(encoded[:])}
}

func authorizeHelperPolicyRequest(request PolicyRequest) PolicyDecision {
	if !validPolicyOperation(request.operation) {
		return newPolicyRejectionDecision(PolicyRejectionOperationDenied)
	}
	if !validPolicyRequestShape(request) {
		return newPolicyRejectionDecision(PolicyRejectionMalformed)
	}
	if !validPolicyRequestLimits(request) {
		return newPolicyRejectionDecision(PolicyRejectionResourceLimit)
	}
	if !validPolicyRequestManifest(request) {
		return newPolicyRejectionDecision(PolicyRejectionManifestMismatch)
	}
	return newPolicyAllowDecision()
}

func validPolicyOperation(operation PolicyOperation) bool {
	switch operation {
	case PolicyOperationPrepare, PolicyOperationExec, PolicyOperationRenew, PolicyOperationRevoke, PolicyOperationInspect:
		return true
	default:
		return false
	}
}

func validPolicyRequestShape(request PolicyRequest) bool {
	if request.correlation.identityDigest == ([32]byte{}) || request.correlation.revision == 0 {
		return false
	}
	packetRequest := request.operation != PolicyOperationInspect
	if packetRequest != (request.correlation.requestID != [16]byte{}) {
		return false
	}

	switch request.operation {
	case PolicyOperationPrepare:
		return validPartialCoreGenerations(request.generations) &&
			request.expiresUnixNano > 0 && request.manifest.count > 0 &&
			request.execBodyBytes == 0 && request.execBodySHA256 == ([32]byte{}) &&
			request.privateBytes == 0 && request.privateSHA256 == ([32]byte{})
	case PolicyOperationExec:
		return validCompleteCoreGenerations(request.generations) &&
			request.expiresUnixNano == 0 && request.manifest.count > 0 &&
			request.execBodyBytes > 0 && request.execBodySHA256 != ([32]byte{}) &&
			validPolicyOptionalDigestPair(request.privateBytes, request.privateSHA256)
	case PolicyOperationRenew:
		return validCompleteCoreGenerations(request.generations) && request.expiresUnixNano > 0 &&
			policyManifestAndBodiesAbsent(request)
	case PolicyOperationRevoke, PolicyOperationInspect:
		return validCompleteCoreGenerations(request.generations) && request.expiresUnixNano == 0 &&
			policyManifestAndBodiesAbsent(request)
	default:
		return false
	}
}

func validPolicyOptionalDigestPair(length uint32, digest [32]byte) bool {
	return length == 0 && digest == ([32]byte{}) || length > 0 && digest != ([32]byte{})
}

func policyManifestAndBodiesAbsent(request PolicyRequest) bool {
	return request.manifest == (ManifestCapability{}) && request.manifestSHA256 == ([32]byte{}) &&
		request.execBodyBytes == 0 && request.execBodySHA256 == ([32]byte{}) &&
		request.privateBytes == 0 && request.privateSHA256 == ([32]byte{})
}

func validPolicyRequestLimits(request PolicyRequest) bool {
	if request.fixedLimitSetID != coreFixedLimitSetID {
		return false
	}
	if request.manifest.count > credentialprotocol.MaxHelperBindings {
		return false
	}
	if request.operation == PolicyOperationExec {
		if request.execBodyBytes > credentialprotocol.MaxHelperPacketBodyBytes || request.privateBytes > credentialprotocol.MaxHelperExecPrivateBytes {
			return false
		}
	}
	return validPolicyManifestResourceLimits(request.manifest)
}

func validPolicyManifestResourceLimits(manifest ManifestCapability) bool {
	var aggregate uint64
	httpBindings := uint16(0)
	sshBindings := uint16(0)
	for index := uint16(0); index < manifest.count && index < credentialprotocol.MaxHelperBindings; index++ {
		record := manifest.records[index]
		switch record.mode {
		case credentialprotocol.DeliveryModeHTTPProxy:
			httpBindings++
		case credentialprotocol.DeliveryModeSSHAgent:
			sshBindings++
		case credentialprotocol.DeliveryModeFileTmpfs:
			if record.declaredFileBytes > credentialprotocol.MaxHelperFileBytes {
				return false
			}
			aggregate += uint64(record.declaredFileBytes)
		}
	}
	return httpBindings <= 1 && sshBindings <= 1 && aggregate <= credentialprotocol.MaxHelperFileAggregateBytes
}

func validPolicyRequestManifest(request PolicyRequest) bool {
	if request.operation != PolicyOperationPrepare && request.operation != PolicyOperationExec {
		return true
	}
	if request.manifestSHA256 == ([32]byte{}) || request.manifest.SHA256() != request.manifestSHA256 {
		return false
	}
	for index := request.manifest.count; index < credentialprotocol.MaxHelperBindings; index++ {
		if request.manifest.records[index] != (manifestRecord{}) {
			return false
		}
	}
	return true
}
