package credentialhelper

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"sync"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	bootstrapIdentityDomain = "hal/l8/guest-helper/agent-identity/v1"
	renewProofDomain        = "hal/l8/guest-helper/renew-proof/v1"
)

type bodyValidationSink struct {
	mu       sync.Mutex
	maximum  int
	validate func([]byte) bool
	writes   int
	valid    bool
	digest   [32]byte
}

type callbackValidationState struct {
	mu    sync.Mutex
	calls int
	valid bool
	err   error
}

type retainedReceivedPayload struct {
	retain bool
	offset uint32
	length uint32
	digest [32]byte
}

type receivedPayloadBody struct {
	owner           ReceivedBodyCapability
	canonicalLength uint32
	offset          uint32
	length          uint32
	digest          [32]byte
}

type borrowedPayloadView struct {
	owner           credentialmemory.BorrowedView
	canonicalLength int
	offset          int
	length          int
}

type payloadSlicingSink struct {
	ctx             context.Context
	sink            credentialmemory.CredentialSink
	canonicalLength int
	offset          int
	length          int
}

type payloadCopySink struct {
	ctx     context.Context
	target  *credentialmemory.LockedMapping
	maximum int
}

func (sink *bodyValidationSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *bodyValidationSink) WriteCredential(value []byte) error {
	valid := len(value) <= sink.maximum && sink.validate(value)
	digest := sha256.Sum256(value)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.writes++
	if sink.writes != 1 {
		sink.valid = false
		return nil
	}
	sink.valid = valid
	sink.digest = digest
	return nil
}

func (sink *bodyValidationSink) snapshot() (int, bool, [32]byte) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.writes, sink.valid, sink.digest
}

func (state *callbackValidationState) record(err error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.calls++
	if state.calls != 1 || err != nil {
		state.valid = false
	}
	if state.err == nil && err != nil {
		state.err = err
	}
}

func (state *callbackValidationState) snapshot() (int, bool, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.calls, state.valid, state.err
}

func (body receivedPayloadBody) Len() uint32 {
	if !configuredDependency(body.owner) || body.owner.Len() != body.canonicalLength {
		return 0
	}
	return body.length
}

func (body receivedPayloadBody) SHA256() [32]byte {
	if !configuredDependency(body.owner) || body.owner.Len() != body.canonicalLength {
		return [32]byte{}
	}
	return body.digest
}

func (body receivedPayloadBody) Borrow(ctx context.Context, callback func(credentialmemory.BorrowedView) error) error {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	if callback == nil || !configuredDependency(body.owner) {
		return ErrContractInvalidArgument
	}
	if ctx.Err() != nil {
		return ErrContractOwnership
	}
	err := body.owner.Borrow(ctx, func(owner credentialmemory.BorrowedView) error {
		if ctx.Err() != nil {
			return ErrContractOwnership
		}
		if !configuredDependency(owner) {
			return ErrContractOwnership
		}
		length := owner.Len()
		if ctx.Err() != nil || length != int(body.canonicalLength) || body.offset > body.canonicalLength || body.length > body.canonicalLength-body.offset {
			return ErrContractOwnership
		}
		callbackErr := callback(borrowedPayloadView{owner: owner, canonicalLength: int(body.canonicalLength), offset: int(body.offset), length: int(body.length)})
		if ctx.Err() != nil {
			return ErrContractOwnership
		}
		return callbackErr
	})
	if ctx.Err() != nil {
		return ErrContractOwnership
	}
	return err
}

func (body receivedPayloadBody) Destroy(ctx context.Context) error {
	return destroyTransportBody(ctx, body.owner)
}

func (view borrowedPayloadView) Len() int {
	if !configuredDependency(view.owner) || view.owner.Len() != view.canonicalLength {
		return 0
	}
	return view.length
}

func (view borrowedPayloadView) CopyTo(ctx context.Context, target *credentialmemory.LockedMapping) error {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	if target == nil {
		return ErrContractInvalidArgument
	}
	return view.WriteTo(ctx, &payloadCopySink{ctx: ctx, target: target, maximum: view.length})
}

func (view borrowedPayloadView) WriteTo(ctx context.Context, sink credentialmemory.CredentialSink) error {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	if !configuredDependency(view.owner) || !configuredDependency(sink) {
		return ErrContractTypedNil
	}
	if ctx.Err() != nil {
		return ErrContractOwnership
	}
	ownerLength := view.owner.Len()
	if ctx.Err() != nil || ownerLength != view.canonicalLength || view.offset < 0 || view.length < 0 || view.offset > view.canonicalLength || view.length > view.canonicalLength-view.offset {
		return ErrContractOwnership
	}
	maximum := sink.MaxCredentialBytes()
	if ctx.Err() != nil || maximum < view.length {
		return ErrContractOwnership
	}
	err := view.owner.WriteTo(ctx, &payloadSlicingSink{ctx: ctx, sink: sink, canonicalLength: view.canonicalLength, offset: view.offset, length: view.length})
	if ctx.Err() != nil {
		return ErrContractOwnership
	}
	return err
}

func (sink *payloadSlicingSink) MaxCredentialBytes() int { return sink.canonicalLength }
func (sink *payloadSlicingSink) WriteCredential(value []byte) error {
	if sink.ctx.Err() != nil {
		return ErrContractOwnership
	}
	if len(value) != sink.canonicalLength || sink.offset < 0 || sink.length < 0 || sink.offset > len(value) || sink.length > len(value)-sink.offset {
		return ErrContractOwnership
	}
	err := sink.sink.WriteCredential(value[sink.offset : sink.offset+sink.length])
	if sink.ctx.Err() != nil {
		return ErrContractOwnership
	}
	return err
}

func (sink *payloadCopySink) MaxCredentialBytes() int { return sink.maximum }
func (sink *payloadCopySink) WriteCredential(value []byte) error {
	if sink.ctx.Err() != nil {
		return ErrContractOwnership
	}
	err := sink.target.Load(sink.ctx, func(region []byte) (int, error) {
		if sink.ctx.Err() != nil {
			return 0, ErrContractOwnership
		}
		if len(value) > len(region) {
			return 0, ErrContractInvalidArgument
		}
		copy(region, value)
		if sink.ctx.Err() != nil {
			return 0, ErrContractOwnership
		}
		return len(value), nil
	})
	if sink.ctx.Err() != nil {
		return ErrContractOwnership
	}
	return err
}

func destroyTransportBody(ctx context.Context, body ReceivedBodyCapability) (err error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	if !configuredDependency(body) {
		return ErrContractDestroyed
	}
	canceled := ctx.Err() != nil
	defer func() {
		if recover() != nil || canceled || ctx.Err() != nil {
			err = ErrContractOwnership
		}
	}()
	if cleanupErr := body.Destroy(ctx); cleanupErr != nil {
		return ErrContractOwnership
	}
	return nil
}

func closeTransportRight(ctx context.Context, right ReceivedCapability) (err error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	if !configuredDependency(right) {
		return ErrContractDestroyed
	}
	canceled := ctx.Err() != nil
	defer func() {
		if recover() != nil || canceled || ctx.Err() != nil {
			err = ErrContractOwnership
		}
	}()
	if cleanupErr := right.Close(ctx); cleanupErr != nil {
		return ErrContractOwnership
	}
	return nil
}

func newReceivedPacket(
	ctx context.Context,
	request ReceiveRequest,
	header credentialprotocol.HelperPacketHeader,
	credential ReceivedKernelCredential,
	credentialCount uint32,
	body ReceivedBodyCapability,
	rightsCount uint32,
	right ReceivedCapability,
	wantType credentialprotocol.PacketType,
	wantRights uint32,
	arm receivedPacketArm,
	retainedPayload retainedReceivedPayload,
	validate func([]byte) bool,
) (packet ReceivedPacket, err error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	ownedBody := configuredDependency(body)
	ownedRight := configuredDependency(right)
	bodyReleased := false
	success := false
	defer func() {
		if success {
			return
		}
		if ownedBody && !bodyReleased {
			bodyReleased = true
			if cleanupErr := destroyTransportBody(ctx, body); cleanupErr != nil {
				err = ErrContractOwnership
			}
		}
		if ownedRight {
			if cleanupErr := closeTransportRight(ctx, right); cleanupErr != nil {
				err = ErrContractOwnership
			}
		}
	}()
	if ctx.Err() != nil {
		return ReceivedPacket{}, ErrContractOwnership
	}

	if request.state == nil || !request.state.consumed.CompareAndSwap(false, true) {
		return ReceivedPacket{}, ErrContractOwnership
	}
	if !ownedBody {
		return ReceivedPacket{}, ErrContractTypedNil
	}
	if credential.pid == 0 || credential.pid > uint32(^uint32(0)>>1) {
		return ReceivedPacket{}, ErrContractInvalidArgument
	}
	if header.Type != wantType || header.Sequence != request.nextSequence {
		return ReceivedPacket{}, ErrContractCorrelation
	}
	if credentialprotocol.ValidateHelperPacketHeaderSemantics(header) != nil {
		return ReceivedPacket{}, ErrContractInvalidArgument
	}
	length := body.Len()
	if ctx.Err() != nil {
		return ReceivedPacket{}, ErrContractOwnership
	}
	if length != header.BodyLength || length > request.maximumBodyBytes || credentialCount != 1 || rightsCount != request.expectedRights || rightsCount != wantRights {
		return ReceivedPacket{}, ErrContractCorrelation
	}
	if wantRights == 0 {
		if ownedRight {
			return ReceivedPacket{}, ErrContractCapability
		}
	} else {
		if !ownedRight {
			return ReceivedPacket{}, ErrContractTypedNil
		}
		kind := right.Kind()
		if ctx.Err() != nil {
			return ReceivedPacket{}, ErrContractOwnership
		}
		digest := right.SHA256()
		if ctx.Err() != nil {
			return ReceivedPacket{}, ErrContractOwnership
		}
		if kind != ReceivedCapabilityAgentPIDFD || digest == ([32]byte{}) {
			return ReceivedPacket{}, ErrContractCapability
		}
	}

	sink := &bodyValidationSink{maximum: int(length), validate: validate}
	callbacks := &callbackValidationState{valid: true}
	if ctx.Err() != nil {
		return ReceivedPacket{}, ErrContractOwnership
	}
	borrowErr := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		var callbackErr error
		if ctx.Err() != nil {
			callbackErr = ErrContractOwnership
		} else if !configuredDependency(view) {
			callbackErr = ErrContractTypedNil
		} else {
			viewLength := view.Len()
			if ctx.Err() != nil || viewLength != int(length) {
				callbackErr = ErrContractOwnership
			} else if writeErr := view.WriteTo(ctx, sink); writeErr != nil {
				callbackErr = ErrContractOwnership
			}
		}
		if ctx.Err() != nil {
			callbackErr = ErrContractOwnership
		}
		callbacks.record(callbackErr)
		return callbackErr
	})
	if ctx.Err() != nil {
		return ReceivedPacket{}, ErrContractOwnership
	}
	callbackCount, callbacksValid, callbackErr := callbacks.snapshot()
	if callbackErr != nil {
		return ReceivedPacket{}, callbackErr
	}
	writes, bodyValid, bodyDigest := sink.snapshot()
	if borrowErr != nil || callbackCount != 1 || !callbacksValid || writes != 1 || !bodyValid {
		return ReceivedPacket{}, ErrContractCorrelation
	}
	sinkDigest := body.SHA256()
	if ctx.Err() != nil {
		return ReceivedPacket{}, ErrContractOwnership
	}
	if sinkDigest == ([32]byte{}) || subtle.ConstantTimeCompare(sinkDigest[:], bodyDigest[:]) != 1 {
		return ReceivedPacket{}, ErrContractCorrelation
	}

	packet = ReceivedPacket{header: header, arm: arm, credential: credential, right: right}
	if retainedPayload.retain {
		if retainedPayload.offset > length || retainedPayload.length > length-retainedPayload.offset || retainedPayload.digest == ([32]byte{}) {
			return ReceivedPacket{}, ErrContractInvalidArgument
		}
		packet.body = receivedPayloadBody{owner: body, canonicalLength: length, offset: retainedPayload.offset, length: retainedPayload.length, digest: retainedPayload.digest}
	} else {
		bodyReleased = true
		if destroyErr := destroyTransportBody(ctx, body); destroyErr != nil {
			return ReceivedPacket{}, ErrContractOwnership
		}
	}
	success = true
	return packet, nil
}

func NewReceivedBootstrapPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, agentPID, agentUID, agentGID uint32, bootGeneration, helperGeneration credentialprotocol.SafeID, right ReceivedCapability) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if agentPID == 0 || agentPID > uint32(^uint32(0)>>1) || credentialprotocol.ValidateSafeID(bootGeneration) != nil || credentialprotocol.ValidateSafeID(helperGeneration) != nil {
		return failedReceivedInputs(ctx, request, body, right, ErrContractInvalidArgument)
	}
	arm := ReceivedBootstrap{agentIdentitySHA256: hashAgentIdentity(agentPID, agentUID, agentGID), bootGeneration: bootGeneration, helperGeneration: helperGeneration}
	return newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, right, credentialprotocol.PacketTypeBootstrap, 1, arm, retainedReceivedPayload{}, func(encoded []byte) bool {
		if len(encoded) < 16 {
			return false
		}
		pid, uid, gid := binary.BigEndian.Uint32(encoded[:4]), binary.BigEndian.Uint32(encoded[4:8]), binary.BigEndian.Uint32(encoded[8:12])
		boot, consumed, decodeErr := credentialprotocol.DecodeBodyTokenPrefix(encoded[12:])
		if decodeErr != nil {
			return false
		}
		helper, helperConsumed, decodeErr := credentialprotocol.DecodeBodyTokenPrefix(encoded[12+consumed:])
		return decodeErr == nil && 12+consumed+helperConsumed == len(encoded) && pid == agentPID && uid == agentUID && gid == agentGID && boot == string(bootGeneration) && helper == string(helperGeneration)
	})
}

func NewReceivedAgentHelloPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, bootstrapSHA256 [32]byte, bootGeneration, helperGeneration credentialprotocol.SafeID, processDescriptorSHA256 [32]byte) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if bootstrapSHA256 == ([32]byte{}) || processDescriptorSHA256 == ([32]byte{}) || credentialprotocol.ValidateSafeID(bootGeneration) != nil || credentialprotocol.ValidateSafeID(helperGeneration) != nil {
		return failedReceivedInputs(ctx, request, body, nil, ErrContractInvalidArgument)
	}
	arm := ReceivedAgentHello{bootstrapSHA256: bootstrapSHA256, bootGeneration: bootGeneration, helperGeneration: helperGeneration, processDescriptorSHA256: processDescriptorSHA256}
	return newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, nil, credentialprotocol.PacketTypeAgentHello, 0, arm, retainedReceivedPayload{}, func(encoded []byte) bool {
		if len(encoded) < 38 || !equalDigest(encoded[:32], bootstrapSHA256) {
			return false
		}
		boot, n, decodeErr := credentialprotocol.DecodeBodyTokenPrefix(encoded[32:])
		if decodeErr != nil {
			return false
		}
		helper, m, decodeErr := credentialprotocol.DecodeBodyTokenPrefix(encoded[32+n:])
		offset := 32 + n + m
		if decodeErr != nil || offset+2 > len(encoded) {
			return false
		}
		declared := uint32(binary.BigEndian.Uint16(encoded[offset : offset+2]))
		descriptor := encoded[offset+2:]
		return boot == string(bootGeneration) && helper == string(helperGeneration) && declared >= 1 && declared <= 1898 && uint32(len(descriptor)) == declared && sha256.Sum256(descriptor) == processDescriptorSHA256
	})
}

func NewReceivedPrepareBeginPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, decoded credentialprotocol.HelperPrepareBeginBody, manifest ManifestCapability) (packet ReceivedPacket, err error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	delegatedBody := false
	success := false
	var transaction *credentialprotocol.HelperPrepareTransaction
	defer func() {
		if success {
			return
		}
		if transaction != nil {
			transaction.Close()
		}
		if !delegatedBody {
			_, cleanupErr := failedReceivedInputs(ctx, request, body, nil, err)
			if cleanupErr != nil {
				err = cleanupErr
			}
		}
	}()
	if ctx.Err() != nil {
		err = ErrContractOwnership
		return ReceivedPacket{}, err
	}
	canonical, encodeErr := credentialprotocol.EncodeHelperPrepareBeginBody(decoded)
	manifestDigest, manifestErr := credentialprotocol.ComputeHelperManifestSHA256(decoded.Bindings)
	correlation, correlationErr := credentialprotocol.NewHelperPrepareTransactionCorrelation(header.RequestID, header.GuestCredentialIdentityDigest, decoded.Revision, decoded.ExpiryUnixNano)
	var transactionErr error
	transaction, transactionErr = credentialprotocol.NewHelperPrepareTransaction(correlation, decoded, manifestDigest)
	if encodeErr != nil || manifestErr != nil || correlationErr != nil || transactionErr != nil || transaction == nil || manifest.Count() == 0 || manifest.SHA256() != manifestDigest {
		wipeBytes(canonical)
		err = ErrContractInvalidArgument
		return ReceivedPacket{}, err
	}
	wantDigest := sha256.Sum256(canonical)
	wantLength := len(canonical)
	wipeBytes(canonical)
	arm := ReceivedPrepareBegin{revision: decoded.Revision, expiryUnixNano: decoded.ExpiryUnixNano, manifest: manifest, transaction: transaction}
	delegatedBody = true
	packet, err = newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, nil, credentialprotocol.PacketTypePrepareBegin, 0, arm, retainedReceivedPayload{}, func(encoded []byte) bool {
		return len(encoded) == wantLength && sha256.Sum256(encoded) == wantDigest
	})
	if err == nil {
		success = true
	}
	return packet, err
}

func NewReceivedPrepareFilePacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, revision uint64, bindingIndex uint16, fileLength uint32, fileSHA256 [32]byte) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if revision == 0 || bindingIndex >= credentialprotocol.MaxHelperBindings || fileLength == 0 || fileLength > credentialprotocol.MaxHelperFileBytes || fileSHA256 == ([32]byte{}) {
		return failedReceivedInputs(ctx, request, body, nil, ErrContractInvalidArgument)
	}
	arm := ReceivedPrepareFile{revision: revision, bindingIndex: bindingIndex, fileLength: fileLength, fileSHA256: fileSHA256}
	return newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, nil, credentialprotocol.PacketTypePrepareFile, 0, arm, retainedReceivedPayload{retain: true, offset: 46, length: fileLength, digest: fileSHA256}, func(encoded []byte) bool {
		return len(encoded) == 46+int(fileLength) && binary.BigEndian.Uint64(encoded[:8]) == revision && binary.BigEndian.Uint16(encoded[8:10]) == bindingIndex && binary.BigEndian.Uint32(encoded[10:14]) == fileLength && equalDigest(encoded[14:46], fileSHA256) && sha256.Sum256(encoded[46:]) == fileSHA256
	})
}

func NewReceivedPrepareCommitPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, decoded credentialprotocol.HelperPrepareCommitBody) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	encoded, encodeErr := credentialprotocol.EncodeHelperPrepareCommitBody(decoded)
	return receivedCanonicalPacket(ctx, request, header, credential, credentialCount, body, rightsCount, credentialprotocol.PacketTypePrepareCommit, ReceivedPrepareCommit{revision: decoded.Revision, manifestSHA256: decoded.ManifestSHA256}, encoded, encodeErr)
}

func NewReceivedRenewPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, revision uint64, expiryUnixNano int64, priorProofID credentialprotocol.SafeID) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if credentialprotocol.ValidateSafeID(priorProofID) != nil {
		return failedReceivedInputs(ctx, request, body, nil, ErrContractInvalidArgument)
	}
	decoded := credentialprotocol.HelperRenewBody{Revision: revision, ExpiryUnixNano: expiryUnixNano, PriorProofID: string(priorProofID)}
	encoded, encodeErr := credentialprotocol.EncodeHelperRenewBody(decoded)
	return receivedCanonicalPacket(ctx, request, header, credential, credentialCount, body, rightsCount, credentialprotocol.PacketTypeRenew, ReceivedRenew{revision: revision, expiryUnixNano: expiryUnixNano, priorProofSHA256: hashOpaqueToken(renewProofDomain, priorProofID)}, encoded, encodeErr)
}

func NewReceivedRevokePacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, decoded credentialprotocol.HelperRevokeBody) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	encoded, encodeErr := credentialprotocol.EncodeHelperRevokeBody(decoded)
	return receivedCanonicalPacket(ctx, request, header, credential, credentialCount, body, rightsCount, credentialprotocol.PacketTypeRevoke, ReceivedRevoke{revision: decoded.Revision, reason: decoded.Reason}, encoded, encodeErr)
}

func NewReceivedExecPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, decoded credentialprotocol.HelperExecBody, plan ExecPlanCapability) (packet ReceivedPacket, err error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	delegatedBody := false
	success := false
	claimed := false
	var transactionSeed credentialprotocol.HelperExecTransactionSeed
	defer func() {
		if success || !claimed {
			return
		}
		transactionSeed.Close()
		plan.destroy()
		if !delegatedBody {
			_, cleanupErr := failedReceivedInputs(ctx, request, body, nil, err)
			if cleanupErr != nil {
				err = cleanupErr
			}
		}
	}()
	claimErr := plan.claimAndMatch(decoded.Plan, &claimed)
	if !claimed {
		return ReceivedPacket{}, claimErr
	}
	if claimErr != nil {
		return ReceivedPacket{}, claimErr
	}
	if ctx.Err() != nil {
		err = ErrContractOwnership
		return ReceivedPacket{}, err
	}
	execBindingID := credentialprotocol.SafeID(decoded.ExecBindingID)
	correlation, correlationErr := credentialprotocol.NewHelperExecTransactionCorrelation(header.RequestID, header.GuestCredentialIdentityDigest, decoded.Revision)
	var transactionErr error
	transactionSeed, transactionErr = credentialprotocol.NewHelperExecTransactionSeed(correlation, decoded)
	if credentialprotocol.ValidateSafeID(execBindingID) != nil || correlationErr != nil || transactionErr != nil {
		err = ErrContractInvalidArgument
		return ReceivedPacket{}, err
	}
	canonical, encodeErr := credentialprotocol.EncodeHelperExecBody(decoded)
	if encodeErr != nil {
		wipeBytes(canonical)
		err = ErrContractInvalidArgument
		return ReceivedPacket{}, err
	}
	wantDigest, wantLength := sha256.Sum256(canonical), len(canonical)
	wipeBytes(canonical)
	arm := ReceivedExec{
		revision: decoded.Revision, execBindingID: execBindingID,
		privateLength: decoded.PrivateBindingLength, privateSHA256: decoded.PrivateBindingSHA256,
		plan: plan, transactionSeed: transactionSeed,
	}
	delegatedBody = true
	packet, err = newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, nil, credentialprotocol.PacketTypeExec, 0, arm, retainedReceivedPayload{}, func(encoded []byte) bool {
		return len(encoded) == wantLength && sha256.Sum256(encoded) == wantDigest
	})
	if err == nil {
		success = true
	}
	return packet, err
}

func NewReceivedExecPrivatePacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, revision uint64, privateBindingLength uint32, privateBindingSHA256 [32]byte) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if revision == 0 || privateBindingLength == 0 || privateBindingLength > credentialprotocol.MaxHelperExecPrivateBytes || privateBindingSHA256 == ([32]byte{}) {
		return failedReceivedInputs(ctx, request, body, nil, ErrContractInvalidArgument)
	}
	arm := ReceivedExecPrivate{revision: revision, privateBindingLength: privateBindingLength, privateBindingSHA256: privateBindingSHA256}
	return newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, nil, credentialprotocol.PacketTypeExecPrivate, 0, arm, retainedReceivedPayload{retain: true, offset: 44, length: privateBindingLength, digest: privateBindingSHA256}, func(encoded []byte) bool {
		return len(encoded) == 44+int(privateBindingLength) && binary.BigEndian.Uint64(encoded[:8]) == revision && binary.BigEndian.Uint32(encoded[8:12]) == privateBindingLength && equalDigest(encoded[12:44], privateBindingSHA256) && sha256.Sum256(encoded[44:]) == privateBindingSHA256
	})
}

func NewReceivedExecStreamPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, revision uint64, streamKind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, offset uint64, payloadLength uint32, payloadSHA256 [32]byte) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if revision == 0 || streamKind != credentialprotocol.HelperExecStreamStdin || (flags != credentialprotocol.HelperExecStreamFlagsNone && flags != credentialprotocol.HelperExecStreamFlagEOF) || payloadLength > credentialprotocol.MaxHelperExecStreamPayloadBytes || (flags == credentialprotocol.HelperExecStreamFlagsNone && payloadLength == 0) || (flags == credentialprotocol.HelperExecStreamFlagEOF && payloadLength != 0) || (payloadLength == 0 && payloadSHA256 != sha256.Sum256(nil)) || (payloadLength > 0 && payloadSHA256 == ([32]byte{})) {
		return failedReceivedInputs(ctx, request, body, nil, ErrContractInvalidArgument)
	}
	arm := ReceivedExecStream{revision: revision, streamKind: streamKind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256}
	return newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, nil, credentialprotocol.PacketTypeExecStream, 0, arm, retainedReceivedPayload{retain: true, offset: 56, length: payloadLength, digest: payloadSHA256}, func(encoded []byte) bool {
		if len(encoded) != 56+int(payloadLength) || binary.BigEndian.Uint64(encoded[:8]) != revision || encoded[8] != byte(streamKind) || encoded[9] != byte(flags) || encoded[10] != 0 || encoded[11] != 0 || binary.BigEndian.Uint64(encoded[12:20]) != offset || binary.BigEndian.Uint32(encoded[20:24]) != payloadLength || !equalDigest(encoded[24:56], payloadSHA256) {
			return false
		}
		return sha256.Sum256(encoded[56:]) == payloadSHA256
	})
}

func NewReceivedExecCreditPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, decoded credentialprotocol.HelperExecCreditBody) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if decoded.StreamKind != credentialprotocol.HelperExecStreamStdout && decoded.StreamKind != credentialprotocol.HelperExecStreamStderr {
		return failedReceivedInputs(ctx, request, body, nil, ErrContractInvalidArgument)
	}
	encoded, encodeErr := credentialprotocol.EncodeHelperExecCreditBody(decoded)
	return receivedCanonicalPacket(ctx, request, header, credential, credentialCount, body, rightsCount, credentialprotocol.PacketTypeExecCredit, ReceivedExecCredit{revision: decoded.Revision, streamKind: decoded.StreamKind, nextOffset: decoded.NextOffset}, encoded, encodeErr)
}

func NewReceivedCloseNotifyPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, decoded credentialprotocol.HelperCloseNotifyBody) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	encoded, encodeErr := credentialprotocol.EncodeHelperCloseNotifyBody(decoded)
	return receivedCanonicalPacket(ctx, request, header, credential, credentialCount, body, rightsCount, credentialprotocol.PacketTypeCloseNotify, ReceivedCloseNotify{reason: decoded.Reason}, encoded, encodeErr)
}

func receivedCanonicalPacket(ctx context.Context, request ReceiveRequest, header credentialprotocol.HelperPacketHeader, credential ReceivedKernelCredential, credentialCount uint32, body ReceivedBodyCapability, rightsCount uint32, packetType credentialprotocol.PacketType, arm receivedPacketArm, canonical []byte, encodeErr error) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		wipeBytes(canonical)
		return ReceivedPacket{}, contextErr
	}
	if encodeErr != nil {
		wipeBytes(canonical)
		return failedReceivedInputs(ctx, request, body, nil, ErrContractInvalidArgument)
	}
	digest, length := sha256.Sum256(canonical), len(canonical)
	wipeBytes(canonical)
	return newReceivedPacket(ctx, request, header, credential, credentialCount, body, rightsCount, nil, packetType, 0, arm, retainedReceivedPayload{}, func(encoded []byte) bool {
		return len(encoded) == length && sha256.Sum256(encoded) == digest
	})
}

func failedReceivedInputs(ctx context.Context, request ReceiveRequest, body ReceivedBodyCapability, right ReceivedCapability, err error) (ReceivedPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ReceivedPacket{}, contextErr
	}
	if request.state == nil || !request.state.consumed.CompareAndSwap(false, true) {
		err = ErrContractOwnership
	}
	if !configuredDependency(body) || right != nil && !configuredDependency(right) {
		err = ErrContractTypedNil
	}
	if configuredDependency(body) {
		if cleanupErr := destroyTransportBody(ctx, body); cleanupErr != nil {
			err = ErrContractOwnership
		}
	}
	if configuredDependency(right) {
		if cleanupErr := closeTransportRight(ctx, right); cleanupErr != nil {
			err = ErrContractOwnership
		}
	}
	return ReceivedPacket{}, err
}

func equalDigest(encoded []byte, digest [32]byte) bool {
	return len(encoded) == len(digest) && subtle.ConstantTimeCompare(encoded, digest[:]) == 1
}

func hashAgentIdentity(pid, uid, gid uint32) [32]byte {
	h := sha256.New()
	writeOpaqueDomain(h, bootstrapIdentityDomain)
	var values [12]byte
	binary.BigEndian.PutUint32(values[:4], pid)
	binary.BigEndian.PutUint32(values[4:8], uid)
	binary.BigEndian.PutUint32(values[8:12], gid)
	_, _ = h.Write(values[:])
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func hashOpaqueToken(domain string, value credentialprotocol.SafeID) [32]byte {
	h := sha256.New()
	writeOpaqueDomain(h, domain)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func writeOpaqueDomain(h hash.Hash, domain string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(domain)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(domain))
}
