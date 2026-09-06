package credentialhelper

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"math"
	"sync"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type serviceCoreCapabilityKind uint8

const (
	serviceCoreCapabilityPreparation serviceCoreCapabilityKind = 1
	serviceCoreCapabilityPrepared    serviceCoreCapabilityKind = 2
	serviceCoreCapabilityExecution   serviceCoreCapabilityKind = 3
	serviceCoreCapabilityCleanup     serviceCoreCapabilityKind = 4
)

type servicePrepareCapabilities struct {
	preparation CorePreparationCapability
	prepared    CorePreparedCapability
	cleanup     CoreCleanupCapability
}

type servicePrepareAuthority struct {
	header      credentialprotocol.HelperPacketHeader
	bootstrap   ServiceBootstrap
	observation ServiceJobObservation
	correlation credentialprotocol.HelperPrepareTransactionCorrelation
	prepare     CorePrepareRequest
	transaction *credentialprotocol.HelperPrepareTransaction
}

type servicePreparing struct {
	authority   servicePrepareAuthority
	preparation CorePreparation
	beginTaken  bool
	fileTaken   bool
	commitTaken bool
	active      bool
}

type servicePreparedActivationCandidate struct {
	issuingCorrelation requestCorrelation
	bootNonce          [32]byte
	generations        CoreGenerations
	observedUnixNano   int64
	hardExpiryUnixNano int64
	expiresUnixNano    int64
	manifest           ManifestCapability
	bindingCount       uint16
	manifestSHA256     [32]byte
	transactionSHA256  [32]byte
	prepared           CorePreparedCapability
	cleanup            CoreCleanupCapability
	activeProofID      credentialprotocol.SafeID
}

type servicePreparedActivation struct {
	issuingCorrelation requestCorrelation
	revision           uint64
	bootNonce          [32]byte
	generations        CoreGenerations
	observedUnixNano   int64
	hardExpiryUnixNano int64
	expiresUnixNano    int64
	manifest           ManifestCapability
	bindingCount       uint16
	manifestSHA256     [32]byte
	transactionSHA256  [32]byte
	prepared           CorePreparedCapability
	cleanup            CoreCleanupCapability
	activeProofID      credentialprotocol.SafeID
	active             bool
}

type serviceRenewAuthority struct {
	activation servicePreparedActivation
}

type serviceExecCapabilities struct {
	execution CoreExecutionCapability
	cleanup   CoreCleanupCapability
}

type serviceExecAuthority struct {
	request     CoreExecRequest
	plan        ExecPlanCapability
	revision    uint64
	transaction *credentialprotocol.HelperExecTransaction
	correlation credentialprotocol.HelperExecTransactionCorrelation
	comparison  bool
}

type serviceExecPlanSink struct {
	canonical [credentialprotocol.MaxHelperExecPlanBytes]byte
	length    uint32
	written   bool
}

type serviceState struct {
	mu                  sync.Mutex
	sendMu              sync.Mutex
	serveCalled         bool
	nextReceiveSequence uint64
	nextSendSequence    uint64
	preparing           servicePreparing
	prepared            servicePreparedActivation
	execution           CoreExecution
	request             CoreExecRequest
	plan                ExecPlanCapability
	revision            uint64
	transaction         *credentialprotocol.HelperExecTransaction
	correlation         credentialprotocol.HelperExecTransactionCorrelation
	comparison          bool
	dispatchTaken       bool
}

type Service struct {
	core       Core
	transport  Transport
	policy     Policy
	extensions []extensionEntry
	host       ExtensionHost
	runtime    ServiceRuntime
	state      *serviceState
}

type serviceExecDispatch struct {
	transaction *credentialprotocol.HelperExecTransaction
	correlation credentialprotocol.HelperExecTransactionCorrelation
	comparison  bool
}

// NewService validates and snapshots the complete configured dependency set.
func NewService(options ServiceOptions) (*Service, error) {
	if !configuredDependency(options.Core) || !configuredDependency(options.Transport) || !configuredDependency(options.Policy) || !configuredDependency(options.Host) || !configuredDependency(options.Runtime) {
		return nil, ErrContractDependency
	}
	extensions := snapshotServiceExtensionEntries(options.Extensions)
	return &Service{core: options.Core, transport: options.Transport, policy: options.Policy, extensions: extensions, host: options.Host, runtime: options.Runtime, state: &serviceState{}}, nil
}

func snapshotServiceExtensionEntries(registry *ExtensionRegistry) []extensionEntry {
	if registry == nil {
		return nil
	}
	result := make([]extensionEntry, len(registry.entries))
	for index, entry := range registry.entries {
		result[index] = extensionEntry{descriptor: credentialprotocol.CloneExtensionDescriptor(entry.descriptor), factory: entry.factory}
	}
	return result
}

func (sink *serviceExecPlanSink) MaxCredentialBytes() int {
	if sink == nil || sink.written {
		return 0
	}
	return len(sink.canonical)
}

func (sink *serviceExecPlanSink) WriteCredential(value []byte) error {
	if sink == nil || sink.written || len(value) == 0 || len(value) > len(sink.canonical) {
		return ErrContractInvalidArgument
	}
	copy(sink.canonical[:], value)
	sink.length = uint32(len(value))
	sink.written = true
	return nil
}

func (sink *serviceExecPlanSink) destroy() {
	if sink == nil {
		return
	}
	clear(sink.canonical[:])
	sink.length = 0
	sink.written = false
}

func newServiceExecCapabilities(correlation requestCorrelation, generations CoreGenerations, bootNonce [32]byte) (serviceExecCapabilities, error) {
	if !validCompleteCoreGenerations(generations) {
		return serviceExecCapabilities{}, ErrContractInvalidArgument
	}
	executionSHA256, executionErr := newServiceCoreCapabilityDigest(serviceCoreCapabilityExecution, correlation, generations, bootNonce)
	if executionErr != nil {
		return serviceExecCapabilities{}, executionErr
	}
	cleanupSHA256, cleanupErr := newServiceCoreCapabilityDigest(serviceCoreCapabilityCleanup, correlation, generations, bootNonce)
	if cleanupErr != nil {
		return serviceExecCapabilities{}, cleanupErr
	}
	return serviceExecCapabilities{execution: CoreExecutionCapability{digest: executionSHA256}, cleanup: CoreCleanupCapability{digest: cleanupSHA256}}, nil
}

func newServiceExecBodyIdentity(packet ReceivedPacket, arm ReceivedExec, plan ExecPlanCapability) (uint32, [32]byte, error) {
	sink := &serviceExecPlanSink{}
	defer sink.destroy()
	if copyErr := plan.CopyCanonicalTo(sink); copyErr != nil || !sink.written || sink.length != plan.EncodedLength() || sha256.Sum256(sink.canonical[:sink.length]) != plan.SHA256() {
		return 0, [32]byte{}, ErrContractCorrelation
	}
	decodedPlan, decodeErr := credentialprotocol.DecodeHelperExecPlan(sink.canonical[:sink.length])
	if decodeErr != nil {
		return 0, [32]byte{}, ErrContractCorrelation
	}
	body := credentialprotocol.HelperExecBody{Revision: arm.Revision(), ExecBindingID: string(arm.ExecBindingID()), PrivateBindingLength: arm.PrivateBindingLength(), PrivateBindingSHA256: arm.PrivateBindingSHA256(), Plan: decodedPlan}
	canonical, encodeErr := credentialprotocol.EncodeHelperExecBody(body)
	if encodeErr != nil {
		return 0, [32]byte{}, ErrContractCorrelation
	}
	defer wipeBytes(canonical[:cap(canonical)])
	if len(canonical) == 0 || uint32(len(canonical)) != packet.Header().BodyLength {
		return 0, [32]byte{}, ErrContractCorrelation
	}
	return uint32(len(canonical)), sha256.Sum256(canonical), nil
}

func closeServiceExecAuthority(authority serviceExecAuthority) (cleanupErr error) {
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	defer authority.plan.destroy()
	if authority.transaction != nil {
		authority.transaction.Close()
	}
	return nil
}

func (s *Service) newServiceExecAuthority(packet ReceivedPacket, arm ReceivedExec) (authority serviceExecAuthority, authorityErr error) {
	plan := arm.Plan()
	transferred := false
	defer func() {
		if recover() != nil {
			authority = serviceExecAuthority{}
			authorityErr = ErrContractOwnership
		}
		if !transferred {
			arm.transactionSeed.Close()
			plan.destroy()
		}
	}()
	header := packet.Header()
	s.state.mu.Lock()
	activation := s.state.prepared
	s.state.mu.Unlock()
	correlation := requestCorrelation{requestID: header.RequestID, identityDigest: header.GuestCredentialIdentityDigest, revision: arm.Revision()}
	if header.Type != credentialprotocol.PacketTypeExec || !activation.active || !validRequestCorrelation(correlation) || !validCompleteCoreGenerations(activation.generations) || !validSafeID(arm.ExecBindingID()) || arm.Revision() != activation.revision || header.GuestCredentialIdentityDigest != activation.issuingCorrelation.identityDigest || subtle.ConstantTimeCompare(header.BootNonce[:], activation.bootNonce[:]) != 1 {
		return serviceExecAuthority{}, ErrContractCorrelation
	}
	bodyLength, bodySHA256, bodyErr := newServiceExecBodyIdentity(packet, arm, plan)
	if bodyErr != nil {
		return serviceExecAuthority{}, bodyErr
	}
	capabilities, capabilityErr := newServiceExecCapabilities(correlation, activation.generations, activation.bootNonce)
	if capabilityErr != nil {
		return serviceExecAuthority{}, capabilityErr
	}
	request, requestErr := NewCoreExecRequest(header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), activation.generations, coreFixedLimitSetID, arm.ExecBindingID(), arm.PrivateBindingLength(), arm.PrivateBindingSHA256(), bodyLength, bodySHA256, plan, activation.prepared, capabilities.execution, capabilities.cleanup)
	if requestErr != nil {
		return serviceExecAuthority{}, requestErr
	}
	transactionCorrelation, correlationErr := credentialprotocol.NewHelperExecTransactionCorrelation(header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision())
	if correlationErr != nil {
		return serviceExecAuthority{}, correlationErr
	}
	transaction, transactionErr := arm.transactionSeed.Begin()
	if transactionErr != nil {
		return serviceExecAuthority{}, transactionErr
	}
	transferred = true
	return serviceExecAuthority{request: request, plan: plan, revision: arm.Revision(), transaction: transaction, correlation: transactionCorrelation, comparison: false}, nil
}

func (s *Service) installExecDispatch(authority serviceExecAuthority) error {
	if authority.transaction == nil || authority.comparison || authority.revision == 0 {
		return ErrContractInvalidArgument
	}
	s.state.mu.Lock()
	if !s.state.prepared.active || s.state.prepared.revision != authority.revision || s.state.revision != 0 || s.state.transaction != nil || s.state.dispatchTaken {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.request = authority.request
	s.state.plan = authority.plan
	s.state.revision = authority.revision
	s.state.transaction = authority.transaction
	s.state.correlation = authority.correlation
	s.state.comparison = authority.comparison
	s.state.dispatchTaken = false
	s.state.mu.Unlock()
	return nil
}

func newServiceCoreCapabilityDigest(kind serviceCoreCapabilityKind, correlation requestCorrelation, generations CoreGenerations, bootNonce [32]byte) ([32]byte, error) {
	if kind < serviceCoreCapabilityPreparation || kind > serviceCoreCapabilityCleanup || !validRequestCorrelation(correlation) || (!validPartialCoreGenerations(generations) && !validCompleteCoreGenerations(generations)) || bootNonce == ([32]byte{}) {
		return [32]byte{}, ErrContractInvalidArgument
	}
	hasher := sha256.New()
	writeExtensionOpaque16(hasher, "hal/l8/guest-helper/core-capability/v1")
	_, _ = hasher.Write([]byte{byte(kind)})
	_, _ = hasher.Write(correlation.requestID[:])
	_, _ = hasher.Write(correlation.identityDigest[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], correlation.revision)
	_, _ = hasher.Write(scalar[:])
	for _, generation := range [...]credentialprotocol.SafeID{generations.boot, generations.helper, generations.job, generations.monitor, generations.mount, generations.cgroup} {
		writeExtensionOpaque16(hasher, string(generation))
	}
	_, _ = hasher.Write(bootNonce[:])
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func newServicePrepareCapabilities(correlation requestCorrelation, generations CoreGenerations, bootNonce [32]byte) (servicePrepareCapabilities, error) {
	if !validPartialCoreGenerations(generations) {
		return servicePrepareCapabilities{}, ErrContractInvalidArgument
	}
	preparationSHA256, err := newServiceCoreCapabilityDigest(serviceCoreCapabilityPreparation, correlation, generations, bootNonce)
	if err != nil {
		return servicePrepareCapabilities{}, err
	}
	preparedSHA256, err := newServiceCoreCapabilityDigest(serviceCoreCapabilityPrepared, correlation, generations, bootNonce)
	if err != nil {
		return servicePrepareCapabilities{}, err
	}
	cleanupSHA256, err := newServiceCoreCapabilityDigest(serviceCoreCapabilityCleanup, correlation, generations, bootNonce)
	if err != nil {
		return servicePrepareCapabilities{}, err
	}
	return servicePrepareCapabilities{
		preparation: CorePreparationCapability{digest: preparationSHA256},
		prepared:    CorePreparedCapability{digest: preparedSHA256},
		cleanup:     CoreCleanupCapability{digest: cleanupSHA256},
	}, nil
}

func newServicePrepareAuthority(packet ReceivedPacket, arm ReceivedPrepareBegin, bootstrap ServiceBootstrap, observation ServiceJobObservation) (servicePrepareAuthority, error) {
	header := packet.Header()
	completeGenerations := observation.Generations()
	generations, generationsErr := NewCoreGenerations(completeGenerations.boot, completeGenerations.helper, completeGenerations.job, "", "", "")
	if generationsErr != nil {
		return servicePrepareAuthority{}, generationsErr
	}
	correlation := requestCorrelation{requestID: header.RequestID, identityDigest: header.GuestCredentialIdentityDigest, revision: arm.Revision()}
	manifestSHA256 := arm.Manifest().SHA256()
	bootstrapBootNonce := bootstrap.BootNonce()
	if header.Type != credentialprotocol.PacketTypePrepareBegin || arm.transaction == nil || !validRequestCorrelation(correlation) || !validCompleteCoreGenerations(completeGenerations) || !validPartialCoreGenerations(generations) || generations.boot != bootstrap.BootGeneration() || generations.helper != bootstrap.HelperGeneration() || arm.ExpiryUnixNano() <= observation.ObservedUnixNano() || arm.ExpiryUnixNano() > observation.HardExpiryUnixNano() || subtle.ConstantTimeCompare(header.BootNonce[:], bootstrapBootNonce[:]) != 1 || manifestSHA256 == ([32]byte{}) {
		return servicePrepareAuthority{}, ErrContractCorrelation
	}
	capabilities, capabilityErr := newServicePrepareCapabilities(correlation, generations, header.BootNonce)
	if capabilityErr != nil {
		return servicePrepareAuthority{}, capabilityErr
	}
	transactionCorrelation, transactionCorrelationErr := credentialprotocol.NewHelperPrepareTransactionCorrelation(header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), arm.ExpiryUnixNano())
	if transactionCorrelationErr != nil {
		return servicePrepareAuthority{}, transactionCorrelationErr
	}
	prepare, prepareErr := NewCorePrepareRequest(header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), generations, arm.ExpiryUnixNano(), coreFixedLimitSetID, arm.Manifest(), manifestSHA256, capabilities.preparation, capabilities.prepared, capabilities.cleanup)
	if prepareErr != nil {
		return servicePrepareAuthority{}, prepareErr
	}
	return servicePrepareAuthority{header: header, bootstrap: bootstrap, observation: observation, correlation: transactionCorrelation, prepare: prepare, transaction: arm.transaction}, nil
}

func (s *Service) reservePreparing(authority servicePrepareAuthority) error {
	if authority.transaction == nil {
		return ErrContractDependency
	}
	s.state.mu.Lock()
	if s.state.preparing.beginTaken || s.state.preparing.active || s.state.prepared.active {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.preparing = servicePreparing{authority: authority, beginTaken: true}
	s.state.mu.Unlock()
	return nil
}

func (s *Service) installPreparing(transaction *credentialprotocol.HelperPrepareTransaction, preparation CorePreparation) error {
	if transaction == nil || !configuredDependency(preparation) {
		return ErrContractDependency
	}
	s.state.mu.Lock()
	if !s.state.preparing.beginTaken || s.state.preparing.active || s.state.preparing.authority.transaction != transaction {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.preparing.preparation = preparation
	s.state.preparing.beginTaken = false
	s.state.preparing.active = true
	s.state.mu.Unlock()
	return nil
}

func closeServicePrepareTransaction(transaction *credentialprotocol.HelperPrepareTransaction) (cleanupErr error) {
	if transaction == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	transaction.Close()
	return nil
}

func rollbackServicePreparation(ctx context.Context, preparation CorePreparation, cleanup CoreCleanupCapability) (cleanupErr error) {
	if !configuredDependency(preparation) {
		return nil
	}
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	for attempt := 0; attempt < 3; attempt++ {
		result, rollbackErr := preparation.Rollback(ctx)
		resultCleanup := result.Cleanup()
		if rollbackErr != nil || subtle.ConstantTimeCompare(resultCleanup.digest[:], cleanup.digest[:]) != 1 {
			return ErrContractOwnership
		}
		switch result.Category() {
		case CoreCleanupComplete:
			if !result.AuthorityAbsent() || !result.ResourcesAbsent() {
				return ErrContractOwnership
			}
			return nil
		case CoreCleanupRetryRequired:
			if !result.AuthorityAbsent() || result.ResourcesAbsent() {
				return ErrContractOwnership
			}
		case CoreCleanupStopVMRequired:
			if result.AuthorityAbsent() && result.ResourcesAbsent() {
				return ErrContractOwnership
			}
			return ErrContractOwnership
		default:
			return ErrContractOwnership
		}
	}
	return ErrContractOwnership
}

func (s *Service) abortPreparing(ctx context.Context, transaction *credentialprotocol.HelperPrepareTransaction, provisional CorePreparation) error {
	if transaction == nil {
		return ErrContractInvalidArgument
	}
	s.state.mu.Lock()
	preparing := s.state.preparing
	if preparing.authority.transaction != transaction || !preparing.beginTaken && !preparing.active {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.preparing = servicePreparing{}
	s.state.mu.Unlock()
	preparation := preparing.preparation
	if configuredDependency(provisional) {
		preparation = provisional
	}
	transactionErr := closeServicePrepareTransaction(transaction)
	rollbackErr := rollbackServicePreparation(ctx, preparation, preparing.authority.prepare.Cleanup())
	if transactionErr != nil || rollbackErr != nil {
		return ErrContractOwnership
	}
	return nil
}

func (s *Service) takePreparing(packet ReceivedPacket) (servicePreparing, error) {
	header := packet.Header()
	s.state.mu.Lock()
	preparing := s.state.preparing
	if !preparing.active || preparing.fileTaken || preparing.commitTaken || header.Type != credentialprotocol.PacketTypePrepareCommit || header.RequestID != preparing.authority.header.RequestID || subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], preparing.authority.header.GuestCredentialIdentityDigest[:]) != 1 || subtle.ConstantTimeCompare(header.BootNonce[:], preparing.authority.header.BootNonce[:]) != 1 {
		s.state.mu.Unlock()
		return servicePreparing{}, ErrContractCorrelation
	}
	s.state.preparing.commitTaken = true
	preparing.commitTaken = true
	s.state.mu.Unlock()
	return preparing, nil
}

func (s *Service) takePreparingFile(packet ReceivedPacket, arm ReceivedPrepareFile) (servicePreparing, error) {
	header := packet.Header()
	s.state.mu.Lock()
	preparing := s.state.preparing
	if !preparing.active || preparing.fileTaken || preparing.commitTaken || header.Type != credentialprotocol.PacketTypePrepareFile || header.RequestID != preparing.authority.header.RequestID || subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], preparing.authority.header.GuestCredentialIdentityDigest[:]) != 1 || subtle.ConstantTimeCompare(header.BootNonce[:], preparing.authority.header.BootNonce[:]) != 1 || arm.Revision() != preparing.authority.prepare.Revision() {
		s.state.mu.Unlock()
		return servicePreparing{}, ErrContractCorrelation
	}
	s.state.preparing.fileTaken = true
	preparing.fileTaken = true
	s.state.mu.Unlock()
	return preparing, nil
}

func (s *Service) finishPreparingFile(transaction *credentialprotocol.HelperPrepareTransaction) error {
	if transaction == nil {
		return ErrContractInvalidArgument
	}
	s.state.mu.Lock()
	if !s.state.preparing.active || !s.state.preparing.fileTaken || s.state.preparing.commitTaken || s.state.preparing.authority.transaction != transaction {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.preparing.fileTaken = false
	s.state.mu.Unlock()
	return nil
}

func newServiceFileRequest(packet ReceivedPacket, arm ReceivedPrepareFile, preparing servicePreparing) (CoreFileRequest, error) {
	header := packet.Header()
	prepare := preparing.authority.prepare
	transactionSnapshot := preparing.authority.transaction.Snapshot()
	bindingID, mode, target, fileLength, fileSHA256, ok := prepare.Manifest().Binding(arm.BindingIndex())
	armFileSHA256 := arm.FileSHA256()
	prepareIdentityDigest := prepare.IdentityDigest()
	if !preparing.active || !preparing.fileTaken || preparing.commitTaken || transactionSnapshot.Terminal || transactionSnapshot.Committed || transactionSnapshot.PendingFile || !transactionSnapshot.HasNextFile || transactionSnapshot.NextBindingIndex != arm.BindingIndex() || header.Type != credentialprotocol.PacketTypePrepareFile || header.RequestID != prepare.RequestID() || subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], prepareIdentityDigest[:]) != 1 || arm.Revision() != prepare.Revision() || !ok || mode != credentialprotocol.DeliveryModeFileTmpfs || arm.FileLength() != fileLength || subtle.ConstantTimeCompare(armFileSHA256[:], fileSHA256[:]) != 1 {
		return CoreFileRequest{}, ErrContractCorrelation
	}
	request, requestErr := NewCoreFileRequest(header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), prepare.Generations().job, prepare.Preparation(), bindingID, arm.BindingIndex(), target, fileLength, fileSHA256)
	if requestErr != nil {
		return CoreFileRequest{}, requestErr
	}
	return request, nil
}

func newServiceCommitRequest(packet ReceivedPacket, arm ReceivedPrepareCommit, authority servicePrepareAuthority) (CoreCommitRequest, error) {
	header := packet.Header()
	prepareManifestSHA256 := authority.prepare.ManifestSHA256()
	prepareIdentityDigest := authority.prepare.IdentityDigest()
	armManifestSHA256 := arm.ManifestSHA256()
	if header.Type != credentialprotocol.PacketTypePrepareCommit || header.RequestID != authority.prepare.RequestID() || subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], prepareIdentityDigest[:]) != 1 || arm.Revision() != authority.prepare.Revision() || subtle.ConstantTimeCompare(armManifestSHA256[:], prepareManifestSHA256[:]) != 1 {
		return CoreCommitRequest{}, ErrContractCorrelation
	}
	transactionResult, transactionErr := authority.transaction.Commit(authority.correlation, credentialprotocol.HelperPrepareCommitBody{Revision: arm.Revision(), ManifestSHA256: arm.ManifestSHA256()})
	if transactionErr != nil {
		return CoreCommitRequest{}, transactionErr
	}
	commit, commitErr := NewCoreCommitRequest(header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), authority.observation.Generations().job, authority.prepare.Preparation(), transactionResult.ManifestSHA256(), transactionResult.TransactionSHA256(), authority.prepare.Prepared())
	if commitErr != nil {
		return CoreCommitRequest{}, commitErr
	}
	return commit, nil
}

func newServiceActiveProofID(correlation requestCorrelation, generations CoreGenerations, bootNonce [32]byte, expiresUnixNano int64, manifestSHA256, transactionSHA256 [32]byte) (credentialprotocol.SafeID, error) {
	if !validRequestCorrelation(correlation) || !validCompleteCoreGenerations(generations) || bootNonce == ([32]byte{}) || expiresUnixNano <= 0 || manifestSHA256 == ([32]byte{}) || transactionSHA256 == ([32]byte{}) {
		return "", ErrContractInvalidArgument
	}
	hasher := sha256.New()
	writeExtensionOpaque16(hasher, "hal/l8/guest-helper/active-proof-label/v1")
	_, _ = hasher.Write(bootNonce[:])
	_, _ = hasher.Write(correlation.identityDigest[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], correlation.revision)
	_, _ = hasher.Write(scalar[:])
	for _, generation := range [...]credentialprotocol.SafeID{generations.boot, generations.helper, generations.job, generations.monitor, generations.mount, generations.cgroup} {
		writeExtensionOpaque16(hasher, string(generation))
	}
	binary.BigEndian.PutUint64(scalar[:], uint64(expiresUnixNano))
	_, _ = hasher.Write(scalar[:])
	_, _ = hasher.Write(manifestSHA256[:])
	_, _ = hasher.Write(transactionSHA256[:])
	return credentialprotocol.SafeID("active." + base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))), nil
}

func newServicePreparedActivationCandidate(preparing servicePreparing, header credentialprotocol.HelperPacketHeader, observation ServiceJobObservation, commit CoreCommitRequest, result CorePreparedResult) (servicePreparedActivationCandidate, error) {
	prepare := preparing.authority.prepare
	bootstrap := preparing.authority.bootstrap
	prepareCorrelation := requestCorrelation{requestID: prepare.RequestID(), identityDigest: prepare.IdentityDigest(), revision: prepare.Revision()}
	prepareCapabilities, capabilityErr := newServicePrepareCapabilities(prepareCorrelation, prepare.Generations(), header.BootNonce)
	if capabilityErr != nil {
		return servicePreparedActivationCandidate{}, capabilityErr
	}
	initialObservation := preparing.authority.observation
	initialGenerations := initialObservation.Generations()
	generations := observation.Generations()
	resultManifestSHA256 := result.ManifestSHA256()
	resultTransactionSHA256 := result.TransactionSHA256()
	resultPrepared := result.Prepared()
	prepareManifestSHA256 := prepare.ManifestSHA256()
	commitManifestSHA256 := commit.ManifestSHA256()
	commitTransactionSHA256 := commit.TransactionSHA256()
	preparePrepared := prepare.Prepared()
	preparePreparation := prepare.Preparation()
	prepareCleanup := prepare.Cleanup()
	commitPrepared := commit.Prepared()
	prepareIdentityDigest := prepare.IdentityDigest()
	commitIdentityDigest := commit.IdentityDigest()
	bootstrapBootNonce := bootstrap.BootNonce()
	correlation := requestCorrelation{requestID: header.RequestID, identityDigest: header.GuestCredentialIdentityDigest, revision: prepare.Revision()}
	valid := preparing.active && preparing.commitTaken && configuredDependency(preparing.preparation) && header.Type == credentialprotocol.PacketTypePrepareCommit && validRequestCorrelation(correlation) && header.RequestID == prepare.RequestID() && header.RequestID == commit.RequestID() && subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], prepareIdentityDigest[:]) == 1 && subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], commitIdentityDigest[:]) == 1 && prepare.Revision() == commit.Revision() && subtle.ConstantTimeCompare(header.BootNonce[:], bootstrapBootNonce[:]) == 1 && subtle.ConstantTimeCompare(preparePreparation.digest[:], prepareCapabilities.preparation.digest[:]) == 1 && subtle.ConstantTimeCompare(preparePrepared.digest[:], prepareCapabilities.prepared.digest[:]) == 1 && subtle.ConstantTimeCompare(prepareCleanup.digest[:], prepareCapabilities.cleanup.digest[:]) == 1 && generations.boot == bootstrap.BootGeneration() && generations.helper == bootstrap.HelperGeneration() && generations == initialGenerations && observation.HardExpiryUnixNano() == initialObservation.HardExpiryUnixNano() && observation.ObservedUnixNano() > initialObservation.ObservedUnixNano() && validCompleteCoreGenerations(generations) && result.Generations() == generations && result.ExpiresUnixNano() == prepare.ExpiresUnixNano() && result.ExpiresUnixNano() > observation.ObservedUnixNano() && result.ExpiresUnixNano() <= observation.HardExpiryUnixNano() && result.BindingCount() == prepare.Manifest().Count() && subtle.ConstantTimeCompare(resultManifestSHA256[:], prepareManifestSHA256[:]) == 1 && subtle.ConstantTimeCompare(resultManifestSHA256[:], commitManifestSHA256[:]) == 1 && subtle.ConstantTimeCompare(resultTransactionSHA256[:], commitTransactionSHA256[:]) == 1 && subtle.ConstantTimeCompare(resultPrepared.digest[:], preparePrepared.digest[:]) == 1 && subtle.ConstantTimeCompare(resultPrepared.digest[:], commitPrepared.digest[:]) == 1
	if !valid {
		return servicePreparedActivationCandidate{}, ErrContractCorrelation
	}
	activeProofID, proofErr := newServiceActiveProofID(correlation, generations, header.BootNonce, result.ExpiresUnixNano(), resultManifestSHA256, resultTransactionSHA256)
	if proofErr != nil {
		return servicePreparedActivationCandidate{}, proofErr
	}
	return servicePreparedActivationCandidate{
		issuingCorrelation: correlation,
		bootNonce:          header.BootNonce,
		generations:        generations,
		observedUnixNano:   observation.ObservedUnixNano(),
		hardExpiryUnixNano: observation.HardExpiryUnixNano(),
		expiresUnixNano:    result.ExpiresUnixNano(),
		manifest:           prepare.Manifest(),
		bindingCount:       result.BindingCount(),
		manifestSHA256:     resultManifestSHA256,
		transactionSHA256:  resultTransactionSHA256,
		prepared:           resultPrepared,
		cleanup:            prepareCleanup,
		activeProofID:      activeProofID,
	}, nil
}

func (s *Service) installPreparedActivation(preparing servicePreparing, header credentialprotocol.HelperPacketHeader, observation ServiceJobObservation, commit CoreCommitRequest, result CorePreparedResult) error {
	candidate, candidateErr := newServicePreparedActivationCandidate(preparing, header, observation, commit, result)
	if candidateErr != nil {
		return candidateErr
	}
	s.state.mu.Lock()
	if s.state.prepared.active || !s.state.preparing.active || !s.state.preparing.commitTaken {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.prepared = servicePreparedActivation{
		issuingCorrelation: candidate.issuingCorrelation,
		revision:           candidate.issuingCorrelation.revision,
		bootNonce:          candidate.bootNonce,
		generations:        candidate.generations,
		observedUnixNano:   candidate.observedUnixNano,
		hardExpiryUnixNano: candidate.hardExpiryUnixNano,
		expiresUnixNano:    candidate.expiresUnixNano,
		manifest:           candidate.manifest,
		bindingCount:       candidate.bindingCount,
		manifestSHA256:     candidate.manifestSHA256,
		transactionSHA256:  candidate.transactionSHA256,
		prepared:           candidate.prepared,
		cleanup:            candidate.cleanup,
		activeProofID:      candidate.activeProofID,
		active:             true,
	}
	s.state.preparing = servicePreparing{}
	s.state.mu.Unlock()
	return nil
}

func (s *Service) revokeCommittedPreparation(ctx context.Context, preparing servicePreparing, observation ServiceJobObservation) (cleanupErr error) {
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	prepare := preparing.authority.prepare
	prepared := prepare.Prepared()
	cleanup := prepare.Cleanup()
	prepareIdentityDigest := prepare.IdentityDigest()
	s.state.mu.Lock()
	currentPreparing := s.state.preparing
	currentPrepared := s.state.prepared
	preparingOwned := currentPreparing.authority.transaction == preparing.authority.transaction && currentPreparing.commitTaken
	preparedOwned := currentPrepared.active && currentPrepared.issuingCorrelation.revision == prepare.Revision() && subtle.ConstantTimeCompare(currentPrepared.issuingCorrelation.identityDigest[:], prepareIdentityDigest[:]) == 1 && subtle.ConstantTimeCompare(currentPrepared.prepared.digest[:], prepared.digest[:]) == 1 && subtle.ConstantTimeCompare(currentPrepared.cleanup.digest[:], cleanup.digest[:]) == 1
	if !preparingOwned && !preparedOwned {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.preparing = servicePreparing{}
	s.state.prepared = servicePreparedActivation{}
	s.state.mu.Unlock()
	transactionErr := closeServicePrepareTransaction(preparing.authority.transaction)
	request, requestErr := NewCoreRevokeRequest(prepare.RequestID(), prepare.IdentityDigest(), prepare.Revision(), observation.Generations(), credentialprotocol.RevokeReasonSessionLoss, prepared, cleanup)
	if requestErr != nil {
		return ErrContractOwnership
	}
	result, revokeErr := s.core.Revoke(ctx, request)
	resultCleanup := result.Cleanup()
	if revokeErr != nil || subtle.ConstantTimeCompare(resultCleanup.digest[:], cleanup.digest[:]) != 1 {
		return ErrContractOwnership
	}
	switch result.Category() {
	case CoreCleanupComplete:
		if !result.AuthorityAbsent() || !result.ResourcesAbsent() {
			return ErrContractOwnership
		}
		if transactionErr != nil {
			return ErrContractOwnership
		}
		return nil
	case CoreCleanupRetryRequired:
		if !result.AuthorityAbsent() || result.ResourcesAbsent() {
			return ErrContractOwnership
		}
		return ErrContractOwnership
	case CoreCleanupStopVMRequired:
		if result.AuthorityAbsent() && result.ResourcesAbsent() {
			return ErrContractOwnership
		}
		return ErrContractOwnership
	default:
		return ErrContractOwnership
	}
}

func (s *Service) revokeServicePreparedActivation(ctx context.Context, expected servicePreparedActivation) (cleanupErr error) {
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	s.state.mu.Lock()
	current := s.state.prepared
	expectedPrepared := expected.prepared
	expectedCleanup := expected.cleanup
	validRevision := current.revision == expected.revision || expected.revision != ^uint64(0) && current.revision == expected.revision+1
	valid := current.active && expected.active && current.issuingCorrelation == expected.issuingCorrelation && validRevision && current.bootNonce == expected.bootNonce && current.generations == expected.generations && current.hardExpiryUnixNano == expected.hardExpiryUnixNano && current.manifest == expected.manifest && current.bindingCount == expected.bindingCount && current.manifestSHA256 == expected.manifestSHA256 && current.transactionSHA256 == expected.transactionSHA256 && subtle.ConstantTimeCompare(current.prepared.digest[:], expectedPrepared.digest[:]) == 1 && subtle.ConstantTimeCompare(current.cleanup.digest[:], expectedCleanup.digest[:]) == 1
	if !valid {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.prepared = servicePreparedActivation{}
	s.state.mu.Unlock()
	request, requestErr := NewCoreRevokeRequest(current.issuingCorrelation.requestID, current.issuingCorrelation.identityDigest, current.revision, current.generations, credentialprotocol.RevokeReasonSessionLoss, current.prepared, current.cleanup)
	if requestErr != nil {
		return ErrContractOwnership
	}
	result, revokeErr := s.core.Revoke(ctx, request)
	resultCleanup := result.Cleanup()
	if revokeErr != nil || subtle.ConstantTimeCompare(resultCleanup.digest[:], current.cleanup.digest[:]) != 1 {
		return ErrContractOwnership
	}
	switch result.Category() {
	case CoreCleanupComplete:
		if !result.AuthorityAbsent() || !result.ResourcesAbsent() {
			return ErrContractOwnership
		}
		return nil
	case CoreCleanupRetryRequired:
		if !result.AuthorityAbsent() || result.ResourcesAbsent() {
			return ErrContractOwnership
		}
		return ErrContractOwnership
	case CoreCleanupStopVMRequired:
		if result.AuthorityAbsent() && result.ResourcesAbsent() {
			return ErrContractOwnership
		}
		return ErrContractOwnership
	default:
		return ErrContractOwnership
	}
}

func validateServiceRenewArm(packet ReceivedPacket, arm ReceivedRenew, activation servicePreparedActivation) error {
	header := packet.Header()
	correlation := requestCorrelation{requestID: header.RequestID, identityDigest: header.GuestCredentialIdentityDigest, revision: arm.revision}
	expectedPriorProofSHA256 := hashOpaqueToken(renewProofDomain, activation.activeProofID)
	valid := header.Type == credentialprotocol.PacketTypeRenew && validRequestCorrelation(correlation) && activation.active && activation.revision != ^uint64(0) && arm.revision == activation.revision+1 && arm.expiryUnixNano > activation.expiresUnixNano && subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], activation.issuingCorrelation.identityDigest[:]) == 1 && subtle.ConstantTimeCompare(header.BootNonce[:], activation.bootNonce[:]) == 1 && subtle.ConstantTimeCompare(arm.priorProofSHA256[:], expectedPriorProofSHA256[:]) == 1
	if !valid {
		return ErrContractCorrelation
	}
	return nil
}

func (s *Service) newServiceRenewRequest(packet ReceivedPacket, arm ReceivedRenew, observation ServiceJobObservation) (CoreRenewRequest, serviceRenewAuthority, error) {
	header := packet.Header()
	s.state.mu.Lock()
	activation := s.state.prepared
	s.state.mu.Unlock()
	if validationErr := validateServiceRenewArm(packet, arm, activation); validationErr != nil {
		return CoreRenewRequest{}, serviceRenewAuthority{}, validationErr
	}
	valid := arm.expiryUnixNano > observation.ObservedUnixNano() && arm.expiryUnixNano <= observation.HardExpiryUnixNano() && observation.ObservedUnixNano() > activation.observedUnixNano && observation.HardExpiryUnixNano() == activation.hardExpiryUnixNano && observation.Generations() == activation.generations
	if !valid {
		return CoreRenewRequest{}, serviceRenewAuthority{}, ErrContractCorrelation
	}
	request, err := NewCoreRenewRequest(header.RequestID, header.GuestCredentialIdentityDigest, arm.revision, activation.generations, arm.expiryUnixNano, activation.prepared)
	if err != nil {
		return CoreRenewRequest{}, serviceRenewAuthority{}, err
	}
	return request, serviceRenewAuthority{activation: activation}, nil
}

func (s *Service) advancePreparedActivation(ctx context.Context, packet ReceivedPacket, observation ServiceJobObservation) (renewErr error) {
	defer func() {
		if recover() != nil {
			renewErr = ErrContractOwnership
		}
	}()
	arm, ok := packet.Renew()
	if !ok {
		return ErrContractInvalidArgument
	}
	request, authority, requestErr := s.newServiceRenewRequest(packet, arm, observation)
	if requestErr != nil {
		return requestErr
	}
	if coreErr := s.core.Renew(ctx, request); coreErr != nil {
		return coreErr
	}
	activation := authority.activation
	correlation := requestCorrelation{requestID: request.RequestID(), identityDigest: request.IdentityDigest(), revision: request.Revision()}
	replacementActiveProofID, proofErr := newServiceActiveProofID(correlation, request.Generations(), activation.bootNonce, request.ExpiresUnixNano(), activation.manifestSHA256, activation.transactionSHA256)
	if proofErr != nil {
		return proofErr
	}
	s.state.mu.Lock()
	if s.state.prepared != activation {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.prepared.revision = request.Revision()
	s.state.prepared.observedUnixNano = observation.ObservedUnixNano()
	s.state.prepared.expiresUnixNano = request.ExpiresUnixNano()
	s.state.prepared.activeProofID = replacementActiveProofID
	s.state.mu.Unlock()
	return nil
}

func (s *Service) newServiceReceiveRequest() (ReceiveRequest, error) {
	s.state.mu.Lock()
	sequence := s.state.nextReceiveSequence
	if sequence > math.MaxUint32 {
		s.state.mu.Unlock()
		return ReceiveRequest{}, ErrContractTransition
	}
	request, requestErr := NewReceiveRequest(sequence, credentialprotocol.MaxHelperPacketBodyBytes, 0)
	if requestErr != nil {
		s.state.mu.Unlock()
		return ReceiveRequest{}, requestErr
	}
	s.state.nextReceiveSequence++
	s.state.mu.Unlock()
	return request, nil
}

func destroyServiceReceivedPacket(ctx context.Context, packet ReceivedPacket) (cleanupErr error) {
	invoke := func(callback func() error) (callbackErr error) {
		defer func() {
			if recover() != nil {
				callbackErr = ErrContractOwnership
			}
		}()
		return callback()
	}
	if packet.body != nil {
		if !configuredDependency(packet.body) {
			cleanupErr = ErrContractOwnership
		} else if bodyErr := invoke(func() error { return packet.body.Destroy(ctx) }); bodyErr != nil {
			cleanupErr = ErrContractOwnership
		}
	}
	if packet.right != nil {
		if !configuredDependency(packet.right) {
			cleanupErr = ErrContractOwnership
		} else if rightErr := invoke(func() error { return packet.right.Close(ctx) }); rightErr != nil {
			cleanupErr = ErrContractOwnership
		}
	}
	return cleanupErr
}

func (s *Service) handlePrepareBegin(ctx context.Context, packet ReceivedPacket) (handlerErr error) {
	var transaction *credentialprotocol.HelperPrepareTransaction
	var preparation CorePreparation
	stateOwned := false
	defer func() {
		recovered := recover()
		packetCleanupErr := destroyServiceReceivedPacket(ctx, packet)
		if recovered != nil || packetCleanupErr != nil {
			handlerErr = ErrContractOwnership
		}
		if handlerErr != nil && stateOwned {
			if abortErr := s.abortPreparing(ctx, transaction, preparation); abortErr != nil {
				handlerErr = ErrContractOwnership
			}
		} else if handlerErr != nil && transaction != nil {
			if closeErr := closeServicePrepareTransaction(transaction); closeErr != nil {
				handlerErr = ErrContractOwnership
			}
		}
	}()
	arm, ok := packet.PrepareBegin()
	if !ok {
		return ErrContractInvalidArgument
	}
	transaction = arm.transaction
	if transaction == nil {
		return ErrContractDependency
	}
	header := packet.Header()
	bootstrap, bootstrapErr := s.runtime.Bootstrap(ctx)
	if bootstrapErr != nil {
		return bootstrapErr
	}
	observationRequest, observationRequestErr := newServiceJobObservationRequest(ServiceOperationPrepare, header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), bootstrap.BootGeneration(), bootstrap.HelperGeneration())
	if observationRequestErr != nil {
		return observationRequestErr
	}
	observation, observationErr := s.runtime.ObserveJob(ctx, observationRequest)
	if observationErr != nil {
		return observationErr
	}
	authority, authorityErr := newServicePrepareAuthority(packet, arm, bootstrap, observation)
	if authorityErr != nil {
		return authorityErr
	}
	reserveErr := s.reservePreparing(authority)
	if reserveErr != nil {
		return reserveErr
	}
	stateOwned = true
	preparation, beginErr := s.core.BeginPrepare(ctx, authority.prepare)
	if beginErr != nil || !configuredDependency(preparation) {
		return ErrContractDependency
	}
	installErr := s.installPreparing(transaction, preparation)
	if installErr != nil {
		return installErr
	}
	return nil
}

func (s *Service) handlePrepareFile(ctx context.Context, packet ReceivedPacket) (handlerErr error) {
	body := packet.body
	var preparing servicePreparing
	taken := false
	defer func() {
		recovered := recover()
		cleanupErr := destroyServiceReceivedPacket(ctx, packet)
		if recovered != nil || cleanupErr != nil {
			handlerErr = ErrContractOwnership
		}
		if handlerErr == nil && taken {
			handlerErr = s.finishPreparingFile(preparing.authority.transaction)
		}
		if handlerErr != nil && taken {
			if abortErr := s.abortPreparing(ctx, preparing.authority.transaction, nil); abortErr != nil {
				handlerErr = ErrContractOwnership
			}
		}
	}()
	if !configuredDependency(body) {
		return ErrContractDependency
	}
	arm, ok := packet.PrepareFile()
	if !ok {
		return ErrContractInvalidArgument
	}
	preparing, takeErr := s.takePreparingFile(packet, arm)
	if takeErr != nil {
		return takeErr
	}
	taken = true
	fileRequest, fileRequestErr := newServiceFileRequest(packet, arm, preparing)
	if fileRequestErr != nil {
		return fileRequestErr
	}
	observedSHA256 := body.SHA256()
	if body.Len() != arm.FileLength() {
		return ErrContractCorrelation
	}
	observation, observationErr := credentialprotocol.NewHelperPrepareFileObservation(arm.Revision(), arm.BindingIndex(), arm.FileLength(), arm.FileSHA256(), observedSHA256)
	if observationErr != nil {
		return observationErr
	}
	borrowErr := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		if stageErr := preparing.preparation.StageFile(ctx, fileRequest, view); stageErr != nil {
			return stageErr
		}
		return preparing.authority.transaction.AcceptObservedFileObservation(preparing.authority.correlation, observation)
	})
	if borrowErr != nil {
		return borrowErr
	}
	return nil
}

func (s *Service) handlePrepareCommit(ctx context.Context, packet ReceivedPacket) (handlerErr error) {
	var preparing servicePreparing
	taken := false
	committed := false
	postcommitCleaned := false
	var observation ServiceJobObservation
	defer func() {
		recovered := recover()
		cleanupErr := destroyServiceReceivedPacket(ctx, packet)
		if recovered != nil || cleanupErr != nil {
			handlerErr = ErrContractOwnership
		}
		if handlerErr != nil && taken && !committed {
			if abortErr := s.abortPreparing(ctx, preparing.authority.transaction, nil); abortErr != nil {
				handlerErr = ErrContractOwnership
			}
		}
		if handlerErr != nil && committed && !postcommitCleaned {
			if revokeErr := s.revokeCommittedPreparation(ctx, preparing, observation); revokeErr != nil {
				handlerErr = ErrContractOwnership
			}
		}
	}()
	arm, ok := packet.PrepareCommit()
	if !ok {
		return ErrContractInvalidArgument
	}
	header := packet.Header()
	preparing, takeErr := s.takePreparing(packet)
	if takeErr != nil {
		return takeErr
	}
	taken = true
	observationRequest, observationRequestErr := newServiceJobObservationRequest(ServiceOperationPrepare, header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), preparing.authority.bootstrap.BootGeneration(), preparing.authority.bootstrap.HelperGeneration())
	if observationRequestErr != nil {
		return observationRequestErr
	}
	observation, observationErr := s.runtime.ObserveJob(ctx, observationRequest)
	if observationErr != nil {
		return observationErr
	}
	commit, commitRequestErr := newServiceCommitRequest(packet, arm, preparing.authority)
	if commitRequestErr != nil {
		return commitRequestErr
	}
	committed = true
	result, commitErr := preparing.preparation.Commit(ctx, commit)
	if commitErr != nil {
		return commitErr
	}
	installErr := s.installPreparedActivation(preparing, header, observation, commit, result)
	if installErr != nil {
		revokeErr := s.revokeCommittedPreparation(ctx, preparing, observation)
		postcommitCleaned = true
		if revokeErr != nil {
			return ErrContractOwnership
		}
		return installErr
	}
	return nil
}

func (s *Service) handleRenew(ctx context.Context, packet ReceivedPacket) (handlerErr error) {
	var activation servicePreparedActivation
	runtimeCalled := false
	defer func() {
		recovered := recover()
		cleanupErr := destroyServiceReceivedPacket(ctx, packet)
		terminalDependencyFailure := recovered != nil || cleanupErr != nil || runtimeCalled && handlerErr != nil
		if terminalDependencyFailure {
			handlerErr = ErrContractOwnership
		}
		if terminalDependencyFailure && activation.active {
			if revokeErr := s.revokeServicePreparedActivation(ctx, activation); revokeErr != nil {
				handlerErr = ErrContractOwnership
			}
		}
	}()
	arm, ok := packet.Renew()
	if !ok {
		return ErrContractInvalidArgument
	}
	header := packet.Header()
	s.state.mu.Lock()
	activation = s.state.prepared
	s.state.mu.Unlock()
	if validationErr := validateServiceRenewArm(packet, arm, activation); validationErr != nil {
		return validationErr
	}
	observationRequest, observationRequestErr := newServiceJobObservationRequest(ServiceOperationRenew, header.RequestID, header.GuestCredentialIdentityDigest, arm.Revision(), activation.generations.boot, activation.generations.helper)
	if observationRequestErr != nil {
		return observationRequestErr
	}
	runtimeCalled = true
	observation, observationErr := s.runtime.ObserveJob(ctx, observationRequest)
	if observationErr != nil {
		return observationErr
	}
	advanceErr := s.advancePreparedActivation(ctx, packet, observation)
	if advanceErr != nil {
		return advanceErr
	}
	return nil
}

func (s *Service) Serve(ctx context.Context) (ServiceResult, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return ServiceResult{}, contextErr
	}
	s.state.mu.Lock()
	if s.state.serveCalled {
		s.state.mu.Unlock()
		return ServiceResult{}, ErrContractTransition
	}
	s.state.serveCalled = true
	s.state.mu.Unlock()
	for {
		request, requestErr := s.newServiceReceiveRequest()
		if requestErr != nil {
			return ServiceResult{}, requestErr
		}
		packet, receiveErr := s.receiveServicePacket(ctx, request)
		if receiveErr != nil {
			return s.finishServiceReceive(ctx, receiveErr)
		}
		var handlerErr error
		switch packet.Type() {
		case credentialprotocol.PacketTypePrepareBegin:
			handlerErr = s.handlePrepareBegin(ctx, packet)
		case credentialprotocol.PacketTypePrepareFile:
			handlerErr = s.handlePrepareFile(ctx, packet)
		case credentialprotocol.PacketTypePrepareCommit:
			handlerErr = s.handlePrepareCommit(ctx, packet)
		case credentialprotocol.PacketTypeRenew:
			handlerErr = s.handleRenew(ctx, packet)
		case credentialprotocol.PacketTypeExec:
			return s.handleExec(ctx, packet)
		default:
			handlerErr = destroyServiceReceivedPacket(ctx, packet)
		}
		if handlerErr != nil {
			return ServiceResult{}, handlerErr
		}
	}
}

const dispatchPrivate = true

type serviceExecInvalidError string

func (value serviceExecInvalidError) Error() string { return string(value) }

const errInvalid serviceExecInvalidError = "credential helper contract dependency"

type serviceExecOutputDigestSink struct {
	hasher   hash.Hash
	expected int
	written  bool
}

type serviceExecOutputLedger struct {
	request         CoreExecRequest
	stdoutMaximum   uint64
	stderrMaximum   uint64
	stdoutHasher    hash.Hash
	stderrHasher    hash.Hash
	stdoutOffset    uint64
	stderrOffset    uint64
	stdoutEOF       bool
	stderrEOF       bool
	stdoutTruncated bool
	stderrTruncated bool
}

type serviceExecReceiveResult struct {
	packet ReceivedPacket
	err    error
}

type serviceExecWorkResult struct {
	dispatch serviceExecDispatch
	err      error
}

type serviceExecCoordinator struct {
	cancel         context.CancelFunc
	receiveResults chan serviceExecReceiveResult
	stdinResults   chan serviceExecWorkResult
	outputResults  chan serviceExecWorkResult
	receivePending bool
	stdinPending   bool
	outputPending  bool
	creditQueued   bool
	queuedCredit   ReceivedExecCredit
	queuedDispatch serviceExecDispatch
}

func (s *Service) takeExecDispatch(revision uint64) (serviceExecDispatch, error) {
	s.state.mu.Lock()
	if revision != s.state.revision || s.state.dispatchTaken {
		s.state.mu.Unlock()
		return serviceExecDispatch{}, ErrContractTransition
	}
	transaction := s.state.transaction
	correlation := s.state.correlation
	comparison := s.state.comparison
	s.state.dispatchTaken = true
	s.state.mu.Unlock()
	return serviceExecDispatch{transaction: transaction, correlation: correlation, comparison: comparison}, nil
}

func (s *Service) handleExec(ctx context.Context, packet ReceivedPacket) (ServiceResult, error) {
	arm, ok := packet.Exec()
	if !ok {
		packetCleanupErr := destroyServiceReceivedPacket(ctx, packet)
		if packetCleanupErr != nil {
			return ServiceResult{}, ErrContractOwnership
		}
		return ServiceResult{}, ErrContractInvalidArgument
	}
	authority, authorityErr := s.newServiceExecAuthority(packet, arm)
	if authorityErr != nil {
		packetCleanupErr := destroyServiceReceivedPacket(ctx, packet)
		if packetCleanupErr != nil {
			return ServiceResult{}, ErrContractOwnership
		}
		return ServiceResult{}, authorityErr
	}
	installErr := s.installExecDispatch(authority)
	if installErr != nil {
		authorityCleanupErr := closeServiceExecAuthority(authority)
		packetCleanupErr := destroyServiceReceivedPacket(ctx, packet)
		if authorityCleanupErr != nil || packetCleanupErr != nil {
			return ServiceResult{}, ErrContractOwnership
		}
		return ServiceResult{}, installErr
	}
	if arm.PrivateBindingLength() == 0 && arm.PrivateBindingSHA256() == ([32]byte{}) {
		return s.zeroPrivate(ctx, packet, false)
	}
	if cleanupErr := destroyServiceReceivedPacket(ctx, packet); cleanupErr != nil {
		return s.finishExecDispatch(ctx, cleanupErr)
	}
	if dispatchPrivate {
		return s.dispatchPrivate(ctx)
	}
	return s.dispatchStdin(ctx)
}

func (s *Service) dispatchPrivate(ctx context.Context) (ServiceResult, error) {
	receiveRequest, requestErr := s.newServiceReceiveRequest()
	if requestErr != nil {
		return s.finishExecDispatch(ctx, requestErr)
	}
	packet, receiveErr := s.receiveServicePacket(ctx, receiveRequest)
	if receiveErr != nil {
		return s.finishExecDispatch(ctx, receiveErr)
	}
	arm, ok := packet.ExecPrivate()
	if !ok {
		packetErr := destroyServiceReceivedPacket(ctx, packet)
		if packetErr != nil {
			return s.finishExecDispatch(ctx, packetErr)
		}
		return s.finishExecDispatch(ctx, errInvalid)
	}
	dispatch, dispatchErr := s.takeExecDispatch(arm.Revision())
	if dispatchErr != nil {
		packetErr := destroyServiceReceivedPacket(ctx, packet)
		if packetErr != nil {
			return s.finishExecDispatch(ctx, packetErr)
		}
		return s.finishExecDispatch(ctx, dispatchErr)
	}
	if validationErr := s.validateServiceExecPacket(packet, dispatch); validationErr != nil {
		packetErr := destroyServiceReceivedPacket(ctx, packet)
		if packetErr != nil {
			return s.finishExecDispatch(ctx, packetErr)
		}
		return s.finishExecDispatch(ctx, validationErr)
	}
	_, handlerErr := s.private(ctx, packet.body, dispatch.transaction, dispatch.correlation, arm.observation, dispatch.comparison)
	if handlerErr != nil {
		return s.finishExecDispatch(ctx, handlerErr)
	}
	if continueErr := s.continueExecDispatch(ctx, dispatch); continueErr != nil {
		return s.finishExecDispatch(ctx, continueErr)
	}
	return s.dispatchStdin(ctx)
}

func (s *Service) private(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, correlation credentialprotocol.HelperExecTransactionCorrelation, obs credentialprotocol.HelperExecPrivateObservation, comparison bool) (serviceResult ServiceResult, serviceErr error) {
	s.state.mu.Lock()
	coreRequest := s.state.request
	s.state.mu.Unlock()
	var pending *credentialprotocol.HelperExecPayloadProposal
	defer func() {
		if recovered := recover(); recovered != nil {
			if pending != nil {
				pending.Wipe()
			}
			serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
			serviceErr = ErrContractOwnership
		}
		bodyDestroyErr := destroyServiceObservedBody(ctx, body)
		if bodyDestroyErr != nil {
			serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
			serviceErr = ErrContractOwnership
		}
	}()
	borrowErr := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		proposal, proposalErr := tx.ProposeObservedPrivate(correlation, obs)
		if proposalErr != nil {
			return proposalErr
		}
		pending = proposal
		if comparison {
			return proposal.Commit()
		}
		execution, coreErr := s.core.BeginExec(ctx, coreRequest, view)
		if coreErr != nil || !configuredDependency(execution) {
			proposal.Wipe()
			return errInvalid
		}
		s.state.mu.Lock()
		s.state.execution = execution
		s.state.mu.Unlock()
		return proposal.Commit()
	})
	if borrowErr != nil {
		return ServiceResult{}, borrowErr
	}
	return ServiceResult{}, nil
}

func (s *Service) dispatchStdin(ctx context.Context) (ServiceResult, error) {
	workerCtx, cancel := context.WithCancel(ctx)
	coordinator := &serviceExecCoordinator{cancel: cancel, receiveResults: make(chan serviceExecReceiveResult, 1), stdinResults: make(chan serviceExecWorkResult, 1), outputResults: make(chan serviceExecWorkResult, 1)}
	var outputLedger *serviceExecOutputLedger
	for {
		if !coordinator.receivePending && !(coordinator.outputPending && coordinator.creditQueued) {
			if startErr := s.startServiceExecReceive(workerCtx, coordinator); startErr != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, startErr)
			}
		}
		select {
		case received := <-coordinator.receiveResults:
			coordinator.receivePending = false
			if received.err != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, received.err)
			}
			packet := received.packet
			arm, streamOK := packet.ExecStream()
			if streamOK {
				if coordinator.stdinPending {
					packetErr := destroyServiceReceivedPacket(ctx, packet)
					if packetErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
					}
					return s.finishServiceExecCoordinator(ctx, coordinator, ErrContractTransition)
				}
				dispatch, dispatchErr := s.takeExecDispatch(arm.Revision())
				if dispatchErr != nil {
					packetErr := destroyServiceReceivedPacket(ctx, packet)
					if packetErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
					}
					return s.finishServiceExecCoordinator(ctx, coordinator, dispatchErr)
				}
				if validationErr := s.validateServiceExecPacket(packet, dispatch); validationErr != nil {
					packetErr := destroyServiceReceivedPacket(ctx, packet)
					if packetErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
					}
					return s.finishServiceExecCoordinator(ctx, coordinator, validationErr)
				}
				if releaseErr := s.releaseExecDispatch(dispatch); releaseErr != nil {
					packetErr := destroyServiceReceivedPacket(ctx, packet)
					if packetErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
					}
					return s.finishServiceExecCoordinator(ctx, coordinator, releaseErr)
				}
				coordinator.stdinPending = true
				go s.runServiceExecStdin(workerCtx, packet, arm, dispatch, coordinator.stdinResults)
				continue
			}
			credit, creditOK := packet.ExecCredit()
			if !creditOK {
				packetErr := destroyServiceReceivedPacket(ctx, packet)
				if packetErr != nil {
					return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
				}
				return s.finishServiceExecCoordinator(ctx, coordinator, ErrContractInvalidArgument)
			}
			dispatch, dispatchErr := s.takeExecDispatch(credit.Revision())
			if dispatchErr != nil {
				packetErr := destroyServiceReceivedPacket(ctx, packet)
				if packetErr != nil {
					return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
				}
				return s.finishServiceExecCoordinator(ctx, coordinator, dispatchErr)
			}
			if validationErr := s.validateServiceExecPacket(packet, dispatch); validationErr != nil {
				packetErr := destroyServiceReceivedPacket(ctx, packet)
				if packetErr != nil {
					return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
				}
				return s.finishServiceExecCoordinator(ctx, coordinator, validationErr)
			}
			if dispatch.comparison {
				packetErr := destroyServiceReceivedPacket(ctx, packet)
				if packetErr != nil {
					return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
				}
				return s.finishServiceExecCoordinator(ctx, coordinator, ErrContractTransition)
			}
			if outputLedger == nil {
				var ledgerErr error
				outputLedger, ledgerErr = s.newServiceExecOutputLedger(dispatch)
				if ledgerErr != nil {
					packetErr := destroyServiceReceivedPacket(ctx, packet)
					if packetErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
					}
					return s.finishServiceExecCoordinator(ctx, coordinator, ledgerErr)
				}
			}
			if packetErr := destroyServiceReceivedPacket(ctx, packet); packetErr != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, packetErr)
			}
			if releaseErr := s.releaseExecDispatch(dispatch); releaseErr != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, releaseErr)
			}
			if coordinator.outputPending {
				if coordinator.creditQueued {
					return s.finishServiceExecCoordinator(ctx, coordinator, ErrContractTransition)
				}
				coordinator.queuedCredit = credit
				coordinator.queuedDispatch = dispatch
				coordinator.creditQueued = true
				continue
			}
			coordinator.outputPending = true
			go s.runServiceExecOutput(workerCtx, credit, dispatch, outputLedger, coordinator.outputResults)
		case completed := <-coordinator.stdinResults:
			coordinator.stdinPending = false
			if completed.err != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, completed.err)
			}
			dispatch, dispatchErr := s.takeExecDispatch(completed.dispatch.correlation.Revision())
			if dispatchErr != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, dispatchErr)
			}
			snapshot := dispatch.transaction.Snapshot()
			if snapshot.Terminal || snapshot.Completed || !snapshot.PrivateComplete || snapshot.PendingPayload || snapshot.StdinCreditOutstanding || snapshot.ComparisonOnly != dispatch.comparison {
				return s.finishServiceExecCoordinator(ctx, coordinator, ErrContractTransition)
			}
			if snapshot.StdinEOF {
				if dispatch.comparison {
					response, replayErr := dispatch.transaction.ReplayResult()
					if replayErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, replayErr)
					}
					if responseErr := s.sendServiceExecResponse(ctx, dispatch, response); responseErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, responseErr)
					}
					return s.finishServiceExecCoordinator(ctx, coordinator, nil)
				}
				if !coordinator.outputPending && outputLedger != nil && outputLedger.stdoutEOF && outputLedger.stderrEOF && !coordinator.creditQueued {
					if completeErr := s.completeServiceExecOutput(ctx, dispatch, outputLedger); completeErr != nil {
						return s.finishServiceExecCoordinator(ctx, coordinator, completeErr)
					}
					return s.finishServiceExecCoordinator(ctx, coordinator, nil)
				}
				if releaseErr := s.releaseExecDispatch(dispatch); releaseErr != nil {
					return s.finishServiceExecCoordinator(ctx, coordinator, releaseErr)
				}
				continue
			}
			if continueErr := s.continueExecDispatch(ctx, dispatch); continueErr != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, continueErr)
			}
		case completed := <-coordinator.outputResults:
			coordinator.outputPending = false
			if completed.err != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, completed.err)
			}
			dispatch, dispatchErr := s.takeExecDispatch(completed.dispatch.correlation.Revision())
			if dispatchErr != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, dispatchErr)
			}
			snapshot := dispatch.transaction.Snapshot()
			if snapshot.Terminal || snapshot.Completed || !snapshot.PrivateComplete || snapshot.ComparisonOnly != dispatch.comparison {
				return s.finishServiceExecCoordinator(ctx, coordinator, ErrContractTransition)
			}
			if !coordinator.stdinPending && snapshot.StdinEOF && outputLedger.stdoutEOF && outputLedger.stderrEOF && !coordinator.creditQueued {
				if completeErr := s.completeServiceExecOutput(ctx, dispatch, outputLedger); completeErr != nil {
					return s.finishServiceExecCoordinator(ctx, coordinator, completeErr)
				}
				return s.finishServiceExecCoordinator(ctx, coordinator, nil)
			}
			if releaseErr := s.releaseExecDispatch(dispatch); releaseErr != nil {
				return s.finishServiceExecCoordinator(ctx, coordinator, releaseErr)
			}
			if coordinator.creditQueued {
				credit := coordinator.queuedCredit
				queuedDispatch := coordinator.queuedDispatch
				coordinator.creditQueued = false
				coordinator.outputPending = true
				go s.runServiceExecOutput(workerCtx, credit, queuedDispatch, outputLedger, coordinator.outputResults)
			}
		}
	}
}

func (s *Service) receiveServicePacket(ctx context.Context, request ReceiveRequest) (packet ReceivedPacket, receiveErr error) {
	defer func() {
		if recover() != nil {
			packet = ReceivedPacket{}
			receiveErr = ErrContractOwnership
		}
	}()
	return s.transport.Receive(ctx, request)
}

func (s *Service) finishServiceReceive(ctx context.Context, cause error) (serviceResult ServiceResult, serviceErr error) {
	defer func() {
		if recover() != nil {
			serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
			serviceErr = ErrContractOwnership
		}
	}()
	s.state.mu.Lock()
	execInstalled := s.state.revision != 0 && s.state.transaction != nil
	preparing := s.state.preparing
	prepared := s.state.prepared
	s.state.mu.Unlock()
	if execInstalled {
		return s.finishExecDispatch(ctx, cause)
	}
	cleanupFailed := false
	if preparing.authority.transaction != nil && (preparing.beginTaken || preparing.active) {
		if abortErr := s.abortPreparing(ctx, preparing.authority.transaction, nil); abortErr != nil {
			cleanupFailed = true
		}
	}
	if prepared.active {
		if revokeErr := s.revokeServicePreparedActivation(ctx, prepared); revokeErr != nil {
			cleanupFailed = true
		}
	}
	stopped, resultErr := newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
	if cause != nil || cleanupFailed || resultErr != nil {
		return stopped, ErrContractOwnership
	}
	return stopped, ErrContractOwnership
}

func (s *Service) stdin(ctx context.Context, body ReceivedBodyCapability, tx *credentialprotocol.HelperExecTransaction, correlation credentialprotocol.HelperExecTransactionCorrelation, obs credentialprotocol.HelperExecStreamObservation, offset uint64, eof bool, comparison bool) (serviceResult ServiceResult, serviceErr error) {
	var pending *credentialprotocol.HelperExecPayloadProposal
	defer func() {
		if recovered := recover(); recovered != nil {
			if pending != nil {
				pending.Wipe()
			}
			serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
			serviceErr = ErrContractOwnership
		}
		bodyDestroyErr := destroyServiceObservedBody(ctx, body)
		if bodyDestroyErr != nil {
			serviceResult, _ = newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
			serviceErr = ErrContractOwnership
		}
	}()
	borrowErr := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		proposal, proposalErr := tx.ProposeObservedStdin(ctx, correlation, obs, view)
		if proposalErr != nil {
			return proposalErr
		}
		pending = proposal
		if comparison {
			return proposal.Commit()
		}
		s.state.mu.Lock()
		retainedExecution := s.state.execution
		s.state.mu.Unlock()
		coreErr := retainedExecution.WriteStdin(ctx, view, offset, eof)
		if coreErr != nil {
			proposal.Wipe()
			return coreErr
		}
		return proposal.Commit()
	})
	if borrowErr != nil {
		return ServiceResult{}, borrowErr
	}
	return ServiceResult{}, nil
}

func (s *Service) zeroPrivate(ctx context.Context, packet ReceivedPacket, comparison bool) (serviceResult ServiceResult, serviceErr error) {
	defer func() {
		if recover() != nil {
			serviceResult, serviceErr = s.finishExecDispatch(ctx, ErrContractOwnership)
		}
	}()
	arm, ok := packet.Exec()
	packetErr := destroyServiceReceivedPacket(ctx, packet)
	if packetErr != nil {
		return s.finishExecDispatch(ctx, packetErr)
	}
	if !ok {
		return s.finishExecDispatch(ctx, ErrContractInvalidArgument)
	}
	if arm.PrivateBindingLength() == 0 && arm.PrivateBindingSHA256() == ([32]byte{}) {
		dispatch, dispatchErr := s.takeExecDispatch(arm.Revision())
		if dispatchErr != nil {
			return s.finishExecDispatch(ctx, dispatchErr)
		}
		if !comparison {
			s.state.mu.Lock()
			stateRequest := s.state.request
			s.state.mu.Unlock()
			execution, coreErr := s.core.BeginExec(ctx, stateRequest, nil)
			if coreErr != nil || !configuredDependency(execution) {
				return s.finishExecDispatch(ctx, ErrContractDependency)
			}
			s.state.mu.Lock()
			s.state.execution = execution
			s.state.mu.Unlock()
		}
		if continueErr := s.continueExecDispatch(ctx, dispatch); continueErr != nil {
			return s.finishExecDispatch(ctx, continueErr)
		}
		return s.dispatchStdin(ctx)
	}
	return s.finishExecDispatch(ctx, ErrContractInvalidArgument)
}

func destroyServiceObservedBody(ctx context.Context, body ReceivedBodyCapability) (cleanupErr error) {
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	if destroyErr := body.Destroy(ctx); destroyErr != nil {
		return ErrContractOwnership
	}
	return nil
}

func cancelServiceExecution(ctx context.Context, execution CoreExecution, cleanup CoreCleanupCapability) (cleanupErr error) {
	if !configuredDependency(execution) {
		return nil
	}
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	result, cancelErr := execution.Cancel(ctx)
	resultCleanup := result.Cleanup()
	if cancelErr != nil || subtle.ConstantTimeCompare(resultCleanup.digest[:], cleanup.digest[:]) != 1 {
		return ErrContractOwnership
	}
	if result.Category() != CoreCleanupComplete || !result.AuthorityAbsent() || !result.ResourcesAbsent() {
		return ErrContractOwnership
	}
	return nil
}

func (sink *serviceExecOutputDigestSink) MaxCredentialBytes() int {
	if sink == nil || sink.written {
		return 0
	}
	return sink.expected
}

func (sink *serviceExecOutputDigestSink) WriteCredential(value []byte) error {
	if sink == nil || sink.written || !configuredDependency(sink.hasher) || sink.expected < 56 || len(value) != sink.expected {
		return ErrContractInvalidArgument
	}
	sink.written = true
	count, writeErr := sink.hasher.Write(value[56:])
	if writeErr != nil || count != len(value)-56 {
		return ErrContractOwnership
	}
	return nil
}

func serviceExecOutputLimits(plan ExecPlanCapability) (uint64, uint64, error) {
	sink := &serviceExecPlanSink{}
	defer sink.destroy()
	if copyErr := plan.CopyCanonicalTo(sink); copyErr != nil || !sink.written || sink.length != plan.EncodedLength() {
		return 0, 0, ErrContractCorrelation
	}
	decoded, decodeErr := credentialprotocol.DecodeHelperExecPlan(sink.canonical[:sink.length])
	if decodeErr != nil || decoded.StdoutMaxBytes == 0 || decoded.StderrMaxBytes == 0 {
		return 0, 0, ErrContractCorrelation
	}
	return uint64(decoded.StdoutMaxBytes), uint64(decoded.StderrMaxBytes), nil
}

func destroyServiceCoreOutputBody(ctx context.Context, body CoreOutputBody) (cleanupErr error) {
	if !configuredDependency(body) {
		return ErrContractOwnership
	}
	defer func() {
		if recover() != nil {
			cleanupErr = ErrContractOwnership
		}
	}()
	if destroyErr := body.Destroy(ctx); destroyErr != nil {
		return ErrContractOwnership
	}
	return nil
}

func observeServiceCoreOutput(ctx context.Context, body CoreOutputBody, hasher hash.Hash, expected int) (observeErr error) {
	defer func() {
		if recover() != nil {
			observeErr = ErrContractOwnership
		}
	}()
	if !configuredDependency(body) || !configuredDependency(hasher) || expected < 56 || body.Len() != uint32(expected) {
		return ErrContractCorrelation
	}
	sink := &serviceExecOutputDigestSink{hasher: hasher, expected: expected}
	borrowErr := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		if !configuredDependency(view) || view.Len() != expected {
			return ErrContractOwnership
		}
		return view.WriteTo(ctx, sink)
	})
	if borrowErr != nil || !sink.written {
		return ErrContractOwnership
	}
	return nil
}

func serviceExecDigest(hasher hash.Hash) ([32]byte, error) {
	if !configuredDependency(hasher) {
		return [32]byte{}, ErrContractOwnership
	}
	encoded := hasher.Sum(nil)
	defer wipeBytes(encoded[:cap(encoded)])
	if len(encoded) != sha256.Size {
		return [32]byte{}, ErrContractOwnership
	}
	var digest [32]byte
	copy(digest[:], encoded)
	return digest, nil
}

func (s *Service) newServiceExecSendHeader(dispatch serviceExecDispatch, packetType credentialprotocol.PacketType, bodyLength uint32) (credentialprotocol.HelperPacketHeader, error) {
	if bodyLength == 0 || packetType != credentialprotocol.PacketTypeExecStream && packetType != credentialprotocol.PacketTypeResponse {
		return credentialprotocol.HelperPacketHeader{}, ErrContractInvalidArgument
	}
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || packetType == credentialprotocol.PacketTypeResponse && !s.state.dispatchTaken || !s.state.prepared.active {
		s.state.mu.Unlock()
		return credentialprotocol.HelperPacketHeader{}, ErrContractTransition
	}
	sequence := s.state.nextSendSequence
	activation := s.state.prepared
	s.state.nextSendSequence++
	s.state.mu.Unlock()
	return credentialprotocol.HelperPacketHeader{Type: packetType, Sequence: sequence, RequestID: dispatch.correlation.RequestID(), BodyLength: bodyLength, GuestCredentialIdentityDigest: dispatch.correlation.IdentityDigest(), BootNonce: activation.bootNonce}, nil
}

func (s *Service) sendServiceExecOutput(ctx context.Context, dispatch serviceExecDispatch, output CoreOutputResult, body CoreOutputBody) (sendErr error) {
	owned := true
	defer func() {
		if recover() != nil {
			sendErr = ErrContractOwnership
		}
		if owned {
			if destroyErr := destroyServiceCoreOutputBody(ctx, body); destroyErr != nil {
				sendErr = ErrContractOwnership
			}
		}
	}()
	s.state.sendMu.Lock()
	defer s.state.sendMu.Unlock()
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	bodyLength := uint32(56) + output.ByteCount()
	header, headerErr := s.newServiceExecSendHeader(dispatch, credentialprotocol.PacketTypeExecStream, bodyLength)
	if headerErr != nil {
		return headerErr
	}
	flags := credentialprotocol.HelperExecStreamFlagsNone
	if output.EOF() {
		flags = credentialprotocol.HelperExecStreamFlagEOF
	}
	owned = false
	packet, packetErr := newExecStreamPacket(ctx, header, dispatch.correlation.Revision(), output.Kind(), flags, output.Offset(), output.ByteCount(), output.SHA256(), body)
	if packetErr != nil {
		return packetErr
	}
	return s.transport.Send(ctx, packet)
}

func (s *Service) sendServiceExecResponse(ctx context.Context, dispatch serviceExecDispatch, response credentialprotocol.HelperResponseBody) (sendErr error) {
	defer func() {
		if recover() != nil {
			sendErr = ErrContractOwnership
		}
	}()
	s.state.sendMu.Lock()
	defer s.state.sendMu.Unlock()
	bodyLength, lengthErr := credentialprotocol.HelperResponseBodyEncodedLength(response)
	if lengthErr != nil {
		return ErrContractCorrelation
	}
	header, headerErr := s.newServiceExecSendHeader(dispatch, credentialprotocol.PacketTypeResponse, bodyLength)
	if headerErr != nil {
		return headerErr
	}
	packet, packetErr := newResponsePacket(ctx, header, response)
	if packetErr != nil {
		return packetErr
	}
	return s.transport.Send(ctx, packet)
}

func (s *Service) validateServiceExecPacket(packet ReceivedPacket, dispatch serviceExecDispatch) error {
	header := packet.Header()
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || !s.state.dispatchTaken || !s.state.prepared.active {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	activation := s.state.prepared
	s.state.mu.Unlock()
	identity := dispatch.correlation.IdentityDigest()
	if header.RequestID != dispatch.correlation.RequestID() || subtle.ConstantTimeCompare(header.GuestCredentialIdentityDigest[:], identity[:]) != 1 || subtle.ConstantTimeCompare(header.BootNonce[:], activation.bootNonce[:]) != 1 {
		return ErrContractCorrelation
	}
	return nil
}

func (s *Service) newServiceExecOutputLedger(dispatch serviceExecDispatch) (*serviceExecOutputLedger, error) {
	if dispatch.comparison {
		return nil, ErrContractTransition
	}
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || !s.state.dispatchTaken || !s.state.prepared.active || !configuredDependency(s.state.execution) {
		s.state.mu.Unlock()
		return nil, ErrContractTransition
	}
	request := s.state.request
	plan := s.state.plan
	s.state.mu.Unlock()
	stdoutMaximum, stderrMaximum, limitsErr := serviceExecOutputLimits(plan)
	if limitsErr != nil {
		return nil, limitsErr
	}
	return &serviceExecOutputLedger{request: request, stdoutMaximum: stdoutMaximum, stderrMaximum: stderrMaximum, stdoutHasher: sha256.New(), stderrHasher: sha256.New()}, nil
}

func (s *Service) releaseExecDispatch(dispatch serviceExecDispatch) error {
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || !s.state.dispatchTaken || !s.state.prepared.active {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.dispatchTaken = false
	s.state.mu.Unlock()
	return nil
}

func destroyUnexpectedServiceCoreOutput(ctx context.Context, event CoreExecutionEvent, cause error) error {
	if _, body, ok := event.Output(); ok && configuredDependency(body) {
		if destroyErr := destroyServiceCoreOutputBody(ctx, body); destroyErr != nil {
			return ErrContractOwnership
		}
	}
	return cause
}

func (s *Service) drainExecOutput(ctx context.Context, arm ReceivedExecCredit, dispatch serviceExecDispatch, ledger *serviceExecOutputLedger) (drainErr error) {
	defer func() {
		if recover() != nil {
			drainErr = ErrContractOwnership
		}
	}()
	if ledger == nil || dispatch.comparison || arm.Revision() != dispatch.correlation.Revision() {
		return ErrContractTransition
	}
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || !s.state.prepared.active || !configuredDependency(s.state.execution) {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	execution := s.state.execution
	s.state.mu.Unlock()
	var offset *uint64
	var eof *bool
	var truncated *bool
	var maximum uint64
	var hasher hash.Hash
	switch arm.StreamKind() {
	case credentialprotocol.HelperExecStreamStdout:
		offset, eof, truncated, maximum, hasher = &ledger.stdoutOffset, &ledger.stdoutEOF, &ledger.stdoutTruncated, ledger.stdoutMaximum, ledger.stdoutHasher
	case credentialprotocol.HelperExecStreamStderr:
		offset, eof, truncated, maximum, hasher = &ledger.stderrOffset, &ledger.stderrEOF, &ledger.stderrTruncated, ledger.stderrMaximum, ledger.stderrHasher
	default:
		return ErrContractInvalidArgument
	}
	if *eof || arm.NextOffset() != *offset || *offset > maximum {
		return ErrContractCorrelation
	}
	capacity := uint32(1)
	if remaining := maximum - *offset; remaining > 0 {
		capacity = credentialprotocol.MaxHelperExecStreamPayloadBytes
		if remaining < uint64(capacity) {
			capacity = uint32(remaining)
		}
	}
	request := ledger.request
	outputRequest, outputErr := NewCoreOutputRequest(request.correlation.requestID, request.correlation.identityDigest, request.correlation.revision, request.generations.job, request.execution, arm.StreamKind(), arm.NextOffset(), capacity)
	if outputErr != nil {
		return outputErr
	}
	if grantErr := execution.GrantOutput(ctx, outputRequest); grantErr != nil {
		return grantErr
	}
	event, nextErr := execution.Next(ctx)
	if nextErr != nil {
		return destroyUnexpectedServiceCoreOutput(ctx, event, nextErr)
	}
	output, outputBody, outputOK := event.Output()
	if !outputOK || !configuredDependency(outputBody) || output.Execution() != outputRequest.Execution() || output.Kind() != outputRequest.Kind() || output.Offset() != outputRequest.Offset() || output.ByteCount() > outputRequest.Capacity() || output.ByteCount() > uint32(maximum-*offset) {
		return destroyUnexpectedServiceCoreOutput(ctx, event, ErrContractCorrelation)
	}
	emptySHA256 := sha256.Sum256(nil)
	nextOffset := *offset + uint64(output.ByteCount())
	if output.EOF() && (output.ByteCount() != 0 || output.SHA256() != emptySHA256 || output.Truncated() && nextOffset != maximum) || !output.EOF() && (output.ByteCount() == 0 || output.Truncated()) {
		return destroyUnexpectedServiceCoreOutput(ctx, event, ErrContractCorrelation)
	}
	if observeErr := observeServiceCoreOutput(ctx, outputBody, hasher, int(56+output.ByteCount())); observeErr != nil {
		if destroyErr := destroyServiceCoreOutputBody(ctx, outputBody); destroyErr != nil {
			return ErrContractOwnership
		}
		return observeErr
	}
	if sendErr := s.sendServiceExecOutput(ctx, dispatch, output, outputBody); sendErr != nil {
		return sendErr
	}
	*offset += uint64(output.ByteCount())
	if output.EOF() {
		*eof = true
		*truncated = output.Truncated()
	}
	return nil
}

func (s *Service) completeServiceExecOutput(ctx context.Context, dispatch serviceExecDispatch, ledger *serviceExecOutputLedger) (completeErr error) {
	defer func() {
		if recover() != nil {
			completeErr = ErrContractOwnership
		}
	}()
	snapshot := dispatch.transaction.Snapshot()
	if ledger == nil || dispatch.comparison || snapshot.Terminal || snapshot.Completed || !snapshot.PrivateComplete || snapshot.PendingPayload || snapshot.StdinCreditOutstanding || !snapshot.StdinEOF || snapshot.ComparisonOnly || !ledger.stdoutEOF || !ledger.stderrEOF {
		return ErrContractTransition
	}
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || !s.state.dispatchTaken || !configuredDependency(s.state.execution) {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	execution := s.state.execution
	s.state.mu.Unlock()
	event, nextErr := execution.Next(ctx)
	if nextErr != nil {
		return destroyUnexpectedServiceCoreOutput(ctx, event, nextErr)
	}
	if _, _, outputOK := event.Output(); outputOK {
		return destroyUnexpectedServiceCoreOutput(ctx, event, ErrContractTransition)
	}
	complete, completeOK := event.Complete()
	stdoutSHA256, stdoutErr := serviceExecDigest(ledger.stdoutHasher)
	stderrSHA256, stderrErr := serviceExecDigest(ledger.stderrHasher)
	if !completeOK || stdoutErr != nil || stderrErr != nil || complete.Execution() != ledger.request.execution || complete.StdinBytes() != snapshot.StdinBytes || complete.StdinSHA256() != snapshot.StdinSHA256 || complete.StdinTranscriptSHA256() != snapshot.StdinTranscriptSHA256 || complete.StdoutBytes() != ledger.stdoutOffset || complete.StdoutSHA256() != stdoutSHA256 || complete.StdoutTruncated() != ledger.stdoutTruncated || complete.StderrBytes() != ledger.stderrOffset || complete.StderrSHA256() != stderrSHA256 || complete.StderrTruncated() != ledger.stderrTruncated || complete.ExecTransactionSHA256() != snapshot.ExecTransactionSHA256 {
		return ErrContractCorrelation
	}
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || !s.state.dispatchTaken || !configuredDependency(s.state.execution) {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	s.state.execution = nil
	s.state.mu.Unlock()
	response := credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeExec, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: dispatch.correlation.Revision(), FailureCode: credentialprotocol.FailureCodeNone, Exec: &credentialprotocol.HelperExecResponseResult{ExitCode: complete.ExitCode(), StdinBytes: complete.StdinBytes(), StdinSHA256: complete.StdinSHA256(), StdoutBytes: complete.StdoutBytes(), StdoutSHA256: complete.StdoutSHA256(), StdoutTruncated: complete.StdoutTruncated(), StderrBytes: complete.StderrBytes(), StderrSHA256: complete.StderrSHA256(), StderrTruncated: complete.StderrTruncated(), ExecTransactionSHA256: complete.ExecTransactionSHA256()}}
	if _, transactionErr := dispatch.transaction.Complete(response); transactionErr != nil {
		return transactionErr
	}
	return s.sendServiceExecResponse(ctx, dispatch, response)
}

func (s *Service) startServiceExecReceive(ctx context.Context, coordinator *serviceExecCoordinator) (startErr error) {
	defer func() {
		if recover() != nil {
			startErr = ErrContractOwnership
		}
	}()
	if coordinator == nil || coordinator.receivePending {
		return ErrContractTransition
	}
	receiveRequest, requestErr := s.newServiceReceiveRequest()
	if requestErr != nil {
		return requestErr
	}
	coordinator.receivePending = true
	go s.receiveServiceExecContinuation(ctx, receiveRequest, coordinator.receiveResults)
	return nil
}

func (s *Service) receiveServiceExecContinuation(ctx context.Context, request ReceiveRequest, results chan<- serviceExecReceiveResult) {
	result := serviceExecReceiveResult{}
	defer func() {
		if recover() != nil {
			result.err = ErrContractOwnership
		}
		results <- result
	}()
	result.packet, result.err = s.transport.Receive(ctx, request)
}

func (s *Service) runServiceExecStdin(ctx context.Context, packet ReceivedPacket, arm ReceivedExecStream, dispatch serviceExecDispatch, results chan<- serviceExecWorkResult) {
	result := serviceExecWorkResult{dispatch: dispatch}
	defer func() {
		if recover() != nil {
			result.err = ErrContractOwnership
		}
		results <- result
	}()
	_, result.err = s.stdin(ctx, packet.body, dispatch.transaction, dispatch.correlation, arm.observation, arm.Offset(), arm.Flags() == credentialprotocol.HelperExecStreamFlagEOF, dispatch.comparison)
}

func (s *Service) runServiceExecOutput(ctx context.Context, arm ReceivedExecCredit, dispatch serviceExecDispatch, ledger *serviceExecOutputLedger, results chan<- serviceExecWorkResult) {
	result := serviceExecWorkResult{dispatch: dispatch}
	defer func() {
		if recover() != nil {
			result.err = ErrContractOwnership
		}
		results <- result
	}()
	result.err = s.drainExecOutput(ctx, arm, dispatch, ledger)
}

func (s *Service) stopServiceExecCoordinator(ctx context.Context, coordinator *serviceExecCoordinator) (stopErr error) {
	defer func() {
		if recover() != nil {
			stopErr = ErrContractOwnership
		}
	}()
	if coordinator == nil || !configuredDependency(coordinator.cancel) {
		return ErrContractOwnership
	}
	coordinator.cancel()
	ownershipFailed := false
	unexpectedPacket := false
	if coordinator.receivePending {
		received := <-coordinator.receiveResults
		coordinator.receivePending = false
		if received.err == nil {
			unexpectedPacket = true
			if packetErr := destroyServiceReceivedPacket(ctx, received.packet); packetErr != nil {
				ownershipFailed = true
			}
		} else if received.err == ErrContractOwnership {
			ownershipFailed = true
		}
	}
	if coordinator.stdinPending {
		completed := <-coordinator.stdinResults
		coordinator.stdinPending = false
		if completed.err == ErrContractOwnership {
			ownershipFailed = true
		}
	}
	if coordinator.outputPending {
		completed := <-coordinator.outputResults
		coordinator.outputPending = false
		if completed.err == ErrContractOwnership {
			ownershipFailed = true
		}
	}
	coordinator.creditQueued = false
	if ownershipFailed {
		return ErrContractOwnership
	}
	if unexpectedPacket {
		return ErrContractTransition
	}
	return nil
}

func (s *Service) finishServiceExecCoordinator(ctx context.Context, coordinator *serviceExecCoordinator, cause error) (ServiceResult, error) {
	if stopErr := s.stopServiceExecCoordinator(ctx, coordinator); stopErr != nil {
		cause = ErrContractOwnership
	}
	return s.finishExecDispatch(ctx, cause)
}

func (s *Service) continueExecDispatch(ctx context.Context, dispatch serviceExecDispatch) (continueErr error) {
	defer func() {
		if recover() != nil {
			continueErr = ErrContractOwnership
		}
	}()
	snapshot := dispatch.transaction.Snapshot()
	if snapshot.Terminal || snapshot.Completed || !snapshot.PrivateComplete || snapshot.PendingPayload || snapshot.StdinCreditOutstanding || snapshot.StdinEOF || snapshot.ComparisonOnly != dispatch.comparison {
		return ErrContractTransition
	}
	credit := credentialprotocol.HelperExecCreditBody{Revision: dispatch.correlation.Revision(), StreamKind: credentialprotocol.HelperExecStreamStdin, NextOffset: snapshot.StdinOffset}
	if creditErr := dispatch.transaction.GrantStdinCredit(dispatch.correlation, credit); creditErr != nil {
		return creditErr
	}
	s.state.sendMu.Lock()
	defer s.state.sendMu.Unlock()
	s.state.mu.Lock()
	if s.state.revision != dispatch.correlation.Revision() || s.state.transaction != dispatch.transaction || s.state.correlation != dispatch.correlation || !s.state.dispatchTaken || !s.state.prepared.active {
		s.state.mu.Unlock()
		return ErrContractTransition
	}
	sequence := s.state.nextSendSequence
	activation := s.state.prepared
	s.state.nextSendSequence++
	s.state.dispatchTaken = false
	s.state.mu.Unlock()
	header := credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeExecCredit, Sequence: sequence, RequestID: dispatch.correlation.RequestID(), BodyLength: credentialprotocol.HelperExecCreditBodyBytes, GuestCredentialIdentityDigest: dispatch.correlation.IdentityDigest(), BootNonce: activation.bootNonce}
	packet, packetErr := newExecCreditPacket(ctx, header, credit)
	if packetErr != nil {
		return packetErr
	}
	return s.transport.Send(ctx, packet)
}

func (s *Service) finishExecDispatch(ctx context.Context, cause error) (ServiceResult, error) {
	s.state.mu.Lock()
	if s.state.revision == 0 || s.state.transaction == nil {
		s.state.mu.Unlock()
		stopped, _ := newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
		return stopped, ErrContractOwnership
	}
	execution := s.state.execution
	request := s.state.request
	plan := s.state.plan
	transaction := s.state.transaction
	activation := s.state.prepared
	s.state.execution = nil
	s.state.request = CoreExecRequest{}
	s.state.plan = ExecPlanCapability{}
	s.state.revision = 0
	s.state.transaction = nil
	s.state.correlation = credentialprotocol.HelperExecTransactionCorrelation{}
	s.state.comparison = false
	s.state.dispatchTaken = true
	s.state.mu.Unlock()
	authorityErr := closeServiceExecAuthority(serviceExecAuthority{plan: plan, transaction: transaction})
	cancelErr := cancelServiceExecution(ctx, execution, request.Cleanup())
	revokeErr := s.revokeServicePreparedActivation(ctx, activation)
	if cause != nil || authorityErr != nil || cancelErr != nil || revokeErr != nil {
		stopped, _ := newServiceResult(ServiceStopVMRequired, credentialprotocol.CloseReasonProtocolError)
		return stopped, ErrContractOwnership
	}
	return newServiceResult(ServiceClosed, credentialprotocol.CloseReasonNormal)
}
