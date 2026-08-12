package credentialprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
)

const helperPrepareTransactionDomain = "hal/l8/guest-helper/prepare-transaction/v1"

var (
	ErrHelperPrepareTransactionCorrelation   = errors.New("credential protocol helper prepare transaction correlation is invalid")
	ErrHelperPrepareTransactionBegin         = errors.New("credential protocol helper prepare transaction begin is invalid")
	ErrHelperPrepareTransactionFile          = errors.New("credential protocol helper prepare transaction file is invalid")
	ErrHelperPrepareTransactionCommit        = errors.New("credential protocol helper prepare transaction commit is invalid")
	ErrHelperPrepareTransactionTerminal      = errors.New("credential protocol helper prepare transaction is terminal")
	ErrHelperPrepareTransactionCommitted     = errors.New("credential protocol helper prepare transaction is committed")
	ErrHelperPrepareFileProposalWiped        = errors.New("credential protocol helper prepare file proposal is wiped")
	ErrHelperPrepareFileProposalConsumed     = errors.New("credential protocol helper prepare file proposal is consumed")
	ErrHelperPrepareFileProposalDestination  = errors.New("credential protocol helper prepare file proposal destination size is invalid")
	ErrHelperPrepareTransactionSerialization = errors.New("credential protocol helper prepare transaction serialization is denied")
)

// HelperPrepareTransactionCorrelation is authenticated caller context for one
// atomic prepare transaction. Its identity digest is the exact nonzero guest
// credential session identity digest, not a digest derived from job identity.
type HelperPrepareTransactionCorrelation struct {
	requestID      [16]byte
	identityDigest [32]byte
	revision       uint64
	expiryUnixNano int64
}

// HelperPrepareTransaction owns pure, in-memory admission state. It never
// stages or publishes a file, mount, capability, descriptor, or proof.
type HelperPrepareTransaction struct {
	owner *helperPrepareTransactionOwner
}

type helperPrepareTransactionOwner struct {
	mu sync.Mutex

	correlation   HelperPrepareTransactionCorrelation
	manifest      [32]byte
	expectedFiles []helperPrepareTransactionFileMetadata
	acceptedFiles []helperPrepareTransactionFileMetadata
	acceptedBytes uint64
	pending       *helperPrepareFileProposalOwner
	terminal      bool
	committed     bool
	result        helperPrepareTransactionResultState
}

type helperPrepareTransactionFileMetadata struct {
	bindingIndex uint16
	fileLength   uint32
	fileSHA256   [32]byte
}

// HelperPrepareFileProposal owns one validated private value while its caller
// makes an external staging decision. Value copies share the wipe state.
type HelperPrepareFileProposal struct {
	owner *helperPrepareFileProposalOwner
}

type helperPrepareFileProposalOwner struct {
	transaction  *helperPrepareTransactionOwner
	metadata     helperPrepareTransactionFileMetadata
	privateBytes []byte
	consumed     bool
	wiped        bool
}

// HelperPrepareTransactionSnapshot contains safe decision counters only.
type HelperPrepareTransactionSnapshot struct {
	Terminal          bool
	Committed         bool
	PendingFile       bool
	HasNextFile       bool
	NextBindingIndex  uint16
	ExpectedFileCount uint16
	AcceptedFileCount uint16
	AcceptedFileBytes uint64
}

// HelperPrepareTransactionResult is the metadata-only result of a valid
// prepare_commit transition. It does not claim live publication or proof.
type HelperPrepareTransactionResult struct {
	state helperPrepareTransactionResultState
}

type helperPrepareTransactionResultState struct {
	manifestSHA256    [32]byte
	transactionSHA256 [32]byte
	fileCount         uint16
}

func NewHelperPrepareTransactionCorrelation(requestID [16]byte, identityDigest [32]byte, revision uint64, expiryUnixNano int64) (HelperPrepareTransactionCorrelation, error) {
	if requestID == [16]byte{} || identityDigest == [32]byte{} || revision != 1 || expiryUnixNano <= 0 {
		return HelperPrepareTransactionCorrelation{}, ErrHelperPrepareTransactionCorrelation
	}
	return HelperPrepareTransactionCorrelation{
		requestID: requestID, identityDigest: identityDigest, revision: revision, expiryUnixNano: expiryUnixNano,
	}, nil
}

func (correlation HelperPrepareTransactionCorrelation) RequestID() [16]byte {
	return correlation.requestID
}

func (correlation HelperPrepareTransactionCorrelation) IdentityDigest() [32]byte {
	return correlation.identityDigest
}

func (correlation HelperPrepareTransactionCorrelation) Revision() uint64 {
	return correlation.revision
}

func (correlation HelperPrepareTransactionCorrelation) ExpiryUnixNano() int64 {
	return correlation.expiryUnixNano
}

func NewHelperPrepareTransaction(correlation HelperPrepareTransactionCorrelation, begin HelperPrepareBeginBody, manifestSHA256 [32]byte) (*HelperPrepareTransaction, error) {
	if !validHelperPrepareTransactionCorrelation(correlation) || begin.Revision != correlation.revision || begin.ExpiryUnixNano != correlation.expiryUnixNano {
		return nil, ErrHelperPrepareTransactionCorrelation
	}
	if _, err := EncodeHelperPrepareBeginBody(begin); err != nil {
		return nil, ErrHelperPrepareTransactionBegin
	}
	computed, err := ComputeHelperManifestSHA256(begin.Bindings)
	if err != nil || manifestSHA256 == [32]byte{} || computed != manifestSHA256 {
		return nil, ErrHelperPrepareTransactionBegin
	}
	expected := make([]helperPrepareTransactionFileMetadata, 0, len(begin.Bindings))
	for index, binding := range begin.Bindings {
		if binding.Mode != DeliveryModeFileTmpfs {
			continue
		}
		expected = append(expected, helperPrepareTransactionFileMetadata{
			bindingIndex: uint16(index), fileLength: binding.DeclaredFileBytes, fileSHA256: binding.FileSHA256,
		})
	}
	return &HelperPrepareTransaction{owner: &helperPrepareTransactionOwner{
		correlation: correlation, manifest: manifestSHA256, expectedFiles: expected,
		acceptedFiles: make([]helperPrepareTransactionFileMetadata, 0, len(expected)),
	}}, nil
}

func (transaction *HelperPrepareTransaction) ProposeFile(correlation HelperPrepareTransactionCorrelation, body *HelperPrepareFileBody) (*HelperPrepareFileProposal, error) {
	owner := helperPrepareTransactionLiveOwner(transaction)
	if owner == nil {
		if body != nil {
			body.Wipe()
		}
		return nil, ErrHelperPrepareTransactionTerminal
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	defer func() {
		if body != nil {
			body.Wipe()
		}
	}()
	if owner.terminal {
		return nil, ErrHelperPrepareTransactionTerminal
	}
	if owner.committed {
		return nil, ErrHelperPrepareTransactionCommitted
	}
	if !helperPrepareTransactionCorrelationEqual(owner.correlation, correlation) {
		return nil, owner.failLocked(ErrHelperPrepareTransactionCorrelation)
	}
	if owner.pending != nil || len(owner.acceptedFiles) >= len(owner.expectedFiles) {
		return nil, owner.failLocked(ErrHelperPrepareTransactionFile)
	}
	state, valid := validHelperPrepareFileState(body)
	if !valid || state.revision != owner.correlation.revision {
		return nil, owner.failLocked(ErrHelperPrepareTransactionFile)
	}
	expected := owner.expectedFiles[len(owner.acceptedFiles)]
	if state.bindingIndex != expected.bindingIndex || state.fileLength != expected.fileLength || state.fileSHA256 != expected.fileSHA256 {
		return nil, owner.failLocked(ErrHelperPrepareTransactionFile)
	}
	if uint64(state.fileLength) > MaxHelperFileAggregateBytes-owner.acceptedBytes {
		return nil, owner.failLocked(ErrHelperPrepareTransactionFile)
	}
	privateBytes := make([]byte, len(state.privateBytes))
	copy(privateBytes, state.privateBytes)
	proposalOwner := &helperPrepareFileProposalOwner{
		transaction: owner, metadata: expected, privateBytes: privateBytes,
	}
	owner.pending = proposalOwner
	return &HelperPrepareFileProposal{owner: proposalOwner}, nil
}

// AcceptObservedFileObservation records canonical safe metadata from one
// already-inspected file packet. It owns no private bytes and does not stage,
// publish, or prove a filesystem object.
func (transaction *HelperPrepareTransaction) AcceptObservedFileObservation(correlation HelperPrepareTransactionCorrelation, observation HelperPrepareFileObservation) error {
	owner := helperPrepareTransactionLiveOwner(transaction)
	if owner == nil {
		return ErrHelperPrepareTransactionTerminal
	}
	observed := observation.owner
	if observed == nil {
		return ErrHelperPrepareFileObservation
	}
	observed.mu.Lock()
	defer observed.mu.Unlock()
	if observed.used {
		return ErrHelperPrepareFileObservationUsed
	}
	observed.used = true
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.terminal {
		return ErrHelperPrepareTransactionTerminal
	}
	if owner.committed {
		return ErrHelperPrepareTransactionCommitted
	}
	if !helperPrepareTransactionCorrelationEqual(owner.correlation, correlation) || owner.pending != nil || len(owner.acceptedFiles) >= len(owner.expectedFiles) {
		return owner.failLocked(ErrHelperPrepareTransactionCorrelation)
	}
	if observed.revision != owner.correlation.revision {
		return owner.failLocked(ErrHelperPrepareTransactionFile)
	}
	expected := owner.expectedFiles[len(owner.acceptedFiles)]
	actual := helperPrepareTransactionFileMetadata{bindingIndex: observed.bindingIndex, fileLength: observed.fileLength, fileSHA256: observed.fileSHA256}
	if actual != expected || uint64(actual.fileLength) > MaxHelperFileAggregateBytes-owner.acceptedBytes {
		return owner.failLocked(ErrHelperPrepareTransactionFile)
	}
	owner.acceptedFiles = append(owner.acceptedFiles, actual)
	owner.acceptedBytes += uint64(actual.fileLength)
	return nil
}

// CopyPrivateBytes copies the complete value into an exact-length destination
// without exposing an alias. Every denial wipes destination through capacity.
func (proposal *HelperPrepareFileProposal) CopyPrivateBytes(destination []byte) (int, error) {
	owner := helperPrepareFileProposalLiveOwner(proposal)
	if owner == nil {
		wipeHelperPrepareTransactionBytes(destination)
		return 0, ErrHelperPrepareFileProposalWiped
	}
	owner.transaction.mu.Lock()
	defer owner.transaction.mu.Unlock()
	if owner.wiped {
		wipeHelperPrepareTransactionBytes(destination)
		return 0, ErrHelperPrepareFileProposalWiped
	}
	if owner.consumed {
		wipeHelperPrepareTransactionBytes(destination)
		return 0, ErrHelperPrepareFileProposalConsumed
	}
	if len(destination) != len(owner.privateBytes) {
		wipeHelperPrepareTransactionBytes(destination)
		return 0, ErrHelperPrepareFileProposalDestination
	}
	wipeHelperPrepareTransactionBytes(destination)
	count := copy(destination, owner.privateBytes)
	wipeHelperPrepareTransactionBytes(owner.privateBytes)
	owner.privateBytes = nil
	owner.consumed = true
	return count, nil
}

// CommitStaged records only the already-validated file metadata and wipes the
// proposal immediately. The caller remains responsible for its unpublished
// external staging object; this pure method publishes no resource or proof.
func (proposal *HelperPrepareFileProposal) CommitStaged() error {
	proposalOwner := helperPrepareFileProposalLiveOwner(proposal)
	if proposalOwner == nil {
		return ErrHelperPrepareFileProposalWiped
	}
	owner := proposalOwner.transaction
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if proposalOwner.wiped {
		return ErrHelperPrepareFileProposalWiped
	}
	if owner.terminal {
		owner.wipeProposalLocked(proposalOwner)
		return ErrHelperPrepareTransactionTerminal
	}
	if owner.committed {
		owner.wipeProposalLocked(proposalOwner)
		return ErrHelperPrepareTransactionCommitted
	}
	if !proposalOwner.consumed {
		owner.failLocked(ErrHelperPrepareTransactionFile)
		return ErrHelperPrepareTransactionFile
	}
	if owner.pending != proposalOwner || len(owner.acceptedFiles) >= len(owner.expectedFiles) || proposalOwner.metadata != owner.expectedFiles[len(owner.acceptedFiles)] {
		owner.failLocked(ErrHelperPrepareTransactionFile)
		return ErrHelperPrepareTransactionFile
	}
	owner.acceptedFiles = append(owner.acceptedFiles, proposalOwner.metadata)
	owner.acceptedBytes += uint64(proposalOwner.metadata.fileLength)
	owner.wipeProposalLocked(proposalOwner)
	return nil
}

// Wipe discards the proposal without advancing transaction state, permitting
// the same exact file to be proposed after caller-owned staging rollback.
func (proposal *HelperPrepareFileProposal) Wipe() {
	proposalOwner := helperPrepareFileProposalLiveOwner(proposal)
	if proposalOwner == nil {
		return
	}
	owner := proposalOwner.transaction
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.wipeProposalLocked(proposalOwner)
}

func (proposal *HelperPrepareFileProposal) Wiped() bool {
	proposalOwner := helperPrepareFileProposalLiveOwner(proposal)
	if proposalOwner == nil {
		return true
	}
	owner := proposalOwner.transaction
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return proposalOwner.wiped
}

func (transaction *HelperPrepareTransaction) Commit(correlation HelperPrepareTransactionCorrelation, commit HelperPrepareCommitBody) (HelperPrepareTransactionResult, error) {
	owner := helperPrepareTransactionLiveOwner(transaction)
	if owner == nil {
		return HelperPrepareTransactionResult{}, ErrHelperPrepareTransactionTerminal
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.terminal {
		return HelperPrepareTransactionResult{}, ErrHelperPrepareTransactionTerminal
	}
	if owner.committed {
		return HelperPrepareTransactionResult{}, ErrHelperPrepareTransactionCommitted
	}
	if !helperPrepareTransactionCorrelationEqual(owner.correlation, correlation) {
		return HelperPrepareTransactionResult{}, owner.failLocked(ErrHelperPrepareTransactionCorrelation)
	}
	if commit.Revision != owner.correlation.revision || commit.ManifestSHA256 != owner.manifest || commit.ManifestSHA256 == [32]byte{} || owner.pending != nil || len(owner.acceptedFiles) != len(owner.expectedFiles) {
		return HelperPrepareTransactionResult{}, owner.failLocked(ErrHelperPrepareTransactionCommit)
	}
	for index := range owner.acceptedFiles {
		if owner.acceptedFiles[index] != owner.expectedFiles[index] {
			return HelperPrepareTransactionResult{}, owner.failLocked(ErrHelperPrepareTransactionCommit)
		}
	}
	result := helperPrepareTransactionResultState{
		manifestSHA256: owner.manifest, fileCount: uint16(len(owner.acceptedFiles)),
		transactionSHA256: computeHelperPrepareTransactionSHA256(owner.correlation, owner.manifest, owner.acceptedFiles),
	}
	owner.result = result
	owner.committed = true
	return HelperPrepareTransactionResult{state: result}, nil
}

func (transaction *HelperPrepareTransaction) Snapshot() HelperPrepareTransactionSnapshot {
	owner := helperPrepareTransactionLiveOwner(transaction)
	if owner == nil {
		return HelperPrepareTransactionSnapshot{Terminal: true}
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	snapshot := HelperPrepareTransactionSnapshot{
		Terminal: owner.terminal, Committed: owner.committed, PendingFile: owner.pending != nil,
		ExpectedFileCount: uint16(len(owner.expectedFiles)), AcceptedFileCount: uint16(len(owner.acceptedFiles)),
		AcceptedFileBytes: owner.acceptedBytes,
	}
	if len(owner.acceptedFiles) < len(owner.expectedFiles) {
		snapshot.HasNextFile = true
		snapshot.NextBindingIndex = owner.expectedFiles[len(owner.acceptedFiles)].bindingIndex
	}
	return snapshot
}

func (transaction *HelperPrepareTransaction) Terminal() bool {
	return transaction.Snapshot().Terminal
}

func (transaction *HelperPrepareTransaction) Committed() bool {
	return transaction.Snapshot().Committed
}

func (transaction *HelperPrepareTransaction) Close() {
	owner := helperPrepareTransactionLiveOwner(transaction)
	if owner == nil {
		return
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.terminal || owner.committed {
		return
	}
	owner.terminal = true
	if owner.pending != nil {
		owner.wipeProposalLocked(owner.pending)
	}
}

// Abort is the pure rollback decision for an uncommitted transaction. It is
// idempotent and has the same private-slot wipe semantics as Close.
func (transaction *HelperPrepareTransaction) Abort() {
	transaction.Close()
}

func (result HelperPrepareTransactionResult) ManifestSHA256() [32]byte {
	return result.state.manifestSHA256
}

func (result HelperPrepareTransactionResult) TransactionSHA256() [32]byte {
	return result.state.transactionSHA256
}

func (result HelperPrepareTransactionResult) FileCount() uint16 {
	return result.state.fileCount
}

func (owner *helperPrepareTransactionOwner) failLocked(err error) error {
	owner.terminal = true
	if owner.pending != nil {
		owner.wipeProposalLocked(owner.pending)
	}
	return err
}

func (owner *helperPrepareTransactionOwner) wipeProposalLocked(proposal *helperPrepareFileProposalOwner) {
	if proposal == nil || proposal.wiped {
		return
	}
	if owner.pending == proposal {
		owner.pending = nil
	}
	wipeHelperPrepareTransactionBytes(proposal.privateBytes)
	proposal.privateBytes = nil
	proposal.metadata = helperPrepareTransactionFileMetadata{}
	proposal.consumed = false
	proposal.wiped = true
}

func validHelperPrepareTransactionCorrelation(correlation HelperPrepareTransactionCorrelation) bool {
	return correlation.requestID != [16]byte{} && correlation.identityDigest != [32]byte{} && correlation.revision == 1 && correlation.expiryUnixNano > 0
}

func helperPrepareTransactionCorrelationEqual(left, right HelperPrepareTransactionCorrelation) bool {
	return left.requestID == right.requestID && left.identityDigest == right.identityDigest && left.revision == right.revision && left.expiryUnixNano == right.expiryUnixNano
}

func validHelperPrepareFileState(body *HelperPrepareFileBody) (*helperPrepareFileState, bool) {
	if body == nil || body.state == nil || body.state.wiped {
		return nil, false
	}
	state := body.state
	if state.revision != 1 || state.bindingIndex >= MaxHelperBindings || state.fileLength == 0 || state.fileLength > MaxHelperFileBytes ||
		int(state.fileLength) != len(state.privateBytes) || cap(state.privateBytes) != len(state.privateBytes) || state.fileSHA256 == [32]byte{} || sha256.Sum256(state.privateBytes) != state.fileSHA256 {
		return nil, false
	}
	return state, true
}

func computeHelperPrepareTransactionSHA256(correlation HelperPrepareTransactionCorrelation, manifest [32]byte, files []helperPrepareTransactionFileMetadata) [32]byte {
	hash := sha256.New()
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(helperPrepareTransactionDomain)))
	_, _ = hash.Write(u16[:])
	_, _ = hash.Write([]byte(helperPrepareTransactionDomain))
	_, _ = hash.Write(correlation.identityDigest[:])
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], correlation.revision)
	_, _ = hash.Write(u64[:])
	binary.BigEndian.PutUint64(u64[:], uint64(correlation.expiryUnixNano))
	_, _ = hash.Write(u64[:])
	_, _ = hash.Write(manifest[:])
	binary.BigEndian.PutUint16(u16[:], uint16(len(files)))
	_, _ = hash.Write(u16[:])
	for _, file := range files {
		binary.BigEndian.PutUint16(u16[:], file.bindingIndex)
		_, _ = hash.Write(u16[:])
		var u32 [4]byte
		binary.BigEndian.PutUint32(u32[:], file.fileLength)
		_, _ = hash.Write(u32[:])
		_, _ = hash.Write(file.fileSHA256[:])
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func helperPrepareTransactionLiveOwner(transaction *HelperPrepareTransaction) *helperPrepareTransactionOwner {
	if transaction == nil {
		return nil
	}
	return transaction.owner
}

func helperPrepareFileProposalLiveOwner(proposal *HelperPrepareFileProposal) *helperPrepareFileProposalOwner {
	if proposal == nil {
		return nil
	}
	return proposal.owner
}

func wipeHelperPrepareTransactionBytes(privateBytes []byte) {
	if privateBytes == nil {
		return
	}
	full := privateBytes[:cap(privateBytes)]
	clear(full)
	runtime.KeepAlive(full)
}
