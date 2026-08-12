package credentialprotocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
)

const (
	helperExecTransactionDomain = "hal/l8/guest-helper/exec-transaction/v1"
	helperExecTranscriptDomain  = "hal/l8/guest-helper/stdin-transcript/v1"
)

var (
	ErrHelperExecTransactionCorrelation    = errors.New("credential protocol helper exec transaction correlation is invalid")
	ErrHelperExecTransactionBegin          = errors.New("credential protocol helper exec transaction begin is invalid")
	ErrHelperExecTransactionPrivate        = errors.New("credential protocol helper exec transaction private input is invalid")
	ErrHelperExecTransactionCredit         = errors.New("credential protocol helper exec transaction stdin credit is invalid")
	ErrHelperExecTransactionStream         = errors.New("credential protocol helper exec transaction stdin stream is invalid")
	ErrHelperExecTransactionRecordCount    = errors.New("credential protocol helper exec transaction stdin record count is exhausted")
	ErrHelperExecTransactionIncomplete     = errors.New("credential protocol helper exec transaction is incomplete")
	ErrHelperExecTransactionResult         = errors.New("credential protocol helper exec transaction result is invalid")
	ErrHelperExecTransactionReplayMismatch = errors.New("credential protocol helper exec transaction replay does not match")
	ErrHelperExecTransactionTerminal       = errors.New("credential protocol helper exec transaction is terminal")
	ErrHelperExecTransactionCompleted      = errors.New("credential protocol helper exec transaction is completed")
	ErrHelperExecProposalWiped             = errors.New("credential protocol helper exec payload proposal is wiped")
	ErrHelperExecProposalConsumed          = errors.New("credential protocol helper exec payload proposal is consumed")
	ErrHelperExecProposalDestination       = errors.New("credential protocol helper exec payload proposal destination size is invalid")
	ErrHelperExecProposalComparisonOnly    = errors.New("credential protocol helper exec comparison payload cannot be copied")
	ErrHelperExecTransactionSerialization  = errors.New("credential protocol helper exec transaction serialization is denied")
)

// HelperExecTransactionCorrelation is the exact authenticated correlation for
// one logical exec transaction. RequestID is an idempotency key and is not
// included in the logical transaction digest.
type HelperExecTransactionCorrelation struct {
	requestID      [16]byte
	identityDigest [32]byte
	revision       uint64
}

// HelperExecTransaction owns pure input-correlation and digest state. It does
// not create a pipe, process, gate, descriptor, transport, or live resource.
type HelperExecTransaction struct {
	owner *helperExecTransactionOwner
}

type helperExecTransactionOwner struct {
	mu sync.Mutex

	correlation HelperExecTransactionCorrelation
	execBodySHA [32]byte
	privateLen  uint32
	privateSHA  [32]byte
	stdinMax    uint32

	stdinHash      *helperExecSHA256
	transcriptHash *helperExecSHA256
	execHash       *helperExecSHA256

	privateComplete bool
	credit          bool
	pending         *helperExecPayloadProposalOwner
	stdinOffset     uint64
	stdinBytes      uint64
	stdinRecords    uint32
	stdinEOF        bool
	stdinSHA        [32]byte
	transcriptSHA   [32]byte
	execSHA         [32]byte

	comparison bool
	cached     helperExecTransactionResultState
	terminal   bool
	completed  bool
}

type helperExecProposalKind uint8

const (
	helperExecProposalPrivate helperExecProposalKind = 1
	helperExecProposalStdin   helperExecProposalKind = 2
)

// HelperExecPayloadProposal owns the sole bounded mutable private/stdin slot.
// Value copies deliberately share consumption and wipe state.
type HelperExecPayloadProposal struct {
	owner *helperExecPayloadProposalOwner
}

type helperExecPayloadProposalOwner struct {
	transaction *helperExecTransactionOwner
	kind        helperExecProposalKind
	flags       HelperExecStreamFlags
	offset      uint64
	length      uint32
	sha256      [32]byte
	slot        []byte
	hashed      bool
	copied      bool
	committed   bool
	wiped       bool
}

// HelperExecTransactionSnapshot contains only safe scalar and digest state.
type HelperExecTransactionSnapshot struct {
	Terminal               bool
	Completed              bool
	ComparisonOnly         bool
	PrivateComplete        bool
	PendingPayload         bool
	StdinCreditOutstanding bool
	ReadyForLaunch         bool
	StdinEOF               bool
	StdinOffset            uint64
	StdinBytes             uint64
	StdinRecordCount       uint32
	StdinSHA256            [32]byte
	StdinTranscriptSHA256  [32]byte
	ExecTransactionSHA256  [32]byte
}

// HelperExecTransactionResult is one safe completed-cache entry. It contains
// correlation, digests, counters, and an independently cloned safe response.
type HelperExecTransactionResult struct {
	state helperExecTransactionResultState
}

type helperExecTransactionResultState struct {
	correlation      HelperExecTransactionCorrelation
	execBodySHA256   [32]byte
	privateLength    uint32
	privateSHA256    [32]byte
	stdinBytes       uint64
	stdinRecordCount uint32
	stdinSHA256      [32]byte
	transcriptSHA256 [32]byte
	execSHA256       [32]byte
	response         HelperResponseBody
	valid            bool
}

func NewHelperExecTransactionCorrelation(requestID [16]byte, identityDigest [32]byte, revision uint64) (HelperExecTransactionCorrelation, error) {
	if requestID == [16]byte{} || identityDigest == [32]byte{} || revision == 0 {
		return HelperExecTransactionCorrelation{}, ErrHelperExecTransactionCorrelation
	}
	return HelperExecTransactionCorrelation{requestID: requestID, identityDigest: identityDigest, revision: revision}, nil
}

func (correlation HelperExecTransactionCorrelation) RequestID() [16]byte {
	return correlation.requestID
}
func (correlation HelperExecTransactionCorrelation) IdentityDigest() [32]byte {
	return correlation.identityDigest
}
func (correlation HelperExecTransactionCorrelation) Revision() uint64 { return correlation.revision }

func NewHelperExecTransaction(correlation HelperExecTransactionCorrelation, body HelperExecBody) (*HelperExecTransaction, error) {
	return newHelperExecTransaction(correlation, body, false, helperExecTransactionResultState{})
}

// NewHelperExecComparisonTransaction starts a no-launch comparison replay of
// an exact completed request ID. It retains only safe cached metadata/result.
func NewHelperExecComparisonTransaction(correlation HelperExecTransactionCorrelation, body HelperExecBody, cached HelperExecTransactionResult) (*HelperExecTransaction, error) {
	if !cached.state.valid || !helperExecTransactionCorrelationEqual(correlation, cached.state.correlation) {
		return nil, ErrHelperExecTransactionCorrelation
	}
	transaction, err := newHelperExecTransaction(correlation, body, true, cached.state)
	if err != nil {
		return nil, err
	}
	owner := transaction.owner
	if subtle.ConstantTimeCompare(owner.execBodySHA[:], cached.state.execBodySHA256[:]) != 1 || owner.privateLen != cached.state.privateLength || subtle.ConstantTimeCompare(owner.privateSHA[:], cached.state.privateSHA256[:]) != 1 {
		return nil, owner.failLocked(ErrHelperExecTransactionReplayMismatch)
	}
	return transaction, nil
}

func newHelperExecTransaction(correlation HelperExecTransactionCorrelation, body HelperExecBody, comparison bool, cached helperExecTransactionResultState) (*HelperExecTransaction, error) {
	if !validHelperExecTransactionCorrelation(correlation) || body.Revision != correlation.revision {
		return nil, ErrHelperExecTransactionCorrelation
	}
	encoded, err := EncodeHelperExecBody(body)
	if err != nil {
		return nil, ErrHelperExecTransactionBegin
	}
	stdinHash := newHelperExecSHA256()
	transcriptHash := newHelperExecSHA256()
	writeHelperExecOpaque16(transcriptHash, helperExecTranscriptDomain)
	execHash := newHelperExecSHA256()
	writeHelperExecOpaque16(execHash, helperExecTransactionDomain)
	execHash.Write(correlation.identityDigest[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], correlation.revision)
	execHash.Write(scalar[:])
	binary.BigEndian.PutUint32(scalar[:4], uint32(len(encoded)))
	execHash.Write(scalar[:4])
	execHash.Write(encoded)
	binary.BigEndian.PutUint32(scalar[:4], body.PrivateBindingLength)
	execHash.Write(scalar[:4])
	execHash.Write(body.PrivateBindingSHA256[:])
	owner := &helperExecTransactionOwner{
		correlation:     correlation,
		execBodySHA:     sha256.Sum256(encoded),
		privateLen:      body.PrivateBindingLength,
		privateSHA:      body.PrivateBindingSHA256,
		stdinMax:        body.Plan.StdinMaxBytes,
		stdinHash:       stdinHash,
		transcriptHash:  transcriptHash,
		execHash:        execHash,
		privateComplete: body.PrivateBindingLength == 0,
		comparison:      comparison,
		cached:          cloneHelperExecResultState(cached),
	}
	return &HelperExecTransaction{owner: owner}, nil
}

// ProposePrivate validates and takes ownership of the exact one required
// private payload. Zero-private transactions forbid this transition.
func (transaction *HelperExecTransaction) ProposePrivate(correlation HelperExecTransactionCorrelation, body *HelperExecPrivateBody) (*HelperExecPayloadProposal, error) {
	owner := helperExecTransactionLiveOwner(transaction)
	if owner == nil {
		wipeHelperExecPrivateBody(body)
		return nil, ErrHelperExecTransactionTerminal
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	defer wipeHelperExecPrivateBody(body)
	if err := owner.admitLocked(correlation); err != nil {
		return nil, err
	}
	if owner.privateComplete || owner.privateLen == 0 || owner.pending != nil || owner.credit || owner.stdinRecords != 0 {
		return nil, owner.failLocked(ErrHelperExecTransactionPrivate)
	}
	state, err := helperExecPrivateLiveState(body)
	if err != nil || state.revision != owner.correlation.revision || state.privateBindingLength != owner.privateLen || subtle.ConstantTimeCompare(state.privateBindingSHA256[:], owner.privateSHA[:]) != 1 {
		return nil, owner.failLocked(ErrHelperExecTransactionPrivate)
	}
	length, digest := state.privateBindingLength, state.privateBindingSHA256
	payload := takeHelperExecPrivatePayload(state)
	proposal := &helperExecPayloadProposalOwner{
		transaction: owner,
		kind:        helperExecProposalPrivate,
		length:      length,
		sha256:      digest,
		slot:        payload,
	}
	if owner.comparison {
		proposal.hashed = true
		owner.wipeProposalSlotLocked(proposal)
	}
	owner.pending = proposal
	return &HelperExecPayloadProposal{owner: proposal}, nil
}

// GrantStdinCredit admits exactly one data-or-EOF record at the current
// offset. Credit never changes a content hash, transcript, or record count.
func (transaction *HelperExecTransaction) GrantStdinCredit(correlation HelperExecTransactionCorrelation, credit HelperExecCreditBody) error {
	owner := helperExecTransactionLiveOwner(transaction)
	if owner == nil {
		return ErrHelperExecTransactionTerminal
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.admitLocked(correlation); err != nil {
		return err
	}
	if !owner.privateComplete || owner.stdinEOF || owner.pending != nil || owner.credit || credit.Revision != owner.correlation.revision || credit.StreamKind != HelperExecStreamStdin || credit.NextOffset != owner.stdinOffset {
		return owner.failLocked(ErrHelperExecTransactionCredit)
	}
	owner.credit = true
	return nil
}

// ProposeStdin validates and owns one exact credited stdin record.
func (transaction *HelperExecTransaction) ProposeStdin(correlation HelperExecTransactionCorrelation, body *HelperExecStreamBody) (*HelperExecPayloadProposal, error) {
	owner := helperExecTransactionLiveOwner(transaction)
	if owner == nil {
		wipeHelperExecStreamBody(body)
		return nil, ErrHelperExecTransactionTerminal
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	defer wipeHelperExecStreamBody(body)
	if err := owner.admitLocked(correlation); err != nil {
		return nil, err
	}
	if !owner.privateComplete || owner.stdinEOF || owner.pending != nil || !owner.credit {
		return nil, owner.failLocked(ErrHelperExecTransactionCredit)
	}
	state, err := helperExecStreamLiveState(body)
	if err != nil || state.revision != owner.correlation.revision || state.streamKind != HelperExecStreamStdin || state.offset != owner.stdinOffset {
		return nil, owner.failLocked(ErrHelperExecTransactionStream)
	}
	if owner.stdinRecords == ^uint32(0) {
		return nil, owner.failLocked(ErrHelperExecTransactionRecordCount)
	}
	if state.flags == HelperExecStreamFlagsNone {
		if owner.stdinBytes > uint64(owner.stdinMax) || uint64(state.payloadLength) > uint64(owner.stdinMax)-owner.stdinBytes {
			return nil, owner.failLocked(ErrHelperExecTransactionStream)
		}
		if ^uint64(0)-owner.stdinOffset < uint64(state.payloadLength) {
			return nil, owner.failLocked(ErrHelperExecTransactionStream)
		}
	}
	flags, offset := state.flags, state.offset
	length, digest := state.payloadLength, state.payloadSHA256
	payload := takeHelperExecStreamPayload(state)
	proposal := &helperExecPayloadProposalOwner{
		transaction: owner,
		kind:        helperExecProposalStdin,
		flags:       flags,
		offset:      offset,
		length:      length,
		sha256:      digest,
		slot:        payload,
	}
	if owner.comparison {
		owner.hashProposalLocked(proposal)
		owner.wipeProposalSlotLocked(proposal)
	}
	owner.pending = proposal
	return &HelperExecPayloadProposal{owner: proposal}, nil
}

func (proposal *HelperExecPayloadProposal) PayloadLength() uint32 {
	owner := helperExecProposalLiveOwner(proposal)
	if owner == nil {
		return 0
	}
	owner.transaction.mu.Lock()
	defer owner.transaction.mu.Unlock()
	if owner.wiped {
		return 0
	}
	return owner.length
}

// CopyPayload transfers a normal proposal to an exact-length destination.
// Every denial clears destination through capacity. Comparison proposals can
// never disclose the replayed private/input bytes.
func (proposal *HelperExecPayloadProposal) CopyPayload(destination []byte) (int, error) {
	owner := helperExecProposalLiveOwner(proposal)
	if owner == nil {
		wipeHelperExecTransactionBytes(destination)
		return 0, ErrHelperExecProposalWiped
	}
	transaction := owner.transaction
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if owner.wiped || transaction.terminal {
		wipeHelperExecTransactionBytes(destination)
		return 0, ErrHelperExecProposalWiped
	}
	if transaction.comparison {
		wipeHelperExecTransactionBytes(destination)
		return 0, ErrHelperExecProposalComparisonOnly
	}
	if owner.copied {
		wipeHelperExecTransactionBytes(destination)
		return 0, ErrHelperExecProposalConsumed
	}
	if len(destination) != int(owner.length) {
		wipeHelperExecTransactionBytes(destination)
		return 0, transaction.failLocked(ErrHelperExecProposalDestination)
	}
	wipeHelperExecTransactionBytes(destination)
	count := copy(destination, owner.slot)
	if owner.kind == helperExecProposalStdin {
		transaction.hashProposalLocked(owner)
	}
	transaction.wipeProposalSlotLocked(owner)
	owner.copied = true
	return count, nil
}

// Commit advances only after a normal transfer, or after comparison-only
// in-place hashing. It never launches or publishes a resource.
func (proposal *HelperExecPayloadProposal) Commit() error {
	owner := helperExecProposalLiveOwner(proposal)
	if owner == nil {
		return ErrHelperExecProposalWiped
	}
	transaction := owner.transaction
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if owner.wiped || transaction.terminal {
		transaction.wipeProposalLocked(owner)
		return ErrHelperExecProposalWiped
	}
	if transaction.completed {
		transaction.wipeProposalLocked(owner)
		return ErrHelperExecTransactionCompleted
	}
	if transaction.pending != owner || owner.committed || (!transaction.comparison && !owner.copied) || (transaction.comparison && !owner.hashed) {
		return transaction.failLocked(ErrHelperExecProposalConsumed)
	}
	kind, flags, length := owner.kind, owner.flags, owner.length
	owner.committed = true
	transaction.wipeProposalLocked(owner)
	switch kind {
	case helperExecProposalPrivate:
		transaction.privateComplete = true
	case helperExecProposalStdin:
		transaction.credit = false
		transaction.stdinRecords++
		transaction.stdinBytes += uint64(length)
		transaction.stdinOffset += uint64(length)
		if flags == HelperExecStreamFlagEOF {
			transaction.stdinEOF = true
			transaction.finalizeInputLocked()
		}
	default:
		return transaction.failLocked(ErrHelperExecTransactionStream)
	}
	return nil
}

// Wipe abandons the sole proposal. Missing private/input is terminal and the
// transaction can never be resumed or launched afterward.
func (proposal *HelperExecPayloadProposal) Wipe() {
	owner := helperExecProposalLiveOwner(proposal)
	if owner == nil {
		return
	}
	transaction := owner.transaction
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if owner.wiped {
		return
	}
	_ = transaction.failLocked(ErrHelperExecProposalWiped)
}

func (proposal *HelperExecPayloadProposal) Wiped() bool {
	owner := helperExecProposalLiveOwner(proposal)
	if owner == nil {
		return true
	}
	owner.transaction.mu.Lock()
	defer owner.transaction.mu.Unlock()
	return owner.wiped
}

// Complete validates and caches one safe terminal exec response only after the
// unique EOF and exact digest construction are complete.
func (transaction *HelperExecTransaction) Complete(response HelperResponseBody) (HelperExecTransactionResult, error) {
	owner := helperExecTransactionLiveOwner(transaction)
	if owner == nil {
		return HelperExecTransactionResult{}, ErrHelperExecTransactionTerminal
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.terminal {
		return HelperExecTransactionResult{}, ErrHelperExecTransactionTerminal
	}
	if owner.completed {
		return HelperExecTransactionResult{}, ErrHelperExecTransactionCompleted
	}
	if owner.comparison {
		return HelperExecTransactionResult{}, owner.failLocked(ErrHelperExecTransactionResult)
	}
	if !owner.stdinEOF || owner.pending != nil || owner.credit {
		return HelperExecTransactionResult{}, ErrHelperExecTransactionIncomplete
	}
	if err := validateHelperExecTerminalResponse(response, owner); err != nil {
		return HelperExecTransactionResult{}, owner.failLocked(ErrHelperExecTransactionResult)
	}
	state := helperExecTransactionResultState{
		correlation:      owner.correlation,
		execBodySHA256:   owner.execBodySHA,
		privateLength:    owner.privateLen,
		privateSHA256:    owner.privateSHA,
		stdinBytes:       owner.stdinBytes,
		stdinRecordCount: owner.stdinRecords,
		stdinSHA256:      owner.stdinSHA,
		transcriptSHA256: owner.transcriptSHA,
		execSHA256:       owner.execSHA,
		response:         cloneHelperExecResponse(response),
		valid:            true,
	}
	owner.cached = cloneHelperExecResultState(state)
	owner.completed = true
	return HelperExecTransactionResult{state: cloneHelperExecResultState(state)}, nil
}

// ReplayResult returns only the cached safe response after an exact complete
// comparison. It never returns private, stdin, stdout, or stderr bytes.
func (transaction *HelperExecTransaction) ReplayResult() (HelperResponseBody, error) {
	owner := helperExecTransactionLiveOwner(transaction)
	if owner == nil {
		return HelperResponseBody{}, ErrHelperExecTransactionTerminal
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.terminal {
		return HelperResponseBody{}, ErrHelperExecTransactionTerminal
	}
	if owner.completed {
		return HelperResponseBody{}, ErrHelperExecTransactionCompleted
	}
	if !owner.comparison {
		return HelperResponseBody{}, owner.failLocked(ErrHelperExecTransactionResult)
	}
	if !owner.stdinEOF || owner.pending != nil || owner.credit {
		return HelperResponseBody{}, ErrHelperExecTransactionIncomplete
	}
	if !helperExecDigestsEqual(owner.execSHA, owner.cached.execSHA256) || owner.stdinBytes != owner.cached.stdinBytes || owner.stdinRecords != owner.cached.stdinRecordCount || !helperExecDigestsEqual(owner.stdinSHA, owner.cached.stdinSHA256) || !helperExecDigestsEqual(owner.transcriptSHA, owner.cached.transcriptSHA256) {
		return HelperResponseBody{}, owner.failLocked(ErrHelperExecTransactionReplayMismatch)
	}
	owner.completed = true
	return cloneHelperExecResponse(owner.cached.response), nil
}

func (transaction *HelperExecTransaction) Snapshot() HelperExecTransactionSnapshot {
	owner := helperExecTransactionLiveOwner(transaction)
	if owner == nil {
		return HelperExecTransactionSnapshot{Terminal: true}
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return HelperExecTransactionSnapshot{
		Terminal:               owner.terminal,
		Completed:              owner.completed,
		ComparisonOnly:         owner.comparison,
		PrivateComplete:        owner.privateComplete,
		PendingPayload:         owner.pending != nil,
		StdinCreditOutstanding: owner.credit,
		ReadyForLaunch:         owner.privateComplete && !owner.comparison && !owner.terminal && !owner.completed,
		StdinEOF:               owner.stdinEOF,
		StdinOffset:            owner.stdinOffset,
		StdinBytes:             owner.stdinBytes,
		StdinRecordCount:       owner.stdinRecords,
		StdinSHA256:            owner.stdinSHA,
		StdinTranscriptSHA256:  owner.transcriptSHA,
		ExecTransactionSHA256:  owner.execSHA,
	}
}

func (transaction *HelperExecTransaction) Terminal() bool  { return transaction.Snapshot().Terminal }
func (transaction *HelperExecTransaction) Completed() bool { return transaction.Snapshot().Completed }

func (transaction *HelperExecTransaction) Close() {
	owner := helperExecTransactionLiveOwner(transaction)
	if owner == nil {
		return
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.completed || owner.terminal {
		return
	}
	_ = owner.failLocked(ErrHelperExecTransactionTerminal)
}

func (result HelperExecTransactionResult) RequestID() [16]byte {
	return result.state.correlation.requestID
}
func (result HelperExecTransactionResult) IdentityDigest() [32]byte {
	return result.state.correlation.identityDigest
}
func (result HelperExecTransactionResult) Revision() uint64   { return result.state.correlation.revision }
func (result HelperExecTransactionResult) StdinBytes() uint64 { return result.state.stdinBytes }
func (result HelperExecTransactionResult) StdinRecordCount() uint32 {
	return result.state.stdinRecordCount
}
func (result HelperExecTransactionResult) StdinSHA256() [32]byte { return result.state.stdinSHA256 }
func (result HelperExecTransactionResult) StdinTranscriptSHA256() [32]byte {
	return result.state.transcriptSHA256
}
func (result HelperExecTransactionResult) ExecTransactionSHA256() [32]byte {
	return result.state.execSHA256
}
func (result HelperExecTransactionResult) Response() HelperResponseBody {
	return cloneHelperExecResponse(result.state.response)
}

func (owner *helperExecTransactionOwner) admitLocked(correlation HelperExecTransactionCorrelation) error {
	if owner.terminal {
		return ErrHelperExecTransactionTerminal
	}
	if owner.completed {
		return ErrHelperExecTransactionCompleted
	}
	if !helperExecTransactionCorrelationEqual(owner.correlation, correlation) {
		return owner.failLocked(ErrHelperExecTransactionCorrelation)
	}
	return nil
}

func (owner *helperExecTransactionOwner) hashProposalLocked(proposal *helperExecPayloadProposalOwner) {
	if proposal == nil || proposal.hashed || proposal.kind != helperExecProposalStdin {
		return
	}
	if proposal.flags == HelperExecStreamFlagsNone {
		owner.stdinHash.Write(proposal.slot)
	}
	owner.transcriptHash.Write([]byte{byte(proposal.flags)})
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], proposal.offset)
	owner.transcriptHash.Write(scalar[:])
	binary.BigEndian.PutUint32(scalar[:4], proposal.length)
	owner.transcriptHash.Write(scalar[:4])
	owner.transcriptHash.Write(proposal.sha256[:])
	owner.transcriptHash.Write(proposal.slot)
	proposal.hashed = true
}

func (owner *helperExecTransactionOwner) finalizeInputLocked() {
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], owner.stdinRecords)
	owner.transcriptHash.Write(count[:])
	owner.stdinSHA = owner.stdinHash.Sum256()
	owner.transcriptSHA = owner.transcriptHash.Sum256()
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], owner.stdinBytes)
	owner.execHash.Write(scalar[:])
	owner.execHash.Write(owner.stdinSHA[:])
	owner.execHash.Write(owner.transcriptSHA[:])
	owner.execSHA = owner.execHash.Sum256()
	owner.clearHashesLocked()
}

func (owner *helperExecTransactionOwner) failLocked(err error) error {
	owner.terminal = true
	owner.credit = false
	if owner.pending != nil {
		owner.wipeProposalLocked(owner.pending)
	}
	owner.clearHashesLocked()
	return err
}

func (owner *helperExecTransactionOwner) clearHashesLocked() {
	if owner.stdinHash != nil {
		owner.stdinHash.Wipe()
		owner.stdinHash = nil
	}
	if owner.transcriptHash != nil {
		owner.transcriptHash.Wipe()
		owner.transcriptHash = nil
	}
	if owner.execHash != nil {
		owner.execHash.Wipe()
		owner.execHash = nil
	}
}

func (owner *helperExecTransactionOwner) wipeProposalLocked(proposal *helperExecPayloadProposalOwner) {
	if proposal == nil || proposal.wiped {
		return
	}
	owner.wipeProposalSlotLocked(proposal)
	if owner.pending == proposal {
		owner.pending = nil
	}
	proposal.kind = 0
	proposal.flags = 0
	proposal.offset = 0
	proposal.length = 0
	proposal.sha256 = [32]byte{}
	proposal.hashed = false
	proposal.copied = false
	proposal.wiped = true
}

func (owner *helperExecTransactionOwner) wipeProposalSlotLocked(proposal *helperExecPayloadProposalOwner) {
	if proposal == nil || proposal.slot == nil {
		return
	}
	wipeHelperExecTransactionBytes(proposal.slot)
	proposal.slot = nil
}

func validateHelperExecTerminalResponse(response HelperResponseBody, owner *helperExecTransactionOwner) error {
	if response.RequestType != PacketTypeExec || response.Revision != owner.correlation.revision {
		return ErrHelperExecTransactionResult
	}
	if _, err := EncodeHelperResponseBody(response); err != nil {
		return ErrHelperExecTransactionResult
	}
	if response.Disposition == ResponseDispositionAccepted {
		if response.Exec == nil || response.Exec.StdinBytes != owner.stdinBytes || !helperExecDigestsEqual(response.Exec.StdinSHA256, owner.stdinSHA) || !helperExecDigestsEqual(response.Exec.ExecTransactionSHA256, owner.execSHA) {
			return ErrHelperExecTransactionResult
		}
	}
	return nil
}

func cloneHelperExecResponse(response HelperResponseBody) HelperResponseBody {
	cloned := response
	if response.Prepare != nil {
		value := *response.Prepare
		value.BindingProofs = append([]HelperBindingProof(nil), response.Prepare.BindingProofs...)
		cloned.Prepare = &value
	}
	if response.Renew != nil {
		value := *response.Renew
		cloned.Renew = &value
	}
	if response.Revoke != nil {
		value := *response.Revoke
		cloned.Revoke = &value
	}
	if response.Exec != nil {
		value := *response.Exec
		cloned.Exec = &value
	}
	return cloned
}

func cloneHelperExecResultState(state helperExecTransactionResultState) helperExecTransactionResultState {
	state.response = cloneHelperExecResponse(state.response)
	return state
}

func validHelperExecTransactionCorrelation(correlation HelperExecTransactionCorrelation) bool {
	return correlation.requestID != [16]byte{} && correlation.identityDigest != [32]byte{} && correlation.revision != 0
}

func helperExecTransactionCorrelationEqual(left, right HelperExecTransactionCorrelation) bool {
	return left.requestID == right.requestID && left.identityDigest == right.identityDigest && left.revision == right.revision
}

func helperExecDigestsEqual(left, right [32]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func writeHelperExecOpaque16(destination *helperExecSHA256, value string) {
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(value)))
	destination.Write(size[:])
	destination.Write([]byte(value))
}

func helperExecTransactionLiveOwner(transaction *HelperExecTransaction) *helperExecTransactionOwner {
	if transaction == nil {
		return nil
	}
	return transaction.owner
}

func helperExecProposalLiveOwner(proposal *HelperExecPayloadProposal) *helperExecPayloadProposalOwner {
	if proposal == nil {
		return nil
	}
	return proposal.owner
}

func wipeHelperExecPrivateBody(body *HelperExecPrivateBody) {
	if body != nil {
		body.Wipe()
	}
}

func takeHelperExecPrivatePayload(state *helperExecPrivateState) []byte {
	payload := state.privateBinding
	state.privateBinding = nil
	state.revision = 0
	state.privateBindingLength = 0
	state.privateBindingSHA256 = [32]byte{}
	state.wiped = true
	return payload
}

func wipeHelperExecStreamBody(body *HelperExecStreamBody) {
	if body != nil {
		body.Wipe()
	}
}

func takeHelperExecStreamPayload(state *helperExecStreamState) []byte {
	payload := state.payload
	state.payload = nil
	state.revision = 0
	state.streamKind = 0
	state.flags = 0
	state.offset = 0
	state.payloadLength = 0
	state.payloadSHA256 = [32]byte{}
	state.wiped = true
	return payload
}

func wipeHelperExecTransactionBytes(value []byte) {
	if value == nil {
		return
	}
	full := value[:cap(value)]
	clear(full)
	runtime.KeepAlive(full)
}
