package credentialprotocol

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/jywlabs/hal/internal/credentialmemory"
)

var (
	ErrHelperExecPrivateObservation       = errors.New("credential protocol helper exec private observation is invalid")
	ErrHelperExecPrivateObservationUsed   = errors.New("credential protocol helper exec private observation is already used")
	ErrHelperExecStreamObservation        = errors.New("credential protocol helper exec stream observation is invalid")
	ErrHelperExecStreamObservationUsed    = errors.New("credential protocol helper exec stream observation is already used")
	ErrHelperExecObservationSerialization = errors.New("credential protocol helper exec observation serialization is denied")
)

// HelperExecPrivateObservation is a copy-safe, one-use handle to canonical
// private-input metadata. It never owns or exposes the private input.
type HelperExecPrivateObservation struct {
	owner *helperExecPrivateObservationOwner
}

type helperExecPrivateObservationOwner struct {
	mu            sync.Mutex
	revision      uint64
	privateLength uint32
	privateSHA256 [32]byte
	used          bool
}

// HelperExecStreamObservation is a copy-safe, one-use handle to canonical
// stdin metadata. It never owns or exposes the stdin payload.
type HelperExecStreamObservation struct {
	owner *helperExecStreamObservationOwner
}

type helperExecStreamObservationOwner struct {
	mu            sync.Mutex
	revision      uint64
	streamKind    HelperExecStreamKind
	flags         HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
	used          bool
}

type helperExecObservedStdinSink struct {
	mu         sync.Mutex
	stdin      *helperExecSHA256
	transcript *helperExecSHA256
	expected   uint32
	calls      uint32
	digest     [32]byte
	valid      bool
}

type helperExecObservedStdinCleanup struct {
	candidateStdinHash      *helperExecSHA256
	candidateTranscriptHash *helperExecSHA256
	external                bool
}

func NewHelperExecPrivateObservation(revision uint64, privateLength uint32, privateSHA256, observedSHA256 [32]byte) (HelperExecPrivateObservation, error) {
	if revision == 0 || privateLength == 0 || privateLength > MaxHelperExecPrivateBytes || privateSHA256 == [32]byte{} || !helperExecDigestsEqual(privateSHA256, observedSHA256) {
		return HelperExecPrivateObservation{}, ErrHelperExecPrivateObservation
	}
	return HelperExecPrivateObservation{owner: &helperExecPrivateObservationOwner{revision: revision, privateLength: privateLength, privateSHA256: privateSHA256}}, nil
}

func NewHelperExecStreamObservation(revision uint64, streamKind HelperExecStreamKind, flags HelperExecStreamFlags, offset uint64, payloadLength uint32, payloadSHA256, observedSHA256 [32]byte) (HelperExecStreamObservation, error) {
	emptySHA256 := sha256.Sum256(nil)
	if revision == 0 || streamKind != HelperExecStreamStdin || (flags != HelperExecStreamFlagsNone && flags != HelperExecStreamFlagEOF) || payloadLength > MaxHelperExecStreamPayloadBytes || offset > ^uint64(0)-uint64(payloadLength) {
		return HelperExecStreamObservation{}, ErrHelperExecStreamObservation
	}
	if flags == HelperExecStreamFlagEOF {
		if payloadLength != 0 || payloadSHA256 != emptySHA256 {
			return HelperExecStreamObservation{}, ErrHelperExecStreamObservation
		}
	} else if payloadLength == 0 || payloadSHA256 == [32]byte{} {
		return HelperExecStreamObservation{}, ErrHelperExecStreamObservation
	}
	if !helperExecDigestsEqual(payloadSHA256, observedSHA256) {
		return HelperExecStreamObservation{}, ErrHelperExecStreamObservation
	}
	return HelperExecStreamObservation{owner: &helperExecStreamObservationOwner{
		revision: revision, streamKind: streamKind, flags: flags, offset: offset,
		payloadLength: payloadLength, payloadSHA256: payloadSHA256,
	}}, nil
}

func (transaction *HelperExecTransaction) ProposeObservedPrivate(correlation HelperExecTransactionCorrelation, observation HelperExecPrivateObservation) (_ *HelperExecPayloadProposal, result error) {
	if observation.owner == nil {
		return nil, ErrHelperExecPrivateObservation
	}
	observation.owner.mu.Lock()
	defer observation.owner.mu.Unlock()
	if !validHelperExecPrivateObservationOwner(observation.owner) {
		return nil, ErrHelperExecPrivateObservation
	}
	if observation.owner.used {
		return nil, ErrHelperExecPrivateObservationUsed
	}
	observation.owner.used = true
	if transaction == nil || transaction.owner == nil {
		return nil, ErrHelperExecTransactionTerminal
	}
	transaction.owner.mu.Lock()
	defer transaction.owner.mu.Unlock()
	defer helperExecObservedLockedFailure(transaction.owner, &result)
	if transaction.owner.terminal {
		return nil, ErrHelperExecTransactionTerminal
	}
	if transaction.owner.completed {
		return nil, ErrHelperExecTransactionCompleted
	}
	if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) {
		return nil, ErrHelperExecTransactionCorrelation
	}
	if transaction.owner.privateComplete || transaction.owner.privateLen == 0 || transaction.owner.pending != nil || transaction.owner.credit || transaction.owner.stdinRecords != 0 {
		return nil, ErrHelperExecTransactionPrivate
	}
	if observation.owner.revision != transaction.owner.correlation.revision || observation.owner.privateLength != transaction.owner.privateLen || !helperExecDigestsEqual(observation.owner.privateSHA256, transaction.owner.privateSHA) {
		return nil, ErrHelperExecTransactionPrivate
	}
	proposalOwner := &helperExecPayloadProposalOwner{
		transaction: transaction.owner, source: helperExecProposalSourceObserved,
		kind: helperExecProposalPrivate, length: observation.owner.privateLength,
		sha256: observation.owner.privateSHA256, observedReady: true,
	}
	transaction.owner.pending = proposalOwner
	return &HelperExecPayloadProposal{owner: proposalOwner}, nil
}

func (transaction *HelperExecTransaction) ProposeObservedStdin(ctx context.Context, correlation HelperExecTransactionCorrelation, observation HelperExecStreamObservation, view credentialmemory.BorrowedView) (proposal *HelperExecPayloadProposal, err error) {
	if ctx == nil || !configuredDependency(ctx) || view == nil || !configuredDependency(view) {
		return nil, ErrHelperExecTransactionStream
	}
	if observation.owner == nil {
		return nil, ErrHelperExecStreamObservation
	}
	observation.owner.mu.Lock()
	defer observation.owner.mu.Unlock()
	if !validHelperExecStreamObservationOwner(observation.owner) {
		return nil, ErrHelperExecStreamObservation
	}
	if observation.owner.used {
		return nil, ErrHelperExecStreamObservationUsed
	}
	observation.owner.used = true
	if transaction == nil || transaction.owner == nil {
		return nil, ErrHelperExecTransactionTerminal
	}
	cleanup := &helperExecObservedStdinCleanup{}
	defer cleanup.finish(transaction.owner, &err)
	defer cleanup.recoverExternal(&proposal, &err)
	transaction.owner.mu.Lock()
	if transaction.owner.terminal {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionTerminal
	}
	if transaction.owner.completed {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionCompleted
	}
	if !helperExecTransactionCorrelationEqual(correlation, transaction.owner.correlation) {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionCorrelation
	}
	if !transaction.owner.privateComplete || transaction.owner.stdinEOF || transaction.owner.pending != nil || !transaction.owner.credit {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionCredit
	}
	if observation.owner.revision != transaction.owner.correlation.revision || observation.owner.streamKind != HelperExecStreamStdin || (observation.owner.flags != HelperExecStreamFlagsNone && observation.owner.flags != HelperExecStreamFlagEOF) || observation.owner.offset != transaction.owner.stdinOffset {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionStream
	}
	if transaction.owner.stdinRecords == ^uint32(0) {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionRecordCount
	}
	if observation.owner.flags == HelperExecStreamFlagsNone && (transaction.owner.stdinBytes > uint64(transaction.owner.stdinMax) || uint64(observation.owner.payloadLength) > uint64(transaction.owner.stdinMax)-transaction.owner.stdinBytes || ^uint64(0)-transaction.owner.stdinOffset < uint64(observation.owner.payloadLength)) {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionStream
	}
	currentStdinHash := transaction.owner.stdinHash
	currentTranscriptHash := transaction.owner.transcriptHash
	candidateStdinHash := cloneHelperExecSHA256(transaction.owner.stdinHash)
	candidateTranscriptHash := cloneHelperExecSHA256(transaction.owner.transcriptHash)
	cleanup.candidateStdinHash = candidateStdinHash
	cleanup.candidateTranscriptHash = candidateTranscriptHash
	candidateStdinOffset := transaction.owner.stdinOffset + uint64(observation.owner.payloadLength)
	candidateStdinBytes := transaction.owner.stdinBytes + uint64(observation.owner.payloadLength)
	candidateStdinRecords := transaction.owner.stdinRecords + 1
	candidateStdinEOF := observation.owner.flags == HelperExecStreamFlagEOF
	if candidateStdinHash == nil || candidateTranscriptHash == nil {
		transaction.owner.mu.Unlock()
		return nil, ErrHelperExecTransactionStream
	}
	candidateTranscriptHash.Write([]byte{byte(observation.owner.flags)})
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], observation.owner.offset)
	candidateTranscriptHash.Write(scalar[:])
	binary.BigEndian.PutUint32(scalar[:4], observation.owner.payloadLength)
	candidateTranscriptHash.Write(scalar[:4])
	candidateTranscriptHash.Write(observation.owner.payloadSHA256[:])
	sink := newHelperExecObservedStdinSink(candidateStdinHash, candidateTranscriptHash)
	sink.expected = observation.owner.payloadLength
	transaction.owner.mu.Unlock()

	if ctx.Err() != nil {
		return nil, ErrHelperExecTransactionStream
	}
	cleanup.external = true
	if view.Len() != int(observation.owner.payloadLength) {
		cleanup.external = false
		return nil, ErrHelperExecTransactionStream
	}
	writeErr := view.WriteTo(ctx, sink)
	cleanup.external = false
	if writeErr != nil || ctx.Err() != nil || !sink.complete() {
		return nil, ErrHelperExecTransactionStream
	}

	transaction.owner.mu.Lock()
	defer transaction.owner.mu.Unlock()
	if transaction.owner.terminal || transaction.owner.completed || transaction.owner.pending != nil || !transaction.owner.credit || transaction.owner.stdinEOF || transaction.owner.stdinOffset != observation.owner.offset || transaction.owner.stdinHash != currentStdinHash || transaction.owner.transcriptHash != currentTranscriptHash {
		return nil, ErrHelperExecTransactionStream
	}
	observedDigest := sink.Sum256()
	if !helperExecDigestsEqual(observation.owner.payloadSHA256, observedDigest) {
		return nil, ErrHelperExecTransactionStream
	}
	proposalOwner := &helperExecPayloadProposalOwner{
		transaction: transaction.owner, source: helperExecProposalSourceObserved,
		kind: helperExecProposalStdin, flags: observation.owner.flags,
		offset: observation.owner.offset, length: observation.owner.payloadLength,
		sha256:             observation.owner.payloadSHA256,
		candidateStdinHash: candidateStdinHash, candidateTranscriptHash: candidateTranscriptHash,
		candidateStdinOffset: candidateStdinOffset, candidateStdinBytes: candidateStdinBytes,
		candidateStdinRecords: candidateStdinRecords, candidateStdinEOF: candidateStdinEOF,
		observedReady: true,
	}
	transaction.owner.pending = proposalOwner
	return &HelperExecPayloadProposal{owner: proposalOwner}, nil
}

func validHelperExecPrivateObservationOwner(owner *helperExecPrivateObservationOwner) bool {
	return owner != nil && owner.revision != 0 && owner.privateLength != 0 && owner.privateLength <= MaxHelperExecPrivateBytes && owner.privateSHA256 != [32]byte{}
}

func validHelperExecStreamObservationOwner(owner *helperExecStreamObservationOwner) bool {
	if owner == nil || owner.revision == 0 || owner.streamKind != HelperExecStreamStdin || (owner.flags != HelperExecStreamFlagsNone && owner.flags != HelperExecStreamFlagEOF) || owner.payloadLength > MaxHelperExecStreamPayloadBytes || owner.offset > ^uint64(0)-uint64(owner.payloadLength) {
		return false
	}
	if owner.flags == HelperExecStreamFlagEOF {
		return owner.payloadLength == 0 && owner.payloadSHA256 == sha256.Sum256(nil)
	}
	return owner.payloadLength != 0 && owner.payloadSHA256 != [32]byte{}
}

func helperExecConfiguredDependencyNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func configuredDependency(value any) bool {
	return !helperExecConfiguredDependencyNil(value)
}

func cloneHelperExecSHA256(owner *helperExecSHA256) *helperExecSHA256 {
	if owner == nil {
		return nil
	}
	clone := *owner
	return &clone
}

func newHelperExecObservedStdinSink(stdin, transcript *helperExecSHA256) *helperExecObservedStdinSink {
	return &helperExecObservedStdinSink{stdin: stdin, transcript: transcript}
}

func (sink *helperExecObservedStdinSink) MaxCredentialBytes() int {
	return MaxHelperExecStreamPayloadBytes
}

func (sink *helperExecObservedStdinSink) WriteCredential(payload []byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.calls++
	if sink.calls != 1 || sink.stdin == nil || sink.transcript == nil || len(payload) != int(sink.expected) || len(payload) > MaxHelperExecStreamPayloadBytes {
		sink.valid = false
		return ErrHelperExecTransactionStream
	}
	sink.stdin.Write(payload)
	sink.transcript.Write(payload)
	sink.digest = sha256.Sum256(payload)
	sink.valid = true
	return nil
}

func (sink *helperExecObservedStdinSink) Sum256() [32]byte {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.digest
}

func (sink *helperExecObservedStdinSink) complete() bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.calls == 1 && sink.valid
}

func helperExecObservedLockedFailure(owner *helperExecTransactionOwner, result *error) {
	if result != nil && *result != nil && !errors.Is(*result, ErrHelperExecTransactionTerminal) && !errors.Is(*result, ErrHelperExecTransactionCompleted) {
		_ = owner.failLocked(*result)
	}
}

func (cleanup *helperExecObservedStdinCleanup) finish(owner *helperExecTransactionOwner, result *error) {
	if cleanup == nil || owner == nil || result == nil || *result == nil {
		return
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	wipeHelperExecObservedCandidateHashes(cleanup.candidateStdinHash, cleanup.candidateTranscriptHash)
	if !errors.Is(*result, ErrHelperExecTransactionTerminal) && !errors.Is(*result, ErrHelperExecTransactionCompleted) {
		_ = owner.failLocked(*result)
	}
}

func (cleanup *helperExecObservedStdinCleanup) recoverExternal(proposal **HelperExecPayloadProposal, result *error) {
	panicValue := recover()
	if panicValue == nil {
		return
	}
	if cleanup == nil || !cleanup.external {
		panic(panicValue)
	}
	*proposal = nil
	*result = ErrHelperExecTransactionStream
}

func wipeHelperExecObservedCandidateHashes(stdin, transcript *helperExecSHA256) {
	if stdin != nil {
		stdin.Wipe()
	}
	if transcript != nil {
		transcript.Wipe()
	}
}

func helperExecObservationFormat(state fmt.State, name string) {
	_, _ = state.Write([]byte("<credentialprotocol." + name + ">"))
}

func (HelperExecPrivateObservation) String() string {
	return "<credentialprotocol.HelperExecPrivateObservation>"
}
func (HelperExecPrivateObservation) GoString() string {
	return "<credentialprotocol.HelperExecPrivateObservation>"
}
func (HelperExecPrivateObservation) Format(state fmt.State, _ rune) {
	helperExecObservationFormat(state, "HelperExecPrivateObservation")
}
func (HelperExecPrivateObservation) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecObservationSerialization
}
func (HelperExecPrivateObservation) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecObservationSerialization
}
func (HelperExecPrivateObservation) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecObservationSerialization
}
func (*HelperExecPrivateObservation) UnmarshalJSON([]byte) error {
	return ErrHelperExecObservationSerialization
}
func (*HelperExecPrivateObservation) UnmarshalText([]byte) error {
	return ErrHelperExecObservationSerialization
}
func (*HelperExecPrivateObservation) UnmarshalBinary([]byte) error {
	return ErrHelperExecObservationSerialization
}

func (HelperExecStreamObservation) String() string {
	return "<credentialprotocol.HelperExecStreamObservation>"
}
func (HelperExecStreamObservation) GoString() string {
	return "<credentialprotocol.HelperExecStreamObservation>"
}
func (HelperExecStreamObservation) Format(state fmt.State, _ rune) {
	helperExecObservationFormat(state, "HelperExecStreamObservation")
}
func (HelperExecStreamObservation) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperExecObservationSerialization
}
func (HelperExecStreamObservation) MarshalText() ([]byte, error) {
	return nil, ErrHelperExecObservationSerialization
}
func (HelperExecStreamObservation) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperExecObservationSerialization
}
func (*HelperExecStreamObservation) UnmarshalJSON([]byte) error {
	return ErrHelperExecObservationSerialization
}
func (*HelperExecStreamObservation) UnmarshalText([]byte) error {
	return ErrHelperExecObservationSerialization
}
func (*HelperExecStreamObservation) UnmarshalBinary([]byte) error {
	return ErrHelperExecObservationSerialization
}
