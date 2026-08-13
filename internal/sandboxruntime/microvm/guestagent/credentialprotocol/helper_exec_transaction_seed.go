package credentialprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"sync"
)

// HelperExecTransactionSeed is a shared one-use owner for an initialized exec
// transcript. It retains no canonical body or plan bytes.
type HelperExecTransactionSeed struct {
	owner *helperExecTransactionSeedOwner
}

type helperExecTransactionSeedOwner struct {
	mu sync.Mutex

	correlation    HelperExecTransactionCorrelation
	execBodyLength uint32
	execBodySHA256 [32]byte
	privateLength  uint32
	privateSHA256  [32]byte
	stdinMaxBytes  uint32
	execHash       *helperExecSHA256
	consumed       bool
	closed         bool
}

func NewHelperExecTransactionSeed(correlation HelperExecTransactionCorrelation, body HelperExecBody) (HelperExecTransactionSeed, error) {
	if !validHelperExecTransactionCorrelation(correlation) || body.Revision != correlation.revision {
		return HelperExecTransactionSeed{}, ErrHelperExecTransactionCorrelation
	}
	canonical, err := EncodeHelperExecBody(body)
	if err != nil {
		return HelperExecTransactionSeed{}, ErrHelperExecTransactionBegin
	}
	defer func() {
		clear(canonical[:cap(canonical)])
		runtime.KeepAlive(canonical)
	}()
	temporaryExecHash := newHelperExecSHA256()
	writeHelperExecOpaque16(temporaryExecHash, helperExecTransactionDomain)
	temporaryExecHash.Write(correlation.identityDigest[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], correlation.revision)
	temporaryExecHash.Write(scalar[:])
	binary.BigEndian.PutUint32(scalar[:4], uint32(len(canonical)))
	temporaryExecHash.Write(scalar[:4])
	temporaryExecHash.Write(canonical)
	binary.BigEndian.PutUint32(scalar[:4], body.PrivateBindingLength)
	temporaryExecHash.Write(scalar[:4])
	temporaryExecHash.Write(body.PrivateBindingSHA256[:])
	clonedExecHash := *temporaryExecHash
	temporaryExecHash.Wipe()
	return HelperExecTransactionSeed{owner: &helperExecTransactionSeedOwner{
		correlation: correlation, execBodyLength: uint32(len(canonical)), execBodySHA256: sha256.Sum256(canonical),
		privateLength: body.PrivateBindingLength, privateSHA256: body.PrivateBindingSHA256,
		stdinMaxBytes: body.Plan.StdinMaxBytes, execHash: &clonedExecHash,
	}}, nil
}

func (seed *HelperExecTransactionSeed) Begin() (*HelperExecTransaction, error) {
	return seed.begin(HelperExecTransactionResult{}, false)
}

func (seed *HelperExecTransactionSeed) BeginComparison(cached HelperExecTransactionResult) (*HelperExecTransaction, error) {
	return seed.begin(cached, true)
}

func (seed *HelperExecTransactionSeed) begin(cached HelperExecTransactionResult, comparison bool) (*HelperExecTransaction, error) {
	if seed == nil || seed.owner == nil {
		return nil, ErrHelperExecTransactionBegin
	}
	owner := seed.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.consumed || owner.execHash == nil {
		return nil, ErrHelperExecTransactionBegin
	}
	if comparison {
		if !validHelperExecCachedResultAgainstSeed(cached.state, owner) {
			return nil, ErrHelperExecTransactionResult
		}
	}
	transactionOwner := &helperExecTransactionOwner{
		correlation: owner.correlation, execBodySHA: owner.execBodySHA256,
		privateLen: owner.privateLength, privateSHA: owner.privateSHA256, stdinMax: owner.stdinMaxBytes,
		stdinHash: newHelperExecSHA256(), transcriptHash: newHelperExecSHA256(), execHash: owner.execHash,
		privateComplete: owner.privateLength == 0, comparison: comparison, cached: cloneHelperExecResultState(cached.state),
	}
	writeHelperExecOpaque16(transactionOwner.transcriptHash, helperExecTranscriptDomain)
	owner.execHash = nil
	owner.consumed = true
	owner.wipeLocked()
	return &HelperExecTransaction{owner: transactionOwner}, nil
}

func validHelperExecCachedResultAgainstSeed(cached helperExecTransactionResultState, seed *helperExecTransactionSeedOwner) bool {
	if !cached.valid || !helperExecTransactionCorrelationEqual(seed.correlation, cached.correlation) ||
		seed.execBodyLength == 0 || seed.execBodyLength > MaxHelperPacketBodyBytes ||
		!helperExecDigestsEqual(seed.execBodySHA256, cached.execBodySHA256) || seed.privateLength != cached.privateLength ||
		!helperExecDigestsEqual(seed.privateSHA256, cached.privateSHA256) || cached.stdinBytes > MaxHelperExecStreamAggregateBytes ||
		cached.stdinRecordCount == 0 || cached.transcriptSHA256 == ([32]byte{}) || cached.execSHA256 == ([32]byte{}) {
		return false
	}
	if cached.stdinBytes == 0 {
		if cached.stdinSHA256 != sha256.Sum256(nil) {
			return false
		}
	} else if cached.stdinSHA256 == ([32]byte{}) {
		return false
	}
	resultOwner := &helperExecTransactionOwner{
		correlation: seed.correlation,
		stdinBytes:  cached.stdinBytes,
		stdinSHA:    cached.stdinSHA256,
		execSHA:     cached.execSHA256,
	}
	return validateHelperExecTerminalResponse(cached.response, resultOwner) == nil
}

func (seed *HelperExecTransactionSeed) Close() {
	if seed == nil || seed.owner == nil {
		return
	}
	owner := seed.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return
	}
	owner.closed = true
	owner.wipeLocked()
}

func (owner *helperExecTransactionSeedOwner) wipeLocked() {
	owner.correlation = HelperExecTransactionCorrelation{}
	owner.execBodyLength = 0
	owner.execBodySHA256 = [32]byte{}
	owner.privateLength = 0
	owner.privateSHA256 = [32]byte{}
	owner.stdinMaxBytes = 0
	if owner.execHash != nil {
		owner.execHash.Wipe()
		owner.execHash = nil
	}
	runtime.KeepAlive(owner)
}
