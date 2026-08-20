package credentialclient

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrSSHIOResult          = errors.New("credential client SSH I/O result is invalid")
	ErrSSHShutdownDirection = errors.New("credential client SSH shutdown direction is invalid")
)

const sshConnectionCleanupTimeout = 30 * time.Second

// SSHIOResult is bounded non-authority I/O metadata. Its constructor validates
// only intrinsic shape; the parent-owned connection view validates whether a
// result is valid for the specific read or write that produced it.
type SSHIOResult struct {
	liveValue
	byteCount uint64
	eof       bool
	truncated bool
}

// NewSSHIOResult captures one bounded issuer result without inferring an I/O
// operation, caller capacity, EOF matrix, or full-write claim.
func NewSSHIOResult(byteCount uint64, eof, truncated bool) (SSHIOResult, error) {
	if byteCount > uint64(credentialprotocol.SSHAgentMaxFrameBytes) {
		return SSHIOResult{}, ErrSSHIOResult
	}
	return SSHIOResult{byteCount: byteCount, eof: eof, truncated: truncated}, nil
}

// ByteCount returns the bounded number of bytes reported by the issuer.
func (result SSHIOResult) ByteCount() uint64 { return result.byteCount }

// EOF reports whether a read observed an orderly end of stream.
func (result SSHIOResult) EOF() bool { return result.eof }

// Truncated reports whether a read filled its bounded sink before the complete
// record was available.
func (result SSHIOResult) Truncated() bool { return result.truncated }

// SSHShutdownDirection is the closed half-close operation catalog.
type SSHShutdownDirection uint8

const (
	SSHShutdownRead  SSHShutdownDirection = 1
	SSHShutdownWrite SSHShutdownDirection = 2
	SSHShutdownBoth  SSHShutdownDirection = 3
)

// ValidateSSHShutdownDirection rejects typed zero and future values.
func ValidateSSHShutdownDirection(direction SSHShutdownDirection) error {
	switch direction {
	case SSHShutdownRead, SSHShutdownWrite, SSHShutdownBoth:
		return nil
	default:
		return ErrSSHShutdownDirection
	}
}

// String returns only a closed, redaction-safe catalog label.
func (direction SSHShutdownDirection) String() string {
	switch direction {
	case SSHShutdownRead:
		return "read"
	case SSHShutdownWrite:
		return "write"
	case SSHShutdownBoth:
		return "both"
	default:
		return "unknown"
	}
}

// GoString keeps Go-syntax formatting on the same closed catalog.
func (direction SSHShutdownDirection) GoString() string { return direction.String() }

// SSHConnectionCapability is the only live stream authority admitted by the
// credential client. It exposes no descriptor, path, peer, duplication, or
// unwrap operation.
type SSHConnectionCapability interface {
	SHA256() [32]byte
	Read(context.Context, credentialmemory.CredentialSink) (SSHIOResult, error)
	Write(context.Context, credentialmemory.BorrowedView) (SSHIOResult, error)
	Shutdown(context.Context, SSHShutdownDirection) error
	Close(context.Context) error
}

// SSHAcceptedPacket is the closed safe arm for one authenticated accepted
// connection. The connection accessor returns only the parent-owned view.
type SSHAcceptedPacket struct {
	liveValue
	revision         uint64
	bindingIndex     uint16
	ordinal          uint8
	capabilitySHA256 [32]byte
	connection       SSHConnectionCapability
	ownership        *sshConnectionOwnership
}

func (packet SSHAcceptedPacket) Revision() uint64 { return packet.revision }

func (packet SSHAcceptedPacket) BindingIndex() uint16 { return packet.bindingIndex }

func (packet SSHAcceptedPacket) Ordinal() uint8 { return packet.ordinal }

func (packet SSHAcceptedPacket) CapabilitySHA256() [32]byte { return packet.capabilitySHA256 }

// Connection returns a shared parent-owned view, never the Transport issuer.
func (packet SSHAcceptedPacket) Connection() SSHConnectionCapability { return packet.connection }

// WaitTransferred waits until the credential client has either committed the
// post-Handle ownership transfer or made that transfer impossible. Observation
// never changes ownership and only a committed transfer returns success.
func (packet SSHAcceptedPacket) WaitTransferred(ctx context.Context) error {
	if packet.ownership == nil || !validSSHContext(ctx) {
		return ErrExtensionPacketOwnership
	}
	ownership := packet.ownership
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	if ownership.phase == sshConnectionClientOwned {
		_ = waitSSHConnectionLocked(ctx, ownership, func() bool {
			return ownership.phase != sshConnectionClientOwned
		})
	}
	if ownership.phase != sshConnectionTransferred {
		return ErrExtensionPacketOwnership
	}
	return nil
}

type sshConnectionPhase uint8

const (
	sshConnectionClientOwned sshConnectionPhase = iota
	sshConnectionTransferred
	sshConnectionClosing
	sshConnectionClosed
)

type sshConnectionOwnership struct {
	mu           sync.Mutex
	cond         *sync.Cond
	phase        sshConnectionPhase
	activeOps    uint32
	digest       [32]byte
	issuer       SSHConnectionCapability
	closeStarted bool
	closeErr     error
}

type sshConnectionView struct {
	liveValue
	ownership *sshConnectionOwnership
}

func newSSHConnectionOwnership(digest [32]byte, issuer SSHConnectionCapability) *sshConnectionOwnership {
	ownership := &sshConnectionOwnership{
		phase:  sshConnectionClientOwned,
		digest: digest,
		issuer: issuer,
	}
	ownership.cond = sync.NewCond(&ownership.mu)
	return ownership
}

func (view sshConnectionView) SHA256() [32]byte {
	if view.ownership == nil {
		return [32]byte{}
	}
	view.ownership.mu.Lock()
	defer view.ownership.mu.Unlock()
	return view.ownership.digest
}

func (view sshConnectionView) Read(ctx context.Context, sink credentialmemory.CredentialSink) (SSHIOResult, error) {
	issuer, err := view.beginOperation(ctx)
	if err != nil {
		return SSHIOResult{}, err
	}
	capacity, valid := safeSSHCredentialSinkCapacity(sink)
	if !valid || capacity < 0 || capacity > credentialprotocol.SSHAgentMaxFrameBytes {
		view.endOperation()
		view.terminateAfterContractFailure()
		return SSHIOResult{}, ErrExtensionPacketOwnership
	}
	result, issuerErr := safeSSHIssuerRead(ctx, issuer, sink)
	view.endOperation()
	if issuerErr != nil || !validSSHReadResult(result, uint64(capacity)) {
		view.terminateAfterContractFailure()
		return SSHIOResult{}, ErrExtensionPacketOwnership
	}
	return result, nil
}

func (view sshConnectionView) Write(ctx context.Context, source credentialmemory.BorrowedView) (SSHIOResult, error) {
	issuer, err := view.beginOperation(ctx)
	if err != nil {
		return SSHIOResult{}, err
	}
	length, valid := safeSSHBorrowedViewLength(source)
	if !valid || length <= 0 || length > credentialprotocol.SSHAgentMaxFrameBytes {
		view.endOperation()
		view.terminateAfterContractFailure()
		return SSHIOResult{}, ErrExtensionPacketOwnership
	}
	result, issuerErr := safeSSHIssuerWrite(ctx, issuer, source)
	view.endOperation()
	if issuerErr != nil || result.eof || result.truncated || result.byteCount != uint64(length) {
		view.terminateAfterContractFailure()
		return SSHIOResult{}, ErrExtensionPacketOwnership
	}
	return result, nil
}

func (view sshConnectionView) Shutdown(ctx context.Context, direction SSHShutdownDirection) error {
	if ValidateSSHShutdownDirection(direction) != nil {
		return ErrSSHShutdownDirection
	}
	issuer, err := view.beginOperation(ctx)
	if err != nil {
		return err
	}
	issuerErr := safeSSHIssuerShutdown(ctx, issuer, direction)
	view.endOperation()
	if issuerErr != nil {
		view.terminateAfterContractFailure()
		return ErrExtensionPacketOwnership
	}
	return nil
}

// Close serializes all aliases, denies new operations, waits for in-flight
// operations under the supplied context, and invokes the private issuer once.
func (view sshConnectionView) Close(ctx context.Context) error {
	if view.ownership == nil {
		return ErrExtensionPacketOwnership
	}
	ownership := view.ownership
	ownership.mu.Lock()
	if ownership.phase == sshConnectionClosed {
		err := ownership.closeErr
		ownership.mu.Unlock()
		return err
	}
	ownership.mu.Unlock()
	if !validSSHContext(ctx) {
		return ErrExtensionPacketOwnership
	}
	ownership.mu.Lock()
	switch ownership.phase {
	case sshConnectionClientOwned:
		ownership.mu.Unlock()
		return ErrExtensionPacketOwnership
	case sshConnectionTransferred:
		ownership.phase = sshConnectionClosing
		ownership.cond.Broadcast()
	case sshConnectionClosing:
	case sshConnectionClosed:
		err := ownership.closeErr
		ownership.mu.Unlock()
		return err
	default:
		ownership.mu.Unlock()
		return ErrExtensionPacketOwnership
	}

	if !waitSSHConnectionLocked(ctx, ownership, func() bool {
		return ownership.activeOps == 0 && (!ownership.closeStarted || ownership.phase == sshConnectionClosed)
	}) {
		ownership.mu.Unlock()
		return ErrExtensionPacketOwnership
	}
	if ownership.phase == sshConnectionClosed {
		err := ownership.closeErr
		ownership.mu.Unlock()
		return err
	}
	ownership.closeStarted = true
	issuer := ownership.issuer
	ownership.mu.Unlock()

	closeErr := safeSSHIssuerClose(ctx, issuer)
	if closeErr != nil {
		closeErr = ErrExtensionPacketOwnership
	}
	ownership.mu.Lock()
	ownership.issuer = nil
	ownership.closeErr = closeErr
	ownership.phase = sshConnectionClosed
	ownership.cond.Broadcast()
	ownership.mu.Unlock()
	return closeErr
}

func (view sshConnectionView) beginOperation(ctx context.Context) (SSHConnectionCapability, error) {
	if !validSSHContext(ctx) || view.ownership == nil {
		return nil, ErrExtensionPacketOwnership
	}
	ownership := view.ownership
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	if ownership.phase != sshConnectionTransferred || !configuredDependency(ownership.issuer) {
		return nil, ErrExtensionPacketOwnership
	}
	ownership.activeOps++
	return ownership.issuer, nil
}

func (view sshConnectionView) endOperation() {
	if view.ownership == nil {
		return
	}
	view.ownership.mu.Lock()
	if view.ownership.activeOps > 0 {
		view.ownership.activeOps--
	}
	view.ownership.cond.Broadcast()
	view.ownership.mu.Unlock()
}

func (view sshConnectionView) terminateAfterContractFailure() {
	ctx, cancel := context.WithTimeout(context.Background(), sshConnectionCleanupTimeout)
	defer cancel()
	_ = view.Close(ctx)
}

func validSSHReadResult(result SSHIOResult, capacity uint64) bool {
	if result.byteCount > capacity || result.byteCount > uint64(credentialprotocol.SSHAgentMaxFrameBytes) {
		return false
	}
	if result.eof {
		return result.byteCount == 0 && !result.truncated
	}
	if result.byteCount == 0 {
		return false
	}
	return !result.truncated || capacity > 0 && result.byteCount == capacity
}

func waitSSHConnectionLocked(ctx context.Context, ownership *sshConnectionOwnership, ready func() bool) (result bool) {
	defer func() {
		if recover() != nil {
			result = false
		}
	}()
	stop := context.AfterFunc(ctx, func() {
		ownership.mu.Lock()
		ownership.cond.Broadcast()
		ownership.mu.Unlock()
	})
	defer stop()
	for !ready() && ctx.Err() == nil {
		ownership.cond.Wait()
	}
	return ctx.Err() == nil && ready()
}

func validSSHContext(ctx context.Context) (valid bool) {
	if !configuredDependency(ctx) {
		return false
	}
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return ctx.Err() == nil
}

func safeSSHCredentialSinkCapacity(sink credentialmemory.CredentialSink) (capacity int, valid bool) {
	if !configuredDependency(sink) {
		return 0, false
	}
	defer func() {
		if recover() != nil {
			capacity = 0
			valid = false
		}
	}()
	return sink.MaxCredentialBytes(), true
}

func safeSSHBorrowedViewLength(source credentialmemory.BorrowedView) (length int, valid bool) {
	if !configuredDependency(source) {
		return 0, false
	}
	defer func() {
		if recover() != nil {
			length = 0
			valid = false
		}
	}()
	return source.Len(), true
}

func safeSSHIssuerDigest(issuer SSHConnectionCapability) (digest [32]byte, valid bool) {
	if !configuredDependency(issuer) {
		return [32]byte{}, false
	}
	defer func() {
		if recover() != nil {
			digest = [32]byte{}
			valid = false
		}
	}()
	return issuer.SHA256(), true
}

func safeSSHIssuerRead(ctx context.Context, issuer SSHConnectionCapability, sink credentialmemory.CredentialSink) (result SSHIOResult, err error) {
	defer func() {
		if recover() != nil {
			result = SSHIOResult{}
			err = ErrExtensionPacketOwnership
		}
	}()
	return issuer.Read(ctx, sink)
}

func safeSSHIssuerWrite(ctx context.Context, issuer SSHConnectionCapability, source credentialmemory.BorrowedView) (result SSHIOResult, err error) {
	defer func() {
		if recover() != nil {
			result = SSHIOResult{}
			err = ErrExtensionPacketOwnership
		}
	}()
	return issuer.Write(ctx, source)
}

func safeSSHIssuerShutdown(ctx context.Context, issuer SSHConnectionCapability, direction SSHShutdownDirection) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrExtensionPacketOwnership
		}
	}()
	return issuer.Shutdown(ctx, direction)
}

func safeSSHIssuerClose(ctx context.Context, issuer SSHConnectionCapability) (err error) {
	if !configuredDependency(issuer) {
		return ErrExtensionPacketOwnership
	}
	defer func() {
		if recover() != nil {
			err = ErrExtensionPacketOwnership
		}
	}()
	return issuer.Close(ctx)
}
