package credentialhelper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var _ func(
	context.Context,
	ReceiveRequest,
	credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential,
	uint32,
	ReceivedBodyCapability,
	uint32,
	[32]byte,
	credentialprotocol.SafeID,
	credentialprotocol.SafeID,
	[32]byte,
) (ReceivedPacket, error) = NewReceivedAgentHelloPacket

type transportTestView struct {
	value []byte
	state *transportTestBodyState
}

func (view transportTestView) Len() int { return len(view.value) }
func (transportTestView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	return errors.New("unused")
}
func (view transportTestView) WriteTo(ctx context.Context, sink credentialmemory.CredentialSink) error {
	view.state.writeContexts = append(view.state.writeContexts, ctx)
	return sink.WriteCredential(view.value)
}

type transportTestBodyState struct {
	mu              sync.Mutex
	region          []byte
	length          int
	borrows         int
	destroyed       bool
	lenCalls        int
	digestCalls     int
	borrowContexts  []context.Context
	writeContexts   []context.Context
	destroyContexts []context.Context
}

type transportTestBody struct{ state *transportTestBodyState }

func newTransportTestBody(body []byte, capacity int) transportTestBody {
	region := make([]byte, capacity)
	copy(region, body)
	return transportTestBody{state: &transportTestBodyState{region: region, length: len(body)}}
}

func (body transportTestBody) Len() uint32 {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	body.state.lenCalls++
	if body.state.destroyed {
		return 0
	}
	return uint32(body.state.length)
}

func (body transportTestBody) SHA256() [32]byte {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	body.state.digestCalls++
	if body.state.destroyed {
		return [32]byte{}
	}
	return sha256.Sum256(body.state.region[:body.state.length])
}

type transportTestLyingBody struct{ transportTestBody }

func (body transportTestLyingBody) SHA256() [32]byte { return sha256.Sum256([]byte("not the body")) }

type cancelBorrowTransportBody struct {
	transportTestBody
	cancel context.CancelFunc
}

func (body cancelBorrowTransportBody) Borrow(ctx context.Context, callback func(credentialmemory.BorrowedView) error) error {
	body.cancel()
	return body.transportTestBody.Borrow(ctx, callback)
}

type cancelBeforeCallbackTransportView struct {
	mu         sync.Mutex
	value      []byte
	lenCalls   int
	writeCalls int
}

func (view *cancelBeforeCallbackTransportView) Len() int {
	view.mu.Lock()
	defer view.mu.Unlock()
	view.lenCalls++
	return len(view.value)
}

func (*cancelBeforeCallbackTransportView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	return errors.New("unused")
}

func (view *cancelBeforeCallbackTransportView) WriteTo(_ context.Context, sink credentialmemory.CredentialSink) error {
	view.mu.Lock()
	view.writeCalls++
	value := view.value
	view.mu.Unlock()
	return sink.WriteCredential(value)
}

func (view *cancelBeforeCallbackTransportView) calls() (int, int) {
	view.mu.Lock()
	defer view.mu.Unlock()
	return view.lenCalls, view.writeCalls
}

type cancelBeforeCallbackTransportBody struct {
	transportTestBody
	mu             sync.Mutex
	view           *cancelBeforeCallbackTransportView
	cancel         context.CancelFunc
	cancelOnBorrow int
	borrowCalls    int
}

func (body *cancelBeforeCallbackTransportBody) Borrow(ctx context.Context, callback func(credentialmemory.BorrowedView) error) error {
	body.mu.Lock()
	body.borrowCalls++
	shouldCancel := body.cancel != nil && body.borrowCalls == body.cancelOnBorrow
	body.mu.Unlock()
	body.state.mu.Lock()
	body.state.borrows++
	body.state.borrowContexts = append(body.state.borrowContexts, ctx)
	body.state.mu.Unlock()
	if shouldCancel {
		body.cancel()
	}
	return callback(body.view)
}

type cancelingMetadataTransportBody struct {
	transportTestBody
	cancel           context.CancelFunc
	cancelLenCall    int
	cancelDigestCall int
}

func (body cancelingMetadataTransportBody) Len() uint32 {
	length := body.transportTestBody.Len()
	body.state.mu.Lock()
	call := body.state.lenCalls
	body.state.mu.Unlock()
	if call == body.cancelLenCall {
		body.cancel()
	}
	return length
}

func (body cancelingMetadataTransportBody) SHA256() [32]byte {
	digest := body.transportTestBody.SHA256()
	body.state.mu.Lock()
	call := body.state.digestCalls
	body.state.mu.Unlock()
	if call == body.cancelDigestCall {
		body.cancel()
	}
	return digest
}

func (body transportTestBody) Borrow(ctx context.Context, callback func(credentialmemory.BorrowedView) error) error {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	if body.state.destroyed {
		return ErrContractDestroyed
	}
	body.state.borrows++
	body.state.borrowContexts = append(body.state.borrowContexts, ctx)
	return callback(transportTestView{value: body.state.region[:body.state.length], state: body.state})
}

func (body transportTestBody) Destroy(ctx context.Context) error {
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	body.state.destroyContexts = append(body.state.destroyContexts, ctx)
	if body.state.destroyed {
		return ErrContractDestroyed
	}
	clear(body.state.region)
	body.state.length = 0
	body.state.destroyed = true
	return nil
}

type transportTestRightState struct {
	mu            sync.Mutex
	kind          ReceivedCapabilityKind
	digest        [32]byte
	closed        bool
	kindCalls     int
	digestCalls   int
	closeContexts []context.Context
}

type transportTestRight struct{ state *transportTestRightState }

func (right transportTestRight) Kind() ReceivedCapabilityKind {
	right.state.mu.Lock()
	defer right.state.mu.Unlock()
	right.state.kindCalls++
	return right.state.kind
}
func (right transportTestRight) SHA256() [32]byte {
	right.state.mu.Lock()
	defer right.state.mu.Unlock()
	right.state.digestCalls++
	return right.state.digest
}
func (right transportTestRight) Close(ctx context.Context) error {
	right.state.mu.Lock()
	defer right.state.mu.Unlock()
	right.state.closeContexts = append(right.state.closeContexts, ctx)
	if right.state.closed {
		return ErrContractDestroyed
	}
	right.state.closed = true
	return nil
}

type cancelingMetadataTransportRight struct {
	transportTestRight
	cancel       context.CancelFunc
	cancelKind   bool
	cancelDigest bool
}

func (right cancelingMetadataTransportRight) Kind() ReceivedCapabilityKind {
	kind := right.transportTestRight.Kind()
	if right.cancelKind {
		right.cancel()
	}
	return kind
}

func (right cancelingMetadataTransportRight) SHA256() [32]byte {
	digest := right.transportTestRight.SHA256()
	if right.cancelDigest {
		right.cancel()
	}
	return digest
}

type cleanupPanicTransportBody struct {
	transportTestBody
	panicDestroy bool
	cancel       context.CancelFunc
}

func (body *cleanupPanicTransportBody) Destroy(ctx context.Context) error {
	body.state.mu.Lock()
	body.state.destroyContexts = append(body.state.destroyContexts, ctx)
	body.state.destroyed = true
	clear(body.state.region)
	body.state.length = 0
	body.state.mu.Unlock()
	if body.cancel != nil {
		body.cancel()
	}
	if body.panicDestroy {
		panic("cleanup body panic must be sanitized")
	}
	return nil
}

type cleanupPanicTransportRight struct {
	transportTestRight
	panicClose bool
	cancel     context.CancelFunc
}

func (right *cleanupPanicTransportRight) Close(ctx context.Context) error {
	right.state.mu.Lock()
	right.state.closeContexts = append(right.state.closeContexts, ctx)
	right.state.closed = true
	right.state.mu.Unlock()
	if right.cancel != nil {
		right.cancel()
	}
	if right.panicClose {
		panic("cleanup right panic must be sanitized")
	}
	return nil
}

type retainedCancellationView struct {
	mu            sync.Mutex
	value         []byte
	cancel        context.CancelFunc
	cancelLen     bool
	cancelWrite   bool
	lenCalls      int
	writeCalls    int
	lastWriteSink credentialmemory.CredentialSink
}

func (view *retainedCancellationView) Len() int {
	view.mu.Lock()
	view.lenCalls++
	cancel := view.cancelLen
	view.mu.Unlock()
	if cancel {
		view.cancel()
	}
	return len(view.value)
}

func (*retainedCancellationView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	return errors.New("unused")
}

func (view *retainedCancellationView) WriteTo(_ context.Context, sink credentialmemory.CredentialSink) error {
	view.mu.Lock()
	view.writeCalls++
	view.lastWriteSink = sink
	cancel := view.cancelWrite
	view.mu.Unlock()
	if cancel {
		view.cancel()
	}
	return sink.WriteCredential(view.value)
}

func (view *retainedCancellationView) calls() (int, int) {
	view.mu.Lock()
	defer view.mu.Unlock()
	return view.lenCalls, view.writeCalls
}

type retainedCancellationBody struct {
	mu                 sync.Mutex
	view               *retainedCancellationView
	cancel             context.CancelFunc
	cancelLen          bool
	cancelBorrowBefore bool
	cancelBorrowAfter  bool
	lenCalls           int
	borrowCalls        int
	destroyCalls       int
}

func (body *retainedCancellationBody) Len() uint32 {
	body.mu.Lock()
	body.lenCalls++
	cancel := body.cancelLen
	length := len(body.view.value)
	body.mu.Unlock()
	if cancel {
		body.cancel()
	}
	return uint32(length)
}

func (body *retainedCancellationBody) SHA256() [32]byte {
	return sha256.Sum256(body.view.value)
}

func (body *retainedCancellationBody) Borrow(_ context.Context, callback func(credentialmemory.BorrowedView) error) error {
	body.mu.Lock()
	body.borrowCalls++
	cancelBefore, cancelAfter := body.cancelBorrowBefore, body.cancelBorrowAfter
	body.mu.Unlock()
	if cancelBefore {
		body.cancel()
	}
	err := callback(body.view)
	if cancelAfter {
		body.cancel()
	}
	return err
}

func (body *retainedCancellationBody) Destroy(context.Context) error {
	body.mu.Lock()
	defer body.mu.Unlock()
	body.destroyCalls++
	return nil
}

func (body *retainedCancellationBody) calls() (int, int, int) {
	body.mu.Lock()
	defer body.mu.Unlock()
	return body.lenCalls, body.borrowCalls, body.destroyCalls
}

type retainedCancellationSink struct {
	mu          sync.Mutex
	maximum     int
	cancel      context.CancelFunc
	cancelMax   bool
	cancelWrite bool
	maxCalls    int
	writes      int
}

func (sink *retainedCancellationSink) MaxCredentialBytes() int {
	sink.mu.Lock()
	sink.maxCalls++
	cancel := sink.cancelMax
	sink.mu.Unlock()
	if cancel {
		sink.cancel()
	}
	return sink.maximum
}

func (sink *retainedCancellationSink) WriteCredential([]byte) error {
	sink.mu.Lock()
	sink.writes++
	cancel := sink.cancelWrite
	sink.mu.Unlock()
	if cancel {
		sink.cancel()
	}
	return nil
}

func (sink *retainedCancellationSink) calls() (int, int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.maxCalls, sink.writes
}

type adversarialTransportView struct {
	value    []byte
	write    bool
	writeErr error
}

func (view adversarialTransportView) Len() int { return len(view.value) }
func (adversarialTransportView) CopyTo(context.Context, *credentialmemory.LockedMapping) error {
	return errors.New("unused")
}
func (view adversarialTransportView) WriteTo(_ context.Context, sink credentialmemory.CredentialSink) error {
	if view.write {
		_ = sink.WriteCredential(view.value)
	}
	return view.writeErr
}

type adversarialTransportBody struct {
	mu         sync.Mutex
	canonical  []byte
	views      []adversarialTransportView
	concurrent bool
	destroyed  bool
}

type countingTransportSink struct {
	mu      sync.Mutex
	maximum int
	calls   int
	err     error
}

type cancelingTransportSink struct {
	maximum int
	cancel  context.CancelFunc
}

type cancelOnMaximumTransportSink struct {
	mu       sync.Mutex
	maximum  int
	cancel   context.CancelFunc
	maxCalls int
	writes   int
}

func (sink cancelingTransportSink) MaxCredentialBytes() int { return sink.maximum }
func (sink cancelingTransportSink) WriteCredential([]byte) error {
	sink.cancel()
	return nil
}

func (sink *cancelOnMaximumTransportSink) MaxCredentialBytes() int {
	sink.mu.Lock()
	sink.maxCalls++
	sink.mu.Unlock()
	sink.cancel()
	return sink.maximum
}

func (sink *cancelOnMaximumTransportSink) WriteCredential([]byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.writes++
	return nil
}

func (sink *cancelOnMaximumTransportSink) counts() (int, int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.maxCalls, sink.writes
}

func (sink *countingTransportSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *countingTransportSink) WriteCredential([]byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.calls++
	return sink.err
}
func (sink *countingTransportSink) callCount() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.calls
}

type panicTransportBody struct {
	destroyed  bool
	destroyErr error
}

func (*panicTransportBody) Len() uint32      { panic("transport test panic") }
func (*panicTransportBody) SHA256() [32]byte { return [32]byte{} }
func (*panicTransportBody) Borrow(context.Context, func(credentialmemory.BorrowedView) error) error {
	panic("transport test panic")
}
func (body *panicTransportBody) Destroy(context.Context) error {
	body.destroyed = true
	return body.destroyErr
}

func (body *adversarialTransportBody) Len() uint32      { return uint32(len(body.canonical)) }
func (body *adversarialTransportBody) SHA256() [32]byte { return sha256.Sum256(body.canonical) }
func (body *adversarialTransportBody) Borrow(_ context.Context, callback func(credentialmemory.BorrowedView) error) error {
	if !body.concurrent {
		for _, view := range body.views {
			_ = callback(view)
		}
		return nil
	}
	var wait sync.WaitGroup
	wait.Add(len(body.views))
	for _, view := range body.views {
		view := view
		go func() {
			defer wait.Done()
			_ = callback(view)
		}()
	}
	wait.Wait()
	return nil
}
func (body *adversarialTransportBody) Destroy(context.Context) error {
	body.mu.Lock()
	defer body.mu.Unlock()
	body.destroyed = true
	return nil
}

type transportContextKey struct{}

func plainNilTransportContext() context.Context { return nil }

type typedNilTransportContext struct{}

func (*typedNilTransportContext) Deadline() (time.Time, bool) {
	panic("typed-nil context method called")
}
func (*typedNilTransportContext) Done() <-chan struct{} { panic("typed-nil context method called") }
func (*typedNilTransportContext) Err() error            { panic("typed-nil context method called") }
func (*typedNilTransportContext) Value(any) any         { panic("typed-nil context method called") }

func TestTransportTypedNilContextIsPreTransferEverywhere(t *testing.T) {
	var typedNil *typedNilTransportContext
	ctx := context.Context(typedNil)
	request, err := NewReceiveRequest(2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	credential := transportCredential(t)
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 32)
	right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("typed-nil-right"))}}
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1)

	received := map[string]func() (ReceivedPacket, error){
		"bootstrap": func() (ReceivedPacket, error) {
			return NewReceivedBootstrapPacket(ctx, request, header, credential, 1, body, 1, 0, 0, 0, "", "", right)
		},
		"agent hello": func() (ReceivedPacket, error) {
			return NewReceivedAgentHelloPacket(ctx, request, header, credential, 1, body, 0, [32]byte{}, "", "", [32]byte{})
		},
		"prepare begin": func() (ReceivedPacket, error) {
			return NewReceivedPrepareBeginPacket(ctx, request, header, credential, 1, body, 0, credentialprotocol.HelperPrepareBeginBody{}, ManifestCapability{})
		},
		"prepare file": func() (ReceivedPacket, error) {
			return NewReceivedPrepareFilePacket(ctx, request, header, credential, 1, body, 0, 0, 0, 0, [32]byte{})
		},
		"prepare commit": func() (ReceivedPacket, error) {
			return NewReceivedPrepareCommitPacket(ctx, request, header, credential, 1, body, 0, credentialprotocol.HelperPrepareCommitBody{})
		},
		"renew": func() (ReceivedPacket, error) {
			return NewReceivedRenewPacket(ctx, request, header, credential, 1, body, 0, 0, 0, "")
		},
		"revoke": func() (ReceivedPacket, error) {
			return NewReceivedRevokePacket(ctx, request, header, credential, 1, body, 0, credentialprotocol.HelperRevokeBody{})
		},
		"exec": func() (ReceivedPacket, error) {
			return NewReceivedExecPacket(ctx, request, header, credential, 1, body, 0, credentialprotocol.HelperExecBody{}, ExecPlanCapability{})
		},
		"exec private": func() (ReceivedPacket, error) {
			return NewReceivedExecPrivatePacket(ctx, request, header, credential, 1, body, 0, 0, 0, [32]byte{})
		},
		"exec stream": func() (ReceivedPacket, error) {
			return NewReceivedExecStreamPacket(ctx, request, header, credential, 1, body, 0, 0, 0, 0, 0, 0, [32]byte{})
		},
		"exec credit": func() (ReceivedPacket, error) {
			return NewReceivedExecCreditPacket(ctx, request, header, credential, 1, body, 0, credentialprotocol.HelperExecCreditBody{})
		},
		"close notify": func() (ReceivedPacket, error) {
			return NewReceivedCloseNotifyPacket(ctx, request, header, credential, 1, body, 0, credentialprotocol.HelperCloseNotifyBody{})
		},
	}
	for name, construct := range received {
		t.Run("receive "+name, func(t *testing.T) {
			if _, err := construct(); !errors.Is(err, ErrContractTypedNil) {
				t.Fatalf("typed-nil context error = %v", err)
			}
		})
	}
	if body.state.lenCalls != 0 || body.state.digestCalls != 0 || body.state.borrows != 0 || len(body.state.destroyContexts) != 0 {
		t.Fatal("typed-nil receive context touched body")
	}
	if right.state.kindCalls != 0 || right.state.digestCalls != 0 || len(right.state.closeContexts) != 0 {
		t.Fatal("typed-nil receive context touched right")
	}
	packet, err := NewReceivedCloseNotifyPacket(context.Background(), request, header, credential, 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil || packet.Type() != credentialprotocol.PacketTypeCloseNotify {
		t.Fatalf("typed-nil receive context consumed request: %#v, %v", packet, err)
	}

	invalidHeader := credentialprotocol.HelperPacketHeader{}
	sendBody := newTransportTestBody([]byte("typed-nil-send-body"), 32)
	sends := map[string]func() (SendPacket, error){
		"newSendPacket": func() (SendPacket, error) {
			return newSendPacket(ctx, invalidHeader, sendExecStreamArm{body: sendBody}, nil)
		},
		"helper ready":    func() (SendPacket, error) { return newHelperReadyPacket(ctx, invalidHeader) },
		"bootstrap ack":   func() (SendPacket, error) { return newBootstrapAckPacket(ctx, invalidHeader, [32]byte{}) },
		"agent hello ack": func() (SendPacket, error) { return newAgentHelloAckPacket(ctx, invalidHeader, [32]byte{}) },
		"ssh accepted": func() (SendPacket, error) {
			return newSSHAcceptedPacket(ctx, invalidHeader, 0, 0, 0, right.state.digest, right)
		},
		"exec credit": func() (SendPacket, error) {
			return newExecCreditPacket(ctx, invalidHeader, credentialprotocol.HelperExecCreditBody{})
		},
		"exec stream": func() (SendPacket, error) {
			return newExecStreamPacket(ctx, invalidHeader, 0, 0, 0, 0, 0, [32]byte{}, sendBody)
		},
		"response": func() (SendPacket, error) {
			return newResponsePacket(ctx, invalidHeader, credentialprotocol.HelperResponseBody{})
		},
		"event": func() (SendPacket, error) {
			return newEventPacket(ctx, invalidHeader, credentialprotocol.HelperEventBody{})
		},
		"close notify": func() (SendPacket, error) {
			return newCloseNotifyPacket(ctx, invalidHeader, credentialprotocol.HelperCloseNotifyBody{})
		},
	}
	for name, construct := range sends {
		t.Run("send "+name, func(t *testing.T) {
			if _, err := construct(); !errors.Is(err, ErrContractTypedNil) {
				t.Fatalf("typed-nil context error = %v", err)
			}
		})
	}
	if right.state.kindCalls != 0 || right.state.digestCalls != 0 || len(right.state.closeContexts) != 0 {
		t.Fatal("typed-nil send context touched right")
	}
	if sendBody.state.lenCalls != 0 || sendBody.state.digestCalls != 0 || sendBody.state.borrows != 0 || len(sendBody.state.destroyContexts) != 0 {
		t.Fatal("typed-nil send context touched body")
	}

	metadata, err := newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	sink := &transportTestSink{maximum: 1}
	if err := metadata.WriteCanonicalBody(ctx, sink); !errors.Is(err, ErrContractTypedNil) {
		t.Fatalf("typed-nil write context error = %v", err)
	}
	if len(sink.value) != 0 {
		t.Fatal("typed-nil write context touched sink")
	}
	if err := metadata.WriteCanonicalBody(context.Background(), sink); err != nil {
		t.Fatalf("typed-nil write context consumed one-shot latch: %v", err)
	}
}

func TestPrivateSendConstructorsRejectNilContextBeforeMetadata(t *testing.T) {
	invalidHeader := credentialprotocol.HelperPacketHeader{}
	for name, construct := range map[string]func() (SendPacket, error){
		"helper ready": func() (SendPacket, error) {
			//nolint:staticcheck // Deliberately exercises frozen nil-context precondition.
			return newHelperReadyPacket(nil, invalidHeader)
		},
		"bootstrap ack": func() (SendPacket, error) {
			//nolint:staticcheck // Deliberately exercises frozen nil-context precondition.
			return newBootstrapAckPacket(nil, invalidHeader, [32]byte{})
		},
		"agent hello ack": func() (SendPacket, error) {
			//nolint:staticcheck // Deliberately exercises frozen nil-context precondition.
			return newAgentHelloAckPacket(nil, invalidHeader, [32]byte{})
		},
		"exec credit": func() (SendPacket, error) {
			return newExecCreditPacket(plainNilTransportContext(), invalidHeader, credentialprotocol.HelperExecCreditBody{})
		},
		"response": func() (SendPacket, error) {
			return newResponsePacket(plainNilTransportContext(), invalidHeader, credentialprotocol.HelperResponseBody{})
		},
		"event": func() (SendPacket, error) {
			return newEventPacket(plainNilTransportContext(), invalidHeader, credentialprotocol.HelperEventBody{})
		},
		"close notify": func() (SendPacket, error) {
			return newCloseNotifyPacket(plainNilTransportContext(), invalidHeader, credentialprotocol.HelperCloseNotifyBody{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := construct(); !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("nil context + invalid metadata error = %v", err)
			}
		})
	}
}

func TestTransportCancellationConsumesOwnershipWithoutExposingContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 32)
	request, _ := NewReceiveRequest(2, 1, 0)
	_, err := NewReceivedCloseNotifyPacket(ctx, request, transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1), transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled receive error = %v", err)
	}
	assertExactTransportContexts(t, ctx, body.state.destroyContexts, "canceled receive destroy")

	duringCtx, duringCancel := context.WithCancel(context.Background())
	duringBodyBase := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 32)
	duringBody := cancelBorrowTransportBody{transportTestBody: duringBodyBase, cancel: duringCancel}
	duringRequest, _ := NewReceiveRequest(2, 1, 0)
	_, err = NewReceivedCloseNotifyPacket(duringCtx, duringRequest, transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1), transportCredential(t), 1, duringBody, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
		t.Fatalf("cancel-during-receive error = %v", err)
	}
	assertExactTransportContexts(t, duringCtx, duringBodyBase.state.destroyContexts, "cancel-during receive destroy")

	if _, err := newCloseNotifyPacket(ctx, credentialprotocol.HelperPacketHeader{}, credentialprotocol.HelperCloseNotifyBody{}); !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled metadata send error = %v", err)
	}

	packet, err := newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	writeCtx, writeCancel := context.WithCancel(context.Background())
	writeCancel()
	if err := packet.WriteCanonicalBody(writeCtx, &transportTestSink{maximum: 1}); !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled write error = %v", err)
	}
	if err := packet.WriteCanonicalBody(context.Background(), &transportTestSink{maximum: 1}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("canceled write did not consume one-shot latch: %v", err)
	}

	packet, err = newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	writeDuringCtx, writeDuringCancel := context.WithCancel(context.Background())
	if err := packet.WriteCanonicalBody(writeDuringCtx, cancelingTransportSink{maximum: 1, cancel: writeDuringCancel}); !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
		t.Fatalf("cancel-during-write error = %v", err)
	}
}

func TestTransportCancellationBeforeBorrowCallbackTouchesNoView(t *testing.T) {
	t.Run("receive validation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		canonical := []byte{byte(credentialprotocol.CloseReasonNormal)}
		base := newTransportTestBody(canonical, 32)
		view := &cancelBeforeCallbackTransportView{value: canonical}
		body := &cancelBeforeCallbackTransportBody{transportTestBody: base, view: view, cancel: cancel, cancelOnBorrow: 1}
		request, _ := NewReceiveRequest(2, 1, 0)
		_, err := NewReceivedCloseNotifyPacket(ctx, request, transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1), transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
		if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("receive cancellation error = %v", err)
		}
		if lenCalls, writeCalls := view.calls(); lenCalls != 0 || writeCalls != 0 {
			t.Fatalf("receive post-cancellation view calls = Len:%d WriteTo:%d, want 0/0", lenCalls, writeCalls)
		}
		assertBodyDestroyedAndWiped(t, base)
	})

	payload := []byte("stdout")
	digest := sha256.Sum256(payload)
	canonical := transportStreamBody(3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, payload, digest)
	header := transportJobHeader(credentialprotocol.PacketTypeExecStream, 7, uint32(len(canonical)))

	t.Run("send stream construction", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		base := newTransportTestBody(canonical, credentialprotocol.MaxHelperPacketBodyBytes)
		view := &cancelBeforeCallbackTransportView{value: canonical}
		body := &cancelBeforeCallbackTransportBody{transportTestBody: base, view: view, cancel: cancel, cancelOnBorrow: 1}
		_, err := newExecStreamPacket(ctx, header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), digest, body)
		if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("send construction cancellation error = %v", err)
		}
		if lenCalls, writeCalls := view.calls(); lenCalls != 0 || writeCalls != 0 {
			t.Fatalf("send construction post-cancellation view calls = Len:%d WriteTo:%d, want 0/0", lenCalls, writeCalls)
		}
		assertBodyDestroyedAndWiped(t, base)
	})

	t.Run("send stream write", func(t *testing.T) {
		base := newTransportTestBody(canonical, credentialprotocol.MaxHelperPacketBodyBytes)
		view := &cancelBeforeCallbackTransportView{value: canonical}
		body := &cancelBeforeCallbackTransportBody{transportTestBody: base, view: view}
		packet, err := newExecStreamPacket(context.Background(), header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), digest, body)
		if err != nil {
			t.Fatal(err)
		}
		view.mu.Lock()
		view.lenCalls, view.writeCalls = 0, 0
		view.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		body.mu.Lock()
		body.cancel = cancel
		body.cancelOnBorrow = body.borrowCalls + 1
		body.mu.Unlock()
		err = packet.WriteCanonicalBody(ctx, &transportTestSink{maximum: len(canonical)})
		if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("send write cancellation error = %v", err)
		}
		if lenCalls, writeCalls := view.calls(); lenCalls != 0 || writeCalls != 0 {
			t.Fatalf("send write post-cancellation view calls = Len:%d WriteTo:%d, want 0/0", lenCalls, writeCalls)
		}
		if err := packet.destroyBody(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTransportCancellationStopsImmediatelyAfterExternalMetadataCallbacks(t *testing.T) {
	t.Run("receive retained body SHA256", func(t *testing.T) {
		payload := []byte("private")
		digest := sha256.Sum256(payload)
		canonical := make([]byte, 44+len(payload))
		binary.BigEndian.PutUint64(canonical[:8], 2)
		binary.BigEndian.PutUint32(canonical[8:12], uint32(len(payload)))
		copy(canonical[12:44], digest[:])
		copy(canonical[44:], payload)
		ctx, cancel := context.WithCancel(context.Background())
		bodyBase := newTransportTestBody(canonical, 256)
		body := cancelingMetadataTransportBody{transportTestBody: bodyBase, cancel: cancel, cancelDigestCall: 1}
		request, err := NewReceiveRequest(2, uint32(len(canonical)), 0)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := NewReceivedExecPrivatePacket(ctx, request, transportJobHeader(credentialprotocol.PacketTypeExecPrivate, 2, uint32(len(canonical))), transportCredential(t), 1, body, 0, 2, uint32(len(payload)), digest)
		if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("cancel-during retained SHA256 error = %v", err)
		}
		if packet != (ReceivedPacket{}) {
			t.Fatal("cancel-during retained SHA256 returned a packet")
		}
		assertBodyDestroyedAndWiped(t, bodyBase)
	})

	streamPayload := []byte("stdout")
	streamDigest := sha256.Sum256(streamPayload)
	streamCanonical := transportStreamBody(3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, streamPayload, streamDigest)
	streamHeader := transportJobHeader(credentialprotocol.PacketTypeExecStream, 7, uint32(len(streamCanonical)))
	for _, test := range []struct {
		name             string
		cancelLenCall    int
		cancelDigestCall int
		wantLenCalls     int
		wantBorrows      int
		wantDigestCalls  int
	}{
		{name: "send stream Len", cancelLenCall: 1, wantLenCalls: 1},
		{name: "send stream validation SHA256", cancelDigestCall: 1, wantLenCalls: 1, wantBorrows: 1, wantDigestCalls: 1},
		{name: "send stream pinned SHA256", cancelDigestCall: 2, wantLenCalls: 1, wantBorrows: 1, wantDigestCalls: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			bodyBase := newTransportTestBody(streamCanonical, credentialprotocol.MaxHelperPacketBodyBytes)
			body := cancelingMetadataTransportBody{
				transportTestBody: bodyBase,
				cancel:            cancel,
				cancelLenCall:     test.cancelLenCall,
				cancelDigestCall:  test.cancelDigestCall,
			}
			packet, err := newExecStreamPacket(ctx, streamHeader, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(streamPayload)), streamDigest, body)
			if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
				t.Fatalf("cancel-during stream metadata error = %v", err)
			}
			if packet != (SendPacket{}) {
				t.Fatal("cancel-during stream metadata returned a packet")
			}
			bodyBase.state.mu.Lock()
			lenCalls, borrows, digestCalls := bodyBase.state.lenCalls, bodyBase.state.borrows, bodyBase.state.digestCalls
			bodyBase.state.mu.Unlock()
			if lenCalls != test.wantLenCalls || borrows != test.wantBorrows || digestCalls != test.wantDigestCalls {
				t.Fatalf("post-cancellation body calls = Len:%d Borrow:%d SHA256:%d, want %d/%d/%d", lenCalls, borrows, digestCalls, test.wantLenCalls, test.wantBorrows, test.wantDigestCalls)
			}
			assertBodyDestroyedAndWiped(t, bodyBase)
		})
	}

	rightDigest := sha256.Sum256([]byte("relay"))
	rightHeader := transportJobHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 9, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength())
	for _, test := range []struct {
		name           string
		cancelKind     bool
		cancelDigest   bool
		wantKindCalls  int
		wantDigestCall int
	}{
		{name: "send right Kind", cancelKind: true, wantKindCalls: 1},
		{name: "send right SHA256", cancelDigest: true, wantKindCalls: 1, wantDigestCall: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			rightBase := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilitySSHConnection, digest: rightDigest}}
			right := cancelingMetadataTransportRight{transportTestRight: rightBase, cancel: cancel, cancelKind: test.cancelKind, cancelDigest: test.cancelDigest}
			packet, err := newSSHAcceptedPacket(ctx, rightHeader, 1, 0, 1, rightDigest, right)
			if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
				t.Fatalf("cancel-during right metadata error = %v", err)
			}
			if packet != (SendPacket{}) {
				t.Fatal("cancel-during right metadata returned a packet")
			}
			rightBase.state.mu.Lock()
			kindCalls, digestCalls, closed := rightBase.state.kindCalls, rightBase.state.digestCalls, rightBase.state.closed
			rightBase.state.mu.Unlock()
			if kindCalls != test.wantKindCalls || digestCalls != test.wantDigestCall || !closed {
				t.Fatalf("post-cancellation right state = Kind:%d SHA256:%d closed:%t, want %d/%d/true", kindCalls, digestCalls, closed, test.wantKindCalls, test.wantDigestCall)
			}
		})
	}

	t.Run("metadata write sink maximum", func(t *testing.T) {
		packet, err := newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		sink := &cancelOnMaximumTransportSink{maximum: 1, cancel: cancel}
		if err := packet.WriteCanonicalBody(ctx, sink); !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("cancel-during metadata sink maximum error = %v", err)
		}
		maxCalls, writes := sink.counts()
		if maxCalls != 1 || writes != 0 {
			t.Fatalf("post-cancellation metadata sink calls = maximum:%d writes:%d, want 1/0", maxCalls, writes)
		}
		if err := packet.WriteCanonicalBody(context.Background(), &transportTestSink{maximum: 1}); !errors.Is(err, ErrContractOwnership) {
			t.Fatalf("canceled metadata write did not consume one-shot: %v", err)
		}
	})

	t.Run("stream write sink maximum", func(t *testing.T) {
		body := newTransportTestBody(streamCanonical, credentialprotocol.MaxHelperPacketBodyBytes)
		packet, err := newExecStreamPacket(context.Background(), streamHeader, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(streamPayload)), streamDigest, body)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		sink := &cancelOnMaximumTransportSink{maximum: len(streamCanonical), cancel: cancel}
		if err := packet.WriteCanonicalBody(ctx, sink); !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("cancel-during stream sink maximum error = %v", err)
		}
		maxCalls, writes := sink.counts()
		body.state.mu.Lock()
		borrows := body.state.borrows
		body.state.mu.Unlock()
		if maxCalls != 1 || writes != 0 || borrows != 1 {
			t.Fatalf("post-cancellation stream calls = maximum:%d writes:%d borrows:%d, want 1/0/1", maxCalls, writes, borrows)
		}
		if err := packet.destroyBody(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetainedPayloadCancellationStopsBeforeNextExternalCall(t *testing.T) {
	newHarness := func(ctx context.Context, cancel context.CancelFunc) (receivedPayloadBody, *retainedCancellationBody, *retainedCancellationView) {
		view := &retainedCancellationView{value: []byte("prefix-private"), cancel: cancel}
		body := &retainedCancellationBody{view: view, cancel: cancel}
		wrapped := receivedPayloadBody{owner: body, canonicalLength: uint32(len(view.value)), offset: 7, length: 7, digest: sha256.Sum256(view.value[7:])}
		return wrapped, body, view
	}

	t.Run("pre-canceled borrow", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		body, owner, _ := newHarness(ctx, cancel)
		callbacks := 0
		err := body.Borrow(ctx, func(credentialmemory.BorrowedView) error { callbacks++; return nil })
		if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled retained borrow error = %v", err)
		}
		_, borrows, _ := owner.calls()
		if borrows != 0 || callbacks != 0 {
			t.Fatalf("pre-canceled retained borrow calls = owner:%d callback:%d", borrows, callbacks)
		}
	})

	for _, test := range []struct {
		name             string
		configure        func(*retainedCancellationBody, *retainedCancellationView)
		cancelInCallback bool
		wantViewLen      int
		wantServiceCalls int
	}{
		{name: "owner borrow cancels before callback", configure: func(body *retainedCancellationBody, _ *retainedCancellationView) { body.cancelBorrowBefore = true }},
		{name: "owner view Len cancels", configure: func(_ *retainedCancellationBody, view *retainedCancellationView) { view.cancelLen = true }, wantViewLen: 1},
		{name: "service callback cancels", cancelInCallback: true, wantViewLen: 1, wantServiceCalls: 1},
		{name: "owner borrow cancels after callback", configure: func(body *retainedCancellationBody, _ *retainedCancellationView) { body.cancelBorrowAfter = true }, wantViewLen: 1, wantServiceCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			body, owner, view := newHarness(ctx, cancel)
			if test.configure != nil {
				test.configure(owner, view)
			}
			serviceCalls := 0
			err := body.Borrow(ctx, func(credentialmemory.BorrowedView) error {
				serviceCalls++
				if test.cancelInCallback {
					cancel()
				}
				return nil
			})
			if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
				t.Fatalf("cancel-during retained borrow error = %v", err)
			}
			_, borrows, _ := owner.calls()
			viewLen, writes := view.calls()
			if borrows != 1 || viewLen != test.wantViewLen || serviceCalls != test.wantServiceCalls || writes != 0 {
				t.Fatalf("retained borrow calls = borrow:%d viewLen:%d service:%d writes:%d, want 1/%d/%d/0", borrows, viewLen, serviceCalls, writes, test.wantViewLen, test.wantServiceCalls)
			}
		})
	}

	for _, test := range []struct {
		name          string
		configureView func(*retainedCancellationView)
		configureSink func(*retainedCancellationSink)
		preCancel     bool
		wantViewLen   int
		wantViewWrite int
		wantSinkMax   int
		wantSinkWrite int
	}{
		{name: "pre-canceled write", preCancel: true},
		{name: "owner view Len cancels", configureView: func(view *retainedCancellationView) { view.cancelLen = true }, wantViewLen: 1},
		{name: "sink maximum cancels", configureSink: func(sink *retainedCancellationSink) { sink.cancelMax = true }, wantViewLen: 1, wantSinkMax: 1},
		{name: "owner WriteTo cancels before slicing fill", configureView: func(view *retainedCancellationView) { view.cancelWrite = true }, wantViewLen: 1, wantSinkMax: 1, wantViewWrite: 1},
		{name: "target write cancels", configureSink: func(sink *retainedCancellationSink) { sink.cancelWrite = true }, wantViewLen: 1, wantSinkMax: 1, wantViewWrite: 1, wantSinkWrite: 1},
	} {
		t.Run("write "+test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			view := &retainedCancellationView{value: []byte("canonical"), cancel: cancel}
			sink := &retainedCancellationSink{maximum: len(view.value), cancel: cancel}
			if test.configureView != nil {
				test.configureView(view)
			}
			if test.configureSink != nil {
				test.configureSink(sink)
			}
			if test.preCancel {
				cancel()
			}
			borrowed := borrowedPayloadView{owner: view, canonicalLength: len(view.value), offset: 0, length: len(view.value)}
			err := borrowed.WriteTo(ctx, sink)
			if !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
				t.Fatalf("cancel-during retained write error = %v", err)
			}
			viewLen, viewWrite := view.calls()
			sinkMax, sinkWrite := sink.calls()
			if viewLen != test.wantViewLen || viewWrite != test.wantViewWrite || sinkMax != test.wantSinkMax || sinkWrite != test.wantSinkWrite {
				t.Fatalf("retained write calls = viewLen:%d viewWrite:%d sinkMax:%d sinkWrite:%d, want %d/%d/%d/%d", viewLen, viewWrite, sinkMax, sinkWrite, test.wantViewLen, test.wantViewWrite, test.wantSinkMax, test.wantSinkWrite)
			}
		})
	}
}

func TestTransportDestroyWrappersApplyContextAndCancellationMatrix(t *testing.T) {
	for _, test := range []struct {
		name     string
		ctx      func() context.Context
		wantErr  error
		wantCall int
	}{
		{name: "plain nil", ctx: plainNilTransportContext, wantErr: ErrContractInvalidArgument},
		{name: "typed nil", ctx: func() context.Context { var value *typedNilTransportContext; return value }, wantErr: ErrContractTypedNil},
		{name: "pre-canceled", ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }, wantErr: ErrContractOwnership, wantCall: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := test.ctx()
			for _, wrapper := range []struct {
				name string
				call func(ReceivedBodyCapability) error
			}{
				{name: "receive", call: func(body ReceivedBodyCapability) error { return (receivedPayloadBody{owner: body}).Destroy(ctx) }},
				{name: "send", call: func(body ReceivedBodyCapability) error {
					return (SendPacket{arm: &sealedSendPacketArm{arm: sendExecStreamArm{body: body}}}).destroyBody(ctx)
				}},
			} {
				t.Run(wrapper.name, func(t *testing.T) {
					body := newTransportTestBody([]byte("secret"), 32)
					err := wrapper.call(body)
					if !errors.Is(err, test.wantErr) || errors.Is(err, context.Canceled) {
						t.Fatalf("destroy wrapper error = %v, want %v", err, test.wantErr)
					}
					body.state.mu.Lock()
					calls := len(body.state.destroyContexts)
					body.state.mu.Unlock()
					if calls != test.wantCall {
						t.Fatalf("destroy calls = %d, want %d", calls, test.wantCall)
					}
				})
			}
		})
	}

	for _, wrapper := range []struct {
		name string
		call func(context.Context, ReceivedBodyCapability) error
	}{
		{name: "receive", call: func(ctx context.Context, body ReceivedBodyCapability) error {
			return (receivedPayloadBody{owner: body}).Destroy(ctx)
		}},
		{name: "send", call: func(ctx context.Context, body ReceivedBodyCapability) error {
			return (SendPacket{arm: &sealedSendPacketArm{arm: sendExecStreamArm{body: body}}}).destroyBody(ctx)
		}},
	} {
		t.Run("cancel during "+wrapper.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			base := newTransportTestBody([]byte("secret"), 32)
			body := &cleanupPanicTransportBody{transportTestBody: base, cancel: cancel}
			if err := wrapper.call(ctx, body); !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
				t.Fatalf("cancel-during destroy error = %v", err)
			}
			base.state.mu.Lock()
			calls := len(base.state.destroyContexts)
			base.state.mu.Unlock()
			if calls != 1 {
				t.Fatalf("cancel-during destroy calls = %d, want 1", calls)
			}
		})
	}

	t.Run("cancel during right close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		base := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("right"))}}
		right := &cleanupPanicTransportRight{transportTestRight: base, cancel: cancel}
		if err := closeTransportRight(ctx, right); !errors.Is(err, ErrContractOwnership) || errors.Is(err, context.Canceled) {
			t.Fatalf("cancel-during right close error = %v", err)
		}
		base.state.mu.Lock()
		calls := len(base.state.closeContexts)
		base.state.mu.Unlock()
		if calls != 1 {
			t.Fatalf("cancel-during right close calls = %d, want 1", calls)
		}
	})
}

func TestTransportConstructorCleanupPanicsDoNotSkipOtherOwners(t *testing.T) {
	type boundary struct {
		name string
		call func(context.Context, ReceivedBodyCapability, ReceivedCapability) error
	}
	boundaries := []boundary{
		{name: "newReceivedPacket", call: func(ctx context.Context, body ReceivedBodyCapability, right ReceivedCapability) error {
			request, _ := NewReceiveRequest(2, 1, 1)
			_, err := NewReceivedBootstrapPacket(ctx, request, transportHeader(credentialprotocol.PacketTypeBootstrap, 3, 1), transportCredential(t), 1, body, 1, 1, 1, 1, "boot-1", "helper-1", right)
			return err
		}},
		{name: "newSendPacket", call: func(ctx context.Context, body ReceivedBodyCapability, right ReceivedCapability) error {
			header := transportJobHeader(credentialprotocol.PacketTypeExecStream, 7, 56)
			_, err := newSendPacket(ctx, header, sendExecStreamArm{revision: 1, streamKind: credentialprotocol.HelperExecStreamStdout, flags: credentialprotocol.HelperExecStreamFlagEOF, payloadSHA256: sha256.Sum256(nil), body: body}, right)
			return err
		}},
		{name: "failedReceivedInputs", call: func(ctx context.Context, body ReceivedBodyCapability, right ReceivedCapability) error {
			request, _ := NewReceiveRequest(2, 1, 1)
			_, err := failedReceivedInputs(ctx, request, body, right, ErrContractInvalidArgument)
			return err
		}},
	}
	for _, boundary := range boundaries {
		t.Run(boundary.name, func(t *testing.T) {
			for _, panicOwner := range []string{"body", "right"} {
				t.Run(panicOwner, func(t *testing.T) {
					ctx := context.Background()
					bodyBase := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 32)
					body := &cleanupPanicTransportBody{transportTestBody: bodyBase, panicDestroy: panicOwner == "body"}
					rightBase := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("right"))}}
					right := &cleanupPanicTransportRight{transportTestRight: rightBase, panicClose: panicOwner == "right"}
					err, panicked := captureTransportCleanupPanic(func() error { return boundary.call(ctx, body, right) })
					if panicked {
						t.Fatal("cleanup panic escaped constructor boundary")
					}
					if !errors.Is(err, ErrContractOwnership) {
						t.Fatalf("cleanup panic error = %v", err)
					}
					bodyBase.state.mu.Lock()
					bodyCalls := len(bodyBase.state.destroyContexts)
					bodyBase.state.mu.Unlock()
					rightBase.state.mu.Lock()
					rightCalls := len(rightBase.state.closeContexts)
					rightBase.state.mu.Unlock()
					if bodyCalls != 1 || rightCalls != 1 {
						t.Fatalf("cleanup attempts = body:%d right:%d, want 1/1", bodyCalls, rightCalls)
					}
				})
			}
		})
	}
}

func captureTransportCleanupPanic(operation func() error) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return operation(), false
}

func TestReceivedValidationIsStickyAgainstAdversarialBorrowAndWriteBehavior(t *testing.T) {
	canonical := []byte{byte(credentialprotocol.CloseReasonNormal)}
	invalid := []byte{byte(credentialprotocol.CloseReasonProtocolError)}
	for _, test := range []struct {
		name       string
		views      []adversarialTransportView
		concurrent bool
	}{
		{name: "concurrent duplicate valid callbacks", concurrent: true, views: []adversarialTransportView{{value: canonical, write: true}, {value: canonical, write: true}}},
		{name: "valid write then suppressed write error", views: []adversarialTransportView{{value: canonical, write: true, writeErr: errors.New("suppressed")}}},
		{name: "invalid write with suppressed callback result", views: []adversarialTransportView{{value: invalid, write: true}}},
		{name: "callback without write", views: []adversarialTransportView{{value: canonical}}},
		{name: "no callback", views: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &adversarialTransportBody{canonical: append([]byte(nil), canonical...), views: test.views, concurrent: test.concurrent}
			request, err := NewReceiveRequest(2, 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = NewReceivedCloseNotifyPacket(context.Background(), request, transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1), transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
			if err == nil {
				t.Fatal("adversarial body was accepted")
			}
			if !body.destroyed {
				t.Fatal("rejected adversarial body was not destroyed")
			}
		})
	}
}

func TestSendStreamWriteRequiresOneExactUnsuppressedDestinationWrite(t *testing.T) {
	payload := []byte("stdout")
	digest := sha256.Sum256(payload)
	canonical := transportStreamBody(3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, payload, digest)
	for _, test := range []struct {
		name       string
		views      []adversarialTransportView
		concurrent bool
		sinkErr    error
		wantCalls  int
	}{
		{name: "no write", views: []adversarialTransportView{{value: canonical}}, wantCalls: 0},
		{name: "concurrent duplicate writes", concurrent: true, views: []adversarialTransportView{{value: canonical, write: true}, {value: canonical, write: true}}, wantCalls: 1},
		{name: "wrong length", views: []adversarialTransportView{{value: canonical[:len(canonical)-1], write: true}}, wantCalls: 0},
		{name: "suppressed destination error", views: []adversarialTransportView{{value: canonical, write: true}}, sinkErr: errors.New("destination failed"), wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &adversarialTransportBody{canonical: append([]byte(nil), canonical...), views: []adversarialTransportView{{value: canonical, write: true}}}
			header := transportJobHeader(credentialprotocol.PacketTypeExecStream, 7, uint32(len(canonical)))
			packet, err := newExecStreamPacket(context.Background(), header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), digest, body)
			if err != nil {
				t.Fatal(err)
			}
			body.views = test.views
			body.concurrent = test.concurrent
			sink := &countingTransportSink{maximum: len(canonical), err: test.sinkErr}
			if err := packet.WriteCanonicalBody(context.Background(), sink); !errors.Is(err, ErrContractOwnership) {
				t.Fatalf("adversarial write error = %v", err)
			}
			if got := sink.callCount(); got != test.wantCalls {
				t.Fatalf("destination writes = %d, want %d", got, test.wantCalls)
			}
			if err := packet.destroyBody(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReceivedExecPlanClaimOwnershipMatrix(t *testing.T) {
	ctx := context.Background()
	decoded := credentialprotocol.HelperExecBody{Revision: 2, ExecBindingID: "exec-1", Plan: transportExecPlan()}
	encoded, err := credentialprotocol.EncodeHelperExecBody(decoded)
	if err != nil {
		t.Fatal(err)
	}
	header := transportJobHeader(credentialprotocol.PacketTypeExec, 2, uint32(len(encoded)))
	credential := transportCredential(t)

	for name, plan := range map[string]ExecPlanCapability{
		"zero": {},
		"destroyed": func() ExecPlanCapability {
			value, err := NewExecPlanCapability(decoded.Plan)
			if err != nil {
				t.Fatal(err)
			}
			value.destroy()
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := NewReceiveRequest(2, uint32(len(encoded)), 0)
			body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
			if _, err := NewReceivedExecPacket(ctx, request, header, credential, 1, body, 0, decoded, plan); !errors.Is(err, ErrContractDestroyed) {
				t.Fatalf("pre-transfer plan error = %v", err)
			}
			if body.state.lenCalls != 0 || body.state.borrows != 0 || len(body.state.destroyContexts) != 0 {
				t.Fatal("pre-transfer plan rejection touched body")
			}
			validPlan, err := NewExecPlanCapability(decoded.Plan)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := NewReceivedExecPacket(ctx, request, header, credential, 1, body, 0, decoded, validPlan)
			if err != nil {
				t.Fatalf("pre-transfer rejection consumed request: %v", err)
			}
			arm, _ := packet.Exec()
			arm.transactionSeed.Close()
			validPlan.destroy()
		})
	}

	claimedPlan, err := NewExecPlanCapability(decoded.Plan)
	if err != nil {
		t.Fatal(err)
	}
	claimed := false
	err = claimedPlan.claimAndMatch(decoded.Plan, &claimed)
	if err != nil || !claimed {
		t.Fatalf("seed claim = %v/%v", claimed, err)
	}
	request, _ := NewReceiveRequest(2, uint32(len(encoded)), 0)
	body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	if _, err := NewReceivedExecPacket(ctx, request, header, credential, 1, body, 0, decoded, claimedPlan); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("already-claimed plan error = %v", err)
	}
	if body.state.lenCalls != 0 || body.state.borrows != 0 || len(body.state.destroyContexts) != 0 {
		t.Fatal("already-claimed rejection touched body")
	}
	claimedPlan.destroy()

	mismatchPlan, err := NewExecPlanCapability(decoded.Plan)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := decoded
	mismatched.Plan.Arguments = []string{"different"}
	mismatchEncoded, err := credentialprotocol.EncodeHelperExecBody(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	mismatchRequest, _ := NewReceiveRequest(2, uint32(len(mismatchEncoded)), 0)
	mismatchBody := newTransportTestBody(mismatchEncoded, credentialprotocol.MaxHelperPacketBodyBytes)
	if _, err := NewReceivedExecPacket(ctx, mismatchRequest, transportJobHeader(credentialprotocol.PacketTypeExec, 2, uint32(len(mismatchEncoded))), credential, 1, mismatchBody, 0, mismatched, mismatchPlan); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("claimed mismatch error = %v", err)
	}
	assertBodyDestroyedAndWiped(t, mismatchBody)
	if mismatchPlan.state == nil || !mismatchPlan.state.destroyed {
		t.Fatal("claimed mismatched plan was not destroyed")
	}

	sharedPlan, err := NewExecPlanCapability(decoded.Plan)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		packet ReceivedPacket
		err    error
		body   transportTestBody
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	for range 2 {
		request, _ := NewReceiveRequest(2, uint32(len(encoded)), 0)
		body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
		go func() {
			<-start
			packet, err := NewReceivedExecPacket(ctx, request, header, credential, 1, body, 0, decoded, sharedPlan)
			results <- outcome{packet: packet, err: err, body: body}
		}()
	}
	close(start)
	successes, losers := 0, 0
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			arm, ok := result.packet.Exec()
			if !ok {
				t.Fatal("claim winner lost exec arm")
			}
			arm.transactionSeed.Close()
		case errors.Is(result.err, ErrContractOwnership):
			losers++
			if result.body.state.lenCalls != 0 || result.body.state.borrows != 0 || len(result.body.state.destroyContexts) != 0 {
				t.Fatal("losing concurrent claim touched body")
			}
		default:
			t.Fatalf("concurrent claim error = %v", result.err)
		}
	}
	if successes != 1 || losers != 1 {
		t.Fatalf("concurrent claim outcomes = %d success/%d loser", successes, losers)
	}
}

func TestTransactionStartConstructorsCleanOwnedStateOnDependencyPanic(t *testing.T) {
	ctx := context.Background()
	credential := transportCredential(t)

	prepareDigest := sha256.Sum256([]byte("file"))
	prepare := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 99, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "binding-1", Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: "secret/file", DeclaredFileBytes: 4, FileSHA256: prepareDigest}}}
	prepareEncoded, err := credentialprotocol.EncodeHelperPrepareBeginBody(prepare)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewManifestCapability(prepare.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	prepareBody := &panicTransportBody{}
	prepareRequest, _ := NewReceiveRequest(2, uint32(len(prepareEncoded)), 0)
	assertPanics(t, func() {
		_, _ = NewReceivedPrepareBeginPacket(ctx, prepareRequest, transportJobHeader(credentialprotocol.PacketTypePrepareBegin, 2, uint32(len(prepareEncoded))), credential, 1, prepareBody, 0, prepare, manifest)
	})
	if !prepareBody.destroyed {
		t.Fatal("prepare panic did not destroy received body")
	}

	exec := credentialprotocol.HelperExecBody{Revision: 2, ExecBindingID: "exec-1", Plan: transportExecPlan()}
	execEncoded, err := credentialprotocol.EncodeHelperExecBody(exec)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewExecPlanCapability(exec.Plan)
	if err != nil {
		t.Fatal(err)
	}
	execBody := &panicTransportBody{}
	execRequest, _ := NewReceiveRequest(2, uint32(len(execEncoded)), 0)
	assertPanics(t, func() {
		_, _ = NewReceivedExecPacket(ctx, execRequest, transportJobHeader(credentialprotocol.PacketTypeExec, 2, uint32(len(execEncoded))), credential, 1, execBody, 0, exec, plan)
	})
	if !execBody.destroyed || plan.state == nil || !plan.state.destroyed {
		t.Fatal("exec panic did not destroy body and claimed plan")
	}
}

func TestReceivedExecCleanupFailureOverridesConstructorError(t *testing.T) {
	ctx := context.Background()
	exec := credentialprotocol.HelperExecBody{Revision: 2, ExecBindingID: "invalid id", Plan: transportExecPlan()}
	plan, err := NewExecPlanCapability(exec.Plan)
	if err != nil {
		t.Fatal(err)
	}
	body := &panicTransportBody{destroyErr: errors.New("destroy failed")}
	request, _ := NewReceiveRequest(2, 1, 0)
	_, err = NewReceivedExecPacket(ctx, request, transportJobHeader(credentialprotocol.PacketTypeExec, 2, 1), transportCredential(t), 1, body, 0, exec, plan)
	if !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("cleanup failure error = %v", err)
	}
	if !body.destroyed || plan.state == nil || !plan.state.destroyed {
		t.Fatal("cleanup failure did not destroy claimed owners")
	}
}

func assertPanics(t *testing.T, operation func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("operation did not panic")
		}
	}()
	operation()
}

func TestTransportNilContextIsPreTransferAndDoesNotConsumeOwnership(t *testing.T) {
	bodyBytes := transportBootstrapBody(t, 42, 998, 998, "boot-1", "helper-1")
	body := newTransportTestBody(bodyBytes, 256)
	right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("pidfd"))}}
	request, err := NewReceiveRequest(2, uint32(len(bodyBytes)), 1)
	if err != nil {
		t.Fatal(err)
	}
	header := transportHeader(credentialprotocol.PacketTypeBootstrap, 2, uint32(len(bodyBytes)))
	if _, err := NewReceivedBootstrapPacket(plainNilTransportContext(), request, header, transportCredential(t), 1, body, 1, 42, 998, 998, "boot-1", "helper-1", right); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("nil-context receive error = %v", err)
	}
	if body.state.lenCalls != 0 || body.state.digestCalls != 0 || body.state.borrows != 0 || len(body.state.destroyContexts) != 0 {
		t.Fatalf("nil-context receive touched body: len=%d digest=%d borrow=%d destroy=%d", body.state.lenCalls, body.state.digestCalls, body.state.borrows, len(body.state.destroyContexts))
	}
	if right.state.kindCalls != 0 || right.state.digestCalls != 0 || len(right.state.closeContexts) != 0 {
		t.Fatalf("nil-context receive touched right: kind=%d digest=%d close=%d", right.state.kindCalls, right.state.digestCalls, len(right.state.closeContexts))
	}

	ctx := context.WithValue(context.Background(), transportContextKey{}, "receive-owner")
	packet, err := NewReceivedBootstrapPacket(ctx, request, header, transportCredential(t), 1, body, 1, 42, 998, 998, "boot-1", "helper-1", right)
	if err != nil {
		t.Fatalf("request was consumed by nil-context precondition: %v", err)
	}
	if packet.right == nil {
		t.Fatal("successful retry lost right ownership")
	}
	if err := packet.right.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if len(right.state.closeContexts) != 1 || right.state.closeContexts[0] != ctx {
		t.Fatalf("right close contexts = %#v", right.state.closeContexts)
	}

	streamPayload := []byte("stdout")
	streamDigest := sha256.Sum256(streamPayload)
	streamBytes := transportStreamBody(3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, streamPayload, streamDigest)
	streamBody := newTransportTestBody(streamBytes, 256)
	streamHeader := transportJobHeader(credentialprotocol.PacketTypeExecStream, 7, uint32(len(streamBytes)))
	if _, err := newExecStreamPacket(plainNilTransportContext(), streamHeader, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(streamPayload)), streamDigest, streamBody); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("nil-context send-body constructor error = %v", err)
	}
	if streamBody.state.lenCalls != 0 || streamBody.state.digestCalls != 0 || streamBody.state.borrows != 0 || len(streamBody.state.destroyContexts) != 0 {
		t.Fatal("nil-context send-body constructor touched body")
	}
	sendRight := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilitySSHConnection, digest: sha256.Sum256([]byte("ssh-right"))}}
	if _, err := newSSHAcceptedPacket(plainNilTransportContext(), transportJobHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 8, 43), 1, 0, 1, sendRight.state.digest, sendRight); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("nil-context send-right constructor error = %v", err)
	}
	if sendRight.state.kindCalls != 0 || sendRight.state.digestCalls != 0 || len(sendRight.state.closeContexts) != 0 {
		t.Fatal("nil-context send-right constructor touched right")
	}

	metadata, err := newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	sink := &transportTestSink{maximum: 1}
	if err := metadata.WriteCanonicalBody(plainNilTransportContext(), sink); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("nil-context write error = %v", err)
	}
	if len(sink.value) != 0 {
		t.Fatal("nil-context write touched sink")
	}
	if err := metadata.WriteCanonicalBody(ctx, sink); err != nil {
		t.Fatalf("nil-context write consumed one-shot owner: %v", err)
	}
}

func TestTransportUsesExactCallerContextForReceiveAndSendOwnership(t *testing.T) {
	ctx := context.WithValue(context.Background(), transportContextKey{}, "exact-owner")
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 32)
	request, err := NewReceiveRequest(2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceivedCloseNotifyPacket(ctx, request, transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1), transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}); err != nil {
		t.Fatal(err)
	}
	assertExactTransportContexts(t, ctx, body.state.borrowContexts, "receive borrow")
	assertExactTransportContexts(t, ctx, body.state.writeContexts, "receive write")
	assertExactTransportContexts(t, ctx, body.state.destroyContexts, "receive destroy")

	payload := []byte("stdout")
	digest := sha256.Sum256(payload)
	encoded := transportStreamBody(3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, payload, digest)
	streamBody := newTransportTestBody(encoded, 256)
	header := transportJobHeader(credentialprotocol.PacketTypeExecStream, 7, uint32(len(encoded)))
	packet, err := newExecStreamPacket(ctx, header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), digest, streamBody)
	if err != nil {
		t.Fatal(err)
	}
	streamBody.state.borrowContexts = nil
	streamBody.state.writeContexts = nil
	writeCtx := context.WithValue(context.Background(), transportContextKey{}, "exact-write")
	if err := packet.WriteCanonicalBody(writeCtx, &transportTestSink{maximum: len(encoded)}); err != nil {
		t.Fatal(err)
	}
	assertExactTransportContexts(t, writeCtx, streamBody.state.borrowContexts, "send write borrow")
	assertExactTransportContexts(t, writeCtx, streamBody.state.writeContexts, "send write copy")
	if err := packet.destroyBody(ctx); err != nil {
		t.Fatal(err)
	}
	if got := streamBody.state.destroyContexts[len(streamBody.state.destroyContexts)-1]; got != ctx {
		t.Fatal("send body destroy did not receive constructor/service context")
	}

	badRight := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("wrong-kind"))}}
	if _, err := newSSHAcceptedPacket(ctx, transportJobHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 8, 43), 1, 0, 1, badRight.state.digest, badRight); !errors.Is(err, ErrContractCapability) {
		t.Fatalf("wrong-kind right error = %v", err)
	}
	assertExactTransportContexts(t, ctx, badRight.state.closeContexts, "send right close")
}

func assertExactTransportContexts(t *testing.T, want context.Context, got []context.Context, operation string) {
	t.Helper()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("%s contexts = %#v, want exact caller context once", operation, got)
	}
}

func TestReceiveRequestBoundsAndSharedOneShotOwnership(t *testing.T) {
	for _, tc := range []struct {
		sequence uint64
		body     uint32
		rights   uint32
		wantErr  error
	}{
		{sequence: 1, body: 0, rights: 0},
		{sequence: math.MaxUint32, body: credentialprotocol.MaxHelperPacketBodyBytes, rights: 1},
		{sequence: 0, body: 1, rights: 0},
		{sequence: math.MaxUint32 + 1, body: 1, rights: 0, wantErr: ErrContractInvalidArgument},
		{sequence: 1, body: credentialprotocol.MaxHelperPacketBodyBytes + 1, rights: 0, wantErr: ErrContractInvalidArgument},
		{sequence: 1, body: 1, rights: 2, wantErr: ErrContractInvalidArgument},
	} {
		request, err := NewReceiveRequest(tc.sequence, tc.body, tc.rights)
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("NewReceiveRequest(%d,%d,%d) error = %v, want %v", tc.sequence, tc.body, tc.rights, err, tc.wantErr)
		}
		if tc.wantErr == nil && (request.NextSequence() != tc.sequence || request.MaximumBodyBytes() != tc.body || request.ExpectedRights() != tc.rights) {
			t.Fatalf("receive request accessors = %d/%d/%d", request.NextSequence(), request.MaximumBodyBytes(), request.ExpectedRights())
		}
		if tc.wantErr != nil && request != (ReceiveRequest{}) {
			t.Fatal("invalid receive request returned nonzero value")
		}
	}

	request, err := NewReceiveRequest(2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	copyRequest := request
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, uint32(body.Len()))
	packet, err := NewReceivedCloseNotifyPacket(context.Background(), request, header, transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil || packet.Type() != credentialprotocol.PacketTypeCloseNotify {
		t.Fatalf("first seal = %#v, %v", packet, err)
	}
	secondBody := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	if _, err := NewReceivedCloseNotifyPacket(context.Background(), copyRequest, header, transportCredential(t), 1, secondBody, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("copied request reuse error = %v", err)
	}
	assertBodyDestroyedAndWiped(t, secondBody)
}

func TestReceivedKernelCredentialBoundsAndOpacity(t *testing.T) {
	for _, pid := range []uint32{1, math.MaxInt32} {
		credential, err := NewReceivedKernelCredential(pid, 0, math.MaxUint32)
		if err != nil {
			t.Fatalf("pid %d: %v", pid, err)
		}
		assertLiveOpaque(t, credential)
	}
	for _, pid := range []uint32{0, math.MaxInt32 + 1, math.MaxUint32} {
		credential, err := NewReceivedKernelCredential(pid, 0, 0)
		if !errors.Is(err, ErrContractInvalidArgument) || credential != (ReceivedKernelCredential{}) {
			t.Fatalf("pid %d = %#v, %v", pid, credential, err)
		}
	}
}

func TestReceivedCloseNotifyCorrelationAndFullCapacityCleanup(t *testing.T) {
	request, _ := NewReceiveRequest(7, 1, 0)
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 128)
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 8, 1)
	packet, err := NewReceivedCloseNotifyPacket(context.Background(), request, header, transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if !errors.Is(err, ErrContractCorrelation) || packet != (ReceivedPacket{}) {
		t.Fatalf("sequence mismatch = %#v, %v", packet, err)
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestReceivedPacketRejectsBodyCapabilityDigestDrift(t *testing.T) {
	request, _ := NewReceiveRequest(7, 1, 0)
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 128)
	lying := transportTestLyingBody{transportTestBody: body}
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 7, 1)
	packet, err := NewReceivedCloseNotifyPacket(context.Background(), request, header, transportCredential(t), 1, lying, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if !errors.Is(err, ErrContractCorrelation) || packet != (ReceivedPacket{}) {
		t.Fatalf("body digest drift = %#v, %v", packet, err)
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestMalformedConstructorStillConsumesReceiveOwnership(t *testing.T) {
	request, _ := NewReceiveRequest(7, 1, 0)
	body := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 7, 1)
	if _, err := NewReceivedCloseNotifyPacket(context.Background(), request, header, transportCredential(t), 1, body, 0, credentialprotocol.HelperCloseNotifyBody{}); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("malformed close error = %v", err)
	}
	secondBody := newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 64)
	if _, err := NewReceivedCloseNotifyPacket(context.Background(), request, header, transportCredential(t), 1, secondBody, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("malformed request reuse error = %v", err)
	}
	assertBodyDestroyedAndWiped(t, secondBody)
}

func TestReceivedPrepareBeginUsesCanonicalCodecAndTypedArm(t *testing.T) {
	digest := sha256.Sum256([]byte("file"))
	decoded := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 99, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "binding-1", Mode: credentialprotocol.DeliveryModeFileTmpfs, TargetPath: "secret/file", DeclaredFileBytes: 4, FileSHA256: digest}}}
	encoded, err := credentialprotocol.EncodeHelperPrepareBeginBody(decoded)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewManifestCapability(decoded.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReceiveRequest(2, uint32(len(encoded)), 0)
	body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	header := transportJobHeader(credentialprotocol.PacketTypePrepareBegin, 2, uint32(len(encoded)))
	packet, err := NewReceivedPrepareBeginPacket(context.Background(), request, header, transportCredential(t), 1, body, 0, decoded, manifest)
	if err != nil {
		t.Fatal(err)
	}
	arm, ok := packet.PrepareBegin()
	if !ok || arm.Revision() != 1 || arm.ExpiryUnixNano() != 99 || arm.Manifest().SHA256() != manifest.SHA256() {
		t.Fatalf("prepare arm = %#v, %v", arm, ok)
	}
	if arm.transaction == nil {
		t.Fatal("prepare arm did not retain the protocol transaction")
	}
	snapshot := arm.transaction.Snapshot()
	if snapshot.Terminal || snapshot.Committed || snapshot.ExpectedFileCount != 1 || snapshot.NextBindingIndex != 0 {
		t.Fatalf("prepare transaction snapshot = %#v", snapshot)
	}
	arm.transaction.Close()
	if _, ok := packet.Exec(); ok {
		t.Fatal("wrong typed arm matched")
	}
	if packet.Header() != header {
		t.Fatal("header accessor changed header")
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestReceivedSensitivePacketRetainsBodyAndRejectsDigestMismatch(t *testing.T) {
	payload := []byte("secret")
	digest := sha256.Sum256(payload)
	bodyBytes := make([]byte, 46+len(payload))
	bodyBytes[7] = 1
	bodyBytes[9] = 1
	bodyBytes[13] = byte(len(payload))
	copy(bodyBytes[14:46], digest[:])
	copy(bodyBytes[46:], payload)
	request, _ := NewReceiveRequest(2, uint32(len(bodyBytes)), 0)
	body := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	header := transportJobHeader(credentialprotocol.PacketTypePrepareFile, 2, uint32(len(bodyBytes)))
	packet, err := NewReceivedPrepareFilePacket(context.Background(), request, header, transportCredential(t), 1, body, 0, 1, 1, uint32(len(payload)), digest)
	if err != nil {
		t.Fatal(err)
	}
	arm, ok := packet.PrepareFile()
	if !ok || arm.Revision() != 1 || arm.BindingIndex() != 1 || arm.FileLength() != uint32(len(payload)) || arm.FileSHA256() != digest {
		t.Fatalf("file arm = %#v, %v", arm, ok)
	}
	if body.state.destroyed {
		t.Fatal("sensitive body destroyed before service ownership")
	}
	if packet.body.Len() != uint32(len(payload)) || packet.body.SHA256() != digest {
		t.Fatalf("private retained payload body = %d/%x", packet.body.Len(), packet.body.SHA256())
	}
	body.state.mu.Lock()
	if !reflect.DeepEqual(body.state.region[:body.state.length], bodyBytes) {
		body.state.mu.Unlock()
		t.Fatal("retained transport owner no longer holds the full canonical body")
	}
	payloadAddress := reflect.ValueOf(body.state.region[46 : 46+len(payload)]).Pointer()
	body.state.mu.Unlock()
	borrowCalls := 0
	err = packet.body.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
		borrowCalls++
		if view.Len() != len(payload) {
			t.Fatalf("borrowed payload length = %d, want %d", view.Len(), len(payload))
		}
		sink := &transportSubviewTestSink{maximum: len(payload), want: payload, wantAddress: payloadAddress}
		if writeErr := view.WriteTo(context.Background(), sink); writeErr != nil {
			return writeErr
		}
		if !sink.called || !sink.sameBacking {
			t.Fatal("service payload subview copied or did not synchronously write")
		}
		return nil
	})
	if err != nil || borrowCalls != 1 {
		t.Fatalf("borrow retained payload = %v, calls %d", err, borrowCalls)
	}

	badRequest, _ := NewReceiveRequest(3, uint32(len(bodyBytes)), 0)
	badBody := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	badDigest := sha256.Sum256([]byte("changed"))
	if _, err := NewReceivedPrepareFilePacket(context.Background(), badRequest, transportJobHeader(credentialprotocol.PacketTypePrepareFile, 3, uint32(len(bodyBytes))), transportCredential(t), 1, badBody, 0, 1, 1, uint32(len(payload)), badDigest); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("private digest mismatch = %v", err)
	}
	assertBodyDestroyedAndWiped(t, badBody)
}

func TestReceivedBootstrapRightOwnershipAndTypedNil(t *testing.T) {
	bodyBytes := transportBootstrapBody(t, 42, 998, 998, "boot-1", "helper-1")
	header := transportHeader(credentialprotocol.PacketTypeBootstrap, 1, uint32(len(bodyBytes)))
	request, _ := NewReceiveRequest(1, uint32(len(bodyBytes)), 1)
	body := newTransportTestBody(bodyBytes, 256)
	right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: sha256.Sum256([]byte("pidfd"))}}
	packet, err := NewReceivedBootstrapPacket(context.Background(), request, header, transportCredential(t), 1, body, 1, 42, 998, 998, "boot-1", "helper-1", right)
	if err != nil {
		t.Fatal(err)
	}
	arm, ok := packet.Bootstrap()
	if !ok || arm.BootGeneration() != "boot-1" || arm.HelperGeneration() != "helper-1" || arm.AgentIdentitySHA256() == ([32]byte{}) {
		t.Fatalf("bootstrap arm = %#v, %v", arm, ok)
	}
	if right.state.closed {
		t.Fatal("right closed after successful transfer")
	}
	assertBodyDestroyedAndWiped(t, body)

	badRequest, _ := NewReceiveRequest(2, uint32(len(bodyBytes)), 1)
	badBody := newTransportTestBody(bodyBytes, 256)
	var nilRight *transportTestRight
	if _, err := NewReceivedBootstrapPacket(context.Background(), badRequest, transportHeader(credentialprotocol.PacketTypeBootstrap, 2, uint32(len(bodyBytes))), transportCredential(t), 1, badBody, 1, 42, 998, 998, "boot-1", "helper-1", nilRight); !errors.Is(err, ErrContractTypedNil) {
		t.Fatalf("typed-nil right = %v", err)
	}
	assertBodyDestroyedAndWiped(t, badBody)
}

type transportTestSink struct {
	maximum int
	value   []byte
	err     error
}

type transportSubviewTestSink struct {
	maximum     int
	want        []byte
	wantAddress uintptr
	called      bool
	sameBacking bool
}

func (sink *transportSubviewTestSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *transportSubviewTestSink) WriteCredential(value []byte) error {
	sink.called = true
	sink.sameBacking = len(value) > 0 && reflect.ValueOf(value).Pointer() == sink.wantAddress
	if !reflect.DeepEqual(value, sink.want) {
		return errors.New("unexpected payload subview")
	}
	return nil
}

type transportRetainingTestSink struct {
	maximum int
	alias   []byte
	copy    []byte
	err     error
}

type transportTrackingSendArm struct {
	state  *transportTrackingSendState
	length uint32
	fail   bool
}

type transportTrackingSendState struct{ alias []byte }

func (transportTrackingSendArm) sendPacketArm()                       {}
func (arm transportTrackingSendArm) canonicalLength() (uint32, error) { return arm.length, nil }
func (arm transportTrackingSendArm) encodeCanonicalTo(dst []byte) error {
	arm.state.alias = dst
	for index := range dst {
		dst[index] = byte(credentialprotocol.CloseReasonNormal)
	}
	if arm.fail {
		return errors.New("encode failed")
	}
	return nil
}

func (sink *transportRetainingTestSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *transportRetainingTestSink) WriteCredential(value []byte) error {
	sink.alias = value
	sink.copy = append(sink.copy[:0], value...)
	return sink.err
}

func (sink *transportTestSink) MaxCredentialBytes() int { return sink.maximum }
func (sink *transportTestSink) WriteCredential(value []byte) error {
	if sink.err != nil {
		return sink.err
	}
	sink.value = append(sink.value[:0], value...)
	return nil
}

func TestSendPacketClosedAccessorsAndSynchronousCopy(t *testing.T) {
	body := credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}
	encoded, err := credentialprotocol.EncodeHelperCloseNotifyBody(body)
	if err != nil {
		t.Fatal(err)
	}
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, uint32(len(encoded)))
	packet, err := newCloseNotifyPacket(context.Background(), header, body)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Type() != credentialprotocol.PacketTypeCloseNotify || packet.Header() != header || packet.EncodedBodyLength() != 1 || packet.BodySHA256() != sha256.Sum256(encoded) || packet.RightsCount() != 0 || packet.Right() != nil {
		t.Fatalf("send accessors = %#v", packet)
	}
	sink := &transportTestSink{maximum: 1}
	if err := packet.WriteCanonicalBody(context.Background(), sink); err != nil || !reflect.DeepEqual(sink.value, encoded) {
		t.Fatalf("WriteCanonicalBody = %x, %v", sink.value, err)
	}
	encoded[0] = 0xff
	if sink.value[0] != byte(credentialprotocol.CloseReasonNormal) {
		t.Fatal("sink output aliased caller bytes")
	}
	typedNilPacket, err := newCloseNotifyPacket(context.Background(), header, body)
	if err != nil {
		t.Fatal(err)
	}
	var nilSink *transportTestSink
	if err := typedNilPacket.WriteCanonicalBody(context.Background(), nilSink); !errors.Is(err, ErrContractTypedNil) {
		t.Fatalf("typed-nil sink error = %v", err)
	}
	if err := typedNilPacket.WriteCanonicalBody(context.Background(), &transportTestSink{maximum: 1}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("typed-nil write did not consume packet ownership: %v", err)
	}
}

func TestSendPacketWipesSafeEncodingAfterSynchronousWrite(t *testing.T) {
	body := credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}
	packet, err := newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), body)
	if err != nil {
		t.Fatal(err)
	}
	sink := &transportRetainingTestSink{maximum: 1}
	if err := packet.WriteCanonicalBody(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sink.copy, []byte{byte(credentialprotocol.CloseReasonNormal)}) {
		t.Fatalf("synchronous safe encoding = %x", sink.copy)
	}
	if len(sink.alias) != 1 || !allZeroBytes(sink.alias[:cap(sink.alias)]) {
		t.Fatalf("safe encoding retained after write = %x", sink.alias)
	}
}

func TestSendPacketWipesSafeEncodingAndConsumesOwnershipOnSinkError(t *testing.T) {
	packet, err := newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	sink := &transportRetainingTestSink{maximum: 1, err: errors.New("sink failed")}
	if err := packet.WriteCanonicalBody(context.Background(), sink); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("sink write error = %v", err)
	}
	if len(sink.alias) != 1 || !allZeroBytes(sink.alias[:cap(sink.alias)]) {
		t.Fatalf("failed safe encoding retained after write = %x", sink.alias)
	}
	if err := packet.WriteCanonicalBody(context.Background(), &transportTestSink{maximum: 1}); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("failed write did not consume packet ownership: %v", err)
	}
}

func TestSendPacketWipesSafeEncodingAfterConstruction(t *testing.T) {
	state := &transportTrackingSendState{}
	arm := transportTrackingSendArm{state: state, length: 1}
	if err := withCanonicalScratch(arm, 1, func(encoded []byte) error {
		if !reflect.DeepEqual(encoded, []byte{byte(credentialprotocol.CloseReasonNormal)}) {
			t.Fatalf("test-only scratch = %x", encoded)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(state.alias) != 1 || !allZeroBytes(state.alias[:cap(state.alias)]) {
		t.Fatalf("safe encoding retained after construction = %x", state.alias)
	}

	failedState := &transportTrackingSendState{}
	if err := withCanonicalScratch(transportTrackingSendArm{state: failedState, length: 1, fail: true}, 1, func([]byte) error { return nil }); !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("failing safe arm error = %v", err)
	}
	if len(failedState.alias) != 1 || !allZeroBytes(failedState.alias[:cap(failedState.alias)]) {
		t.Fatal("failed constructor did not wipe scratch through capacity")
	}
}

func TestSendPacketSnapshotsSafeArmBeforeTransportOwnership(t *testing.T) {
	body := credentialprotocol.HelperResponseBody{
		RequestType: credentialprotocol.PacketTypePrepareCommit,
		Disposition: credentialprotocol.ResponseDispositionAccepted,
		Revision:    1,
		Prepare: &credentialprotocol.HelperPrepareResponseResult{
			ExpiresAtUnixNano: 1,
			ActiveProofID:     "active",
			ExecBindingID:     "exec",
			BindingProofs: []credentialprotocol.HelperBindingProof{{
				BindingID: "binding",
				Mode:      credentialprotocol.DeliveryModeHTTPProxy,
				ProofID:   "proof",
			}},
		},
	}
	canonical, err := credentialprotocol.EncodeHelperResponseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := newResponsePacket(context.Background(), transportJobHeader(credentialprotocol.PacketTypeResponse, 9, uint32(len(canonical))), body)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(canonical)
	body.Prepare.BindingProofs[0].ProofID = "other"
	if got := packet.BodySHA256(); got != wantDigest {
		t.Fatalf("caller alias mutation changed sealed send digest: got %x, want %x", got, wantDigest)
	}
	sink := &transportTestSink{maximum: len(canonical)}
	if err := packet.WriteCanonicalBody(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sink.value, canonical) {
		t.Fatalf("caller alias mutation changed sealed send body: got %x, want %x", sink.value, canonical)
	}
}

func TestSendPacketDeepSnapshotsEveryResponseResultArm(t *testing.T) {
	digest := sha256.Sum256([]byte("digest"))
	tests := []struct {
		name   string
		body   credentialprotocol.HelperResponseBody
		mutate func()
	}{
		{
			name: "prepare",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypePrepareCommit, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: 1, Prepare: &credentialprotocol.HelperPrepareResponseResult{
				ExpiresAtUnixNano: 1, ActiveProofID: "active", ExecBindingID: "exec", BindingProofs: []credentialprotocol.HelperBindingProof{{BindingID: "binding", Mode: credentialprotocol.DeliveryModeHTTPProxy, ProofID: "proof"}},
			}},
		},
		{
			name: "renew",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeRenew, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: 1, Renew: &credentialprotocol.HelperRenewResponseResult{ExpiresAtUnixNano: 1, ReplacementActiveProofID: "replacement"}},
		},
		{
			name: "revoke",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeRevoke, Disposition: credentialprotocol.ResponseDispositionCleanupComplete, Revision: 1, Revoke: &credentialprotocol.HelperRevokeResponseResult{CleanupProofID: "cleanup", AuthorityAbsent: true, ResourcesAbsent: true}},
		},
		{
			name: "exec",
			body: credentialprotocol.HelperResponseBody{RequestType: credentialprotocol.PacketTypeExec, Disposition: credentialprotocol.ResponseDispositionAccepted, Revision: 1, Exec: &credentialprotocol.HelperExecResponseResult{ExitCode: 1, StdinBytes: 1, StdinSHA256: digest, StdoutBytes: 1, StdoutSHA256: digest, StderrBytes: 1, StderrSHA256: digest, ExecTransactionSHA256: digest}},
		},
	}
	for index := range tests {
		test := &tests[index]
		switch test.name {
		case "prepare":
			test.mutate = func() {
				test.body.Prepare.ActiveProofID = "changed"
				test.body.Prepare.BindingProofs[0].ProofID = "changed"
			}
		case "renew":
			test.mutate = func() { test.body.Renew.ReplacementActiveProofID = "changed" }
		case "revoke":
			test.mutate = func() { test.body.Revoke.CleanupProofID = "changed" }
		case "exec":
			test.mutate = func() { test.body.Exec.ExitCode = 2 }
		}
		t.Run(test.name, func(t *testing.T) {
			canonical, err := credentialprotocol.EncodeHelperResponseBody(test.body)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := newResponsePacket(context.Background(), transportJobHeader(credentialprotocol.PacketTypeResponse, 9, uint32(len(canonical))), test.body)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate()
			if packet.BodySHA256() != sha256.Sum256(canonical) {
				t.Fatal("caller mutation changed pinned response digest")
			}
			sink := &transportTestSink{maximum: len(canonical)}
			if err := packet.WriteCanonicalBody(context.Background(), sink); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(sink.value, canonical) {
				t.Fatal("caller mutation changed pinned response encoding")
			}
			if packet.BodySHA256() != sha256.Sum256(canonical) {
				t.Fatal("response digest changed after write")
			}
		})
	}
}

func TestSendPacketWriteIsOneUseAcrossConcurrentAliases(t *testing.T) {
	packet, err := newCloseNotifyPacket(context.Background(), transportHeader(credentialprotocol.PacketTypeCloseNotify, 9, 1), credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := packet.BodySHA256()
	const contenders = 32
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		alias := packet
		go func() {
			defer wait.Done()
			results <- alias.WriteCanonicalBody(context.Background(), &transportTestSink{maximum: 1})
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for writeErr := range results {
		if writeErr == nil {
			successes++
		} else if !errors.Is(writeErr, ErrContractOwnership) {
			t.Fatalf("alias write error = %v", writeErr)
		}
	}
	if successes != 1 {
		t.Fatalf("successful alias writes = %d, want 1", successes)
	}
	if packet.BodySHA256() != wantDigest {
		t.Fatal("pinned body digest changed after write")
	}
}

func TestSendPacketSSHRightCardinalityAndOwnership(t *testing.T) {
	digest := sha256.Sum256([]byte("relay"))
	right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilitySSHConnection, digest: digest}}
	header := transportJobHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 9, 43)
	packet, err := newSSHAcceptedPacket(context.Background(), header, 1, 0, 1, digest, right)
	if err != nil {
		t.Fatal(err)
	}
	if packet.RightsCount() != 1 || packet.Right() != right || right.state.closed {
		t.Fatal("send right ownership changed before Transport")
	}
	bad := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilityAgentPIDFD, digest: digest}}
	if _, err := newSSHAcceptedPacket(context.Background(), header, 1, 0, 1, digest, bad); !errors.Is(err, ErrContractCapability) {
		t.Fatalf("wrong outbound right error = %v", err)
	}
	changedDigest := digest
	changedDigest[31] ^= 1
	mismatch := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilitySSHConnection, digest: changedDigest}}
	mismatchAlias := mismatch
	if _, err := newSSHAcceptedPacket(context.Background(), header, 1, 0, 1, digest, mismatchAlias); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("outbound right/body digest mismatch = %v", err)
	}
	if !mismatch.state.closed {
		t.Fatal("mismatched outbound right alias was not closed")
	}
}

func TestSendSSHAcceptedPacketConnectionOrdinalBounds(t *testing.T) {
	digest := sha256.Sum256([]byte("relay"))
	header := transportJobHeader(credentialprotocol.PacketTypeSSHAcceptedFD, 9, credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength())
	for _, tc := range []struct {
		name    string
		ordinal uint8
		wantErr bool
	}{
		{name: "maximum", ordinal: 64},
		{name: "maximum plus one", ordinal: 65, wantErr: true},
		{name: "uint8 maximum", ordinal: 255, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			right := transportTestRight{state: &transportTestRightState{kind: ReceivedCapabilitySSHConnection, digest: digest}}
			packet, err := newSSHAcceptedPacket(context.Background(), header, 1, 0, tc.ordinal, digest, right)
			if tc.wantErr {
				if !errors.Is(err, ErrContractInvalidArgument) {
					t.Fatalf("ordinal %d error = %v, want ErrContractInvalidArgument", tc.ordinal, err)
				}
				if !right.state.closed {
					t.Fatalf("invalid ordinal %d did not close owned right", tc.ordinal)
				}
				return
			}
			if err != nil {
				t.Fatalf("ordinal %d rejected: %v", tc.ordinal, err)
			}
			if right.state.closed || packet.Right() != right {
				t.Fatal("valid maximum ordinal changed right ownership")
			}
			if err := packet.Right().Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSendExecStreamOwnsLockedBodyUntilExplicitDestroy(t *testing.T) {
	payload := []byte("stdout")
	digest := sha256.Sum256(payload)
	encoded := transportStreamBody(3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, payload, digest)
	body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	header := transportJobHeader(credentialprotocol.PacketTypeExecStream, 10, uint32(len(encoded)))
	packet, err := newExecStreamPacket(context.Background(), header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), digest, body)
	if err != nil {
		t.Fatal(err)
	}
	pinnedDigest := sha256.Sum256(encoded)
	if body.state.destroyed || packet.BodySHA256() != pinnedDigest || body.state.borrows != 1 {
		t.Fatal("send stream body ownership changed before send")
	}
	sink := &transportTestSink{maximum: len(encoded)}
	if err := packet.WriteCanonicalBody(context.Background(), sink); err != nil || !reflect.DeepEqual(sink.value, encoded) {
		t.Fatalf("send stream copy = %x, %v", sink.value, err)
	}
	if body.state.borrows != 2 {
		t.Fatalf("send stream borrows after construction/write = %d, want 2", body.state.borrows)
	}
	if err := packet.WriteCanonicalBody(context.Background(), sink); !errors.Is(err, ErrContractOwnership) {
		t.Fatalf("second send stream write = %v", err)
	}
	if body.state.borrows != 2 {
		t.Fatalf("second stream write borrowed again: %d", body.state.borrows)
	}
	if err := packet.destroyBody(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, body)
	if packet.BodySHA256() != pinnedDigest {
		t.Fatal("pinned stream digest changed after write/destroy")
	}

	badBody := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	badDigest := sha256.Sum256([]byte("different"))
	if _, err := newExecStreamPacket(context.Background(), header, 3, credentialprotocol.HelperExecStreamStdout, credentialprotocol.HelperExecStreamFlagsNone, 5, uint32(len(payload)), badDigest, badBody); !errors.Is(err, ErrContractCorrelation) {
		t.Fatalf("send stream correlation error = %v", err)
	}
	assertBodyDestroyedAndWiped(t, badBody)
}

func TestSendExecStreamCanonicalEncoderIsUnavailable(t *testing.T) {
	if err := (sendExecStreamArm{}).encodeCanonicalTo(make([]byte, 1)); !errors.Is(err, ErrContractCapability) {
		t.Fatalf("sensitive stream canonical encoder = %v", err)
	}
	assertPublicMethods(t, reflect.TypeOf((*credentialmemory.CredentialSink)(nil)).Elem(), []string{"MaxCredentialBytes", "WriteCredential"})
}

func TestExecStreamAndCreditDirectionMatrix(t *testing.T) {
	credential := transportCredential(t)
	streamPayload := []byte("payload")
	streamDigest := sha256.Sum256(streamPayload)
	for _, tc := range []struct {
		name     string
		kind     credentialprotocol.HelperExecStreamKind
		accepted bool
	}{
		{name: "inbound stdin", kind: credentialprotocol.HelperExecStreamStdin, accepted: true},
		{name: "inbound stdout", kind: credentialprotocol.HelperExecStreamStdout},
		{name: "inbound stderr", kind: credentialprotocol.HelperExecStreamStderr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := transportStreamBody(2, tc.kind, credentialprotocol.HelperExecStreamFlagsNone, 0, streamPayload, streamDigest)
			body := newTransportTestBody(encoded, 256)
			request, _ := NewReceiveRequest(2, uint32(len(encoded)), 0)
			packet, err := NewReceivedExecStreamPacket(context.Background(), request, transportJobHeader(credentialprotocol.PacketTypeExecStream, 2, uint32(len(encoded))), credential, 1, body, 0, 2, tc.kind, credentialprotocol.HelperExecStreamFlagsNone, 0, uint32(len(streamPayload)), streamDigest)
			if tc.accepted {
				if err != nil {
					t.Fatal(err)
				}
				if err := packet.body.Destroy(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("wrong inbound stream direction error = %v", err)
			}
			assertBodyDestroyedAndWiped(t, body)
		})
	}

	for _, tc := range []struct {
		name     string
		kind     credentialprotocol.HelperExecStreamKind
		accepted bool
	}{
		{name: "outbound stdin", kind: credentialprotocol.HelperExecStreamStdin},
		{name: "outbound stdout", kind: credentialprotocol.HelperExecStreamStdout, accepted: true},
		{name: "outbound stderr", kind: credentialprotocol.HelperExecStreamStderr, accepted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := transportStreamBody(2, tc.kind, credentialprotocol.HelperExecStreamFlagsNone, 0, streamPayload, streamDigest)
			body := newTransportTestBody(encoded, 256)
			packet, err := newExecStreamPacket(context.Background(), transportJobHeader(credentialprotocol.PacketTypeExecStream, 2, uint32(len(encoded))), 2, tc.kind, credentialprotocol.HelperExecStreamFlagsNone, 0, uint32(len(streamPayload)), streamDigest, body)
			if tc.accepted {
				if err != nil {
					t.Fatal(err)
				}
				if err := packet.destroyBody(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrContractCorrelation) {
				t.Fatalf("wrong outbound stream direction error = %v", err)
			}
			assertBodyDestroyedAndWiped(t, body)
		})
	}

	for _, tc := range []struct {
		name     string
		kind     credentialprotocol.HelperExecStreamKind
		accepted bool
	}{
		{name: "inbound credit stdin", kind: credentialprotocol.HelperExecStreamStdin},
		{name: "inbound credit stdout", kind: credentialprotocol.HelperExecStreamStdout, accepted: true},
		{name: "inbound credit stderr", kind: credentialprotocol.HelperExecStreamStderr, accepted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded := credentialprotocol.HelperExecCreditBody{Revision: 2, StreamKind: tc.kind, NextOffset: 1}
			encoded, err := credentialprotocol.EncodeHelperExecCreditBody(decoded)
			if err != nil {
				t.Fatal(err)
			}
			body := newTransportTestBody(encoded, 256)
			request, _ := NewReceiveRequest(2, uint32(len(encoded)), 0)
			_, err = NewReceivedExecCreditPacket(context.Background(), request, transportJobHeader(credentialprotocol.PacketTypeExecCredit, 2, uint32(len(encoded))), credential, 1, body, 0, decoded)
			if tc.accepted && err != nil {
				t.Fatal(err)
			}
			if !tc.accepted && !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("wrong inbound credit direction error = %v", err)
			}
			assertBodyDestroyedAndWiped(t, body)
		})
	}

	for _, tc := range []struct {
		name     string
		kind     credentialprotocol.HelperExecStreamKind
		accepted bool
	}{
		{name: "outbound credit stdin", kind: credentialprotocol.HelperExecStreamStdin, accepted: true},
		{name: "outbound credit stdout", kind: credentialprotocol.HelperExecStreamStdout},
		{name: "outbound credit stderr", kind: credentialprotocol.HelperExecStreamStderr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded := credentialprotocol.HelperExecCreditBody{Revision: 2, StreamKind: tc.kind, NextOffset: 1}
			encoded, err := credentialprotocol.EncodeHelperExecCreditBody(decoded)
			if err != nil {
				t.Fatal(err)
			}
			_, err = newExecCreditPacket(context.Background(), transportJobHeader(credentialprotocol.PacketTypeExecCredit, 2, uint32(len(encoded))), decoded)
			if tc.accepted && err != nil {
				t.Fatal(err)
			}
			if !tc.accepted && !errors.Is(err, ErrContractInvalidArgument) {
				t.Fatalf("wrong outbound credit direction error = %v", err)
			}
		})
	}
}

func TestBootSendConstructorsRequireFixedSequences(t *testing.T) {
	digest := sha256.Sum256([]byte("digest"))
	for _, tc := range []struct {
		name       string
		want       uint64
		bodyBytes  uint32
		packetType credentialprotocol.PacketType
		construct  func(credentialprotocol.HelperPacketHeader) (SendPacket, error)
	}{
		{name: "helper ready", want: 0, bodyBytes: 0, packetType: credentialprotocol.PacketTypeHelperReady, construct: func(header credentialprotocol.HelperPacketHeader) (SendPacket, error) {
			return newHelperReadyPacket(context.Background(), header)
		}},
		{name: "bootstrap ack", want: 1, bodyBytes: 32, packetType: credentialprotocol.PacketTypeBootstrapAck, construct: func(header credentialprotocol.HelperPacketHeader) (SendPacket, error) {
			return newBootstrapAckPacket(context.Background(), header, digest)
		}},
		{name: "agent hello ack", want: 2, bodyBytes: 32, packetType: credentialprotocol.PacketTypeAgentHelloAck, construct: func(header credentialprotocol.HelperPacketHeader) (SendPacket, error) {
			return newAgentHelloAckPacket(context.Background(), header, digest)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := transportHeader(tc.packetType, tc.want, tc.bodyBytes)
			if tc.packetType == credentialprotocol.PacketTypeHelperReady {
				header.BootNonce = [32]byte{}
			}
			if _, err := tc.construct(header); err != nil {
				t.Fatalf("fixed sequence rejected: %v", err)
			}
			wrong := tc.want + 1
			if tc.want > 0 {
				wrong = tc.want - 1
			}
			header.Sequence = wrong
			if _, err := tc.construct(header); !errors.Is(err, ErrContractCorrelation) {
				t.Fatalf("wrong boot sequence %d error = %v", wrong, err)
			}
		})
	}
}

func TestJobSendConstructorsKeepServiceOwnedSequences(t *testing.T) {
	for _, sequence := range []uint64{0, 17, uint64(^uint32(0))} {
		body := credentialprotocol.HelperExecCreditBody{
			Revision:   2,
			StreamKind: credentialprotocol.HelperExecStreamStdin,
			NextOffset: sequence,
		}
		packet, err := newExecCreditPacket(context.Background(), transportJobHeader(credentialprotocol.PacketTypeExecCredit, sequence, credentialprotocol.HelperExecCreditBodyBytes), body)
		if err != nil {
			t.Fatalf("dynamic job sequence %d rejected: %v", sequence, err)
		}
		if packet.Header().Sequence != sequence {
			t.Fatalf("job sequence = %d, want %d", packet.Header().Sequence, sequence)
		}
	}
}

func TestReceiveRequestConcurrentCopiesHaveOneOwner(t *testing.T) {
	const contenders = 32
	request, err := NewReceiveRequest(2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	header := transportHeader(credentialprotocol.PacketTypeCloseNotify, 2, 1)
	credential := transportCredential(t)
	var wait sync.WaitGroup
	wait.Add(contenders)
	results := make(chan error, contenders)
	bodies := make([]transportTestBody, contenders)
	for index := range bodies {
		bodies[index] = newTransportTestBody([]byte{byte(credentialprotocol.CloseReasonNormal)}, 32)
		go func(body transportTestBody) {
			defer wait.Done()
			_, constructErr := NewReceivedCloseNotifyPacket(context.Background(), request, header, credential, 1, body, 0, credentialprotocol.HelperCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal})
			results <- constructErr
		}(bodies[index])
	}
	wait.Wait()
	close(results)
	successes := 0
	for constructErr := range results {
		if constructErr == nil {
			successes++
		} else if !errors.Is(constructErr, ErrContractOwnership) {
			t.Fatalf("contender error = %v", constructErr)
		}
	}
	if successes != 1 {
		t.Fatalf("successful owners = %d, want 1", successes)
	}
	for _, body := range bodies {
		assertBodyDestroyedAndWiped(t, body)
	}
}

func TestTransportValuePublicMethodSetsAreClosed(t *testing.T) {
	assertPublicMethods(t, reflect.TypeOf(ReceivedKernelCredential{}), []string{"Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "String"})
	assertPublicMethods(t, reflect.TypeOf(ReceiveRequest{}), []string{"ExpectedRights", "Format", "GoString", "MarshalBinary", "MarshalJSON", "MarshalText", "MaximumBodyBytes", "NextSequence", "String"})
	assertPublicMethods(t, reflect.TypeOf(ReceivedPacket{}), []string{"AgentHello", "Bootstrap", "CloseNotify", "Exec", "ExecCredit", "ExecPrivate", "ExecStream", "Format", "GoString", "Header", "MarshalBinary", "MarshalJSON", "MarshalText", "PrepareBegin", "PrepareCommit", "PrepareFile", "Renew", "Revoke", "String", "Type"})
	assertPublicMethods(t, reflect.TypeOf(SendPacket{}), []string{"BodySHA256", "EncodedBodyLength", "Format", "GoString", "Header", "MarshalBinary", "MarshalJSON", "MarshalText", "Right", "RightsCount", "String", "Type", "WriteCanonicalBody"})
}

func TestTransportValuesAreOpaqueAsValuesAndPointers(t *testing.T) {
	credential := transportCredential(t)
	request, err := NewReceiveRequest(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		credential, &credential,
		request, &request,
		ReceivedPacket{}, &ReceivedPacket{},
		ReceivedBootstrap{}, &ReceivedBootstrap{},
		ReceivedAgentHello{}, &ReceivedAgentHello{},
		ReceivedPrepareBegin{}, &ReceivedPrepareBegin{},
		ReceivedPrepareFile{}, &ReceivedPrepareFile{},
		ReceivedPrepareCommit{}, &ReceivedPrepareCommit{},
		ReceivedRenew{}, &ReceivedRenew{},
		ReceivedRevoke{}, &ReceivedRevoke{},
		ReceivedExec{}, &ReceivedExec{},
		ReceivedExecPrivate{}, &ReceivedExecPrivate{},
		ReceivedExecStream{}, &ReceivedExecStream{},
		ReceivedExecCredit{}, &ReceivedExecCredit{},
		ReceivedCloseNotify{}, &ReceivedCloseNotify{},
		SendPacket{}, &SendPacket{},
	}
	for _, value := range values {
		assertLiveOpaque(t, value)
	}
}

func TestReceivedAgentHelloParsesOnlyCanonicalDescriptorLength(t *testing.T) {
	credential := transportCredential(t)
	bootstrapDigest := sha256.Sum256([]byte("bootstrap"))
	for _, tc := range []struct {
		name       string
		declared   uint16
		descriptor []byte
		digest     [32]byte
	}{
		{name: "zero length", declared: 0, descriptor: nil, digest: sha256.Sum256(nil)},
		{name: "above maximum", declared: 1899, descriptor: make([]byte, 1899), digest: sha256.Sum256(make([]byte, 1899))},
		{name: "nonexact remainder", declared: 2, descriptor: []byte{1}, digest: sha256.Sum256([]byte{1})},
		{name: "independent digest mismatch", declared: 1, descriptor: []byte{1}, digest: sha256.Sum256([]byte{2})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bodyBytes := transportAgentHelloBody(t, bootstrapDigest, "boot-1", "helper-1", tc.declared, tc.descriptor)
			request, err := NewReceiveRequest(1, uint32(len(bodyBytes)), 0)
			if err != nil {
				t.Fatal(err)
			}
			body := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
			_, err = NewReceivedAgentHelloPacket(context.Background(), request, transportHeader(credentialprotocol.PacketTypeAgentHello, 1, uint32(len(bodyBytes))), credential, 1, body, 0, bootstrapDigest, "boot-1", "helper-1", tc.digest)
			if !errors.Is(err, ErrContractCorrelation) {
				t.Fatalf("malformed descriptor error = %v", err)
			}
			assertBodyDestroyedAndWiped(t, body)
		})
	}

	descriptor := make([]byte, 1898)
	digest := sha256.Sum256(descriptor)
	bodyBytes := transportAgentHelloBody(t, bootstrapDigest, "boot-1", "helper-1", 1898, descriptor)
	request, err := NewReceiveRequest(1, uint32(len(bodyBytes)), 0)
	if err != nil {
		t.Fatal(err)
	}
	body := newTransportTestBody(bodyBytes, credentialprotocol.MaxHelperPacketBodyBytes)
	if _, err := NewReceivedAgentHelloPacket(context.Background(), request, transportHeader(credentialprotocol.PacketTypeAgentHello, 1, uint32(len(bodyBytes))), credential, 1, body, 0, bootstrapDigest, "boot-1", "helper-1", digest); err != nil {
		t.Fatalf("maximum canonical descriptor: %v", err)
	}
	assertBodyDestroyedAndWiped(t, body)
}

func TestAllReceivedTypedArmsRoundTripCanonicalCodecMetadata(t *testing.T) {
	credential := transportCredential(t)
	bootstrapDigest := sha256.Sum256([]byte("bootstrap"))
	descriptor := []byte("canonical-descriptor")
	descriptorDigest := sha256.Sum256(descriptor)
	bootToken, _ := credentialprotocol.EncodeBodyToken("boot-1")
	helperToken, _ := credentialprotocol.EncodeBodyToken("helper-1")
	helloBytes := make([]byte, 32, 32+len(bootToken)+len(helperToken)+2+len(descriptor))
	copy(helloBytes, bootstrapDigest[:])
	helloBytes = append(helloBytes, bootToken...)
	helloBytes = append(helloBytes, helperToken...)
	helloBytes = binary.BigEndian.AppendUint16(helloBytes, uint16(len(descriptor)))
	helloBytes = append(helloBytes, descriptor...)
	helloRequest, _ := NewReceiveRequest(1, uint32(len(helloBytes)), 0)
	helloBody := newTransportTestBody(helloBytes, 256)
	hello, err := NewReceivedAgentHelloPacket(context.Background(), helloRequest, transportHeader(credentialprotocol.PacketTypeAgentHello, 1, uint32(len(helloBytes))), credential, 1, helloBody, 0, bootstrapDigest, "boot-1", "helper-1", descriptorDigest)
	if err != nil {
		t.Fatal(err)
	}
	helloArm, ok := hello.AgentHello()
	if !ok || helloArm.BootstrapSHA256() != bootstrapDigest || helloArm.BootGeneration() != "boot-1" || helloArm.HelperGeneration() != "helper-1" || helloArm.ProcessDescriptorSHA256() != descriptorDigest {
		t.Fatalf("agent hello arm = %#v, %v", helloArm, ok)
	}
	assertBodyDestroyedAndWiped(t, helloBody)

	manifestDigest := sha256.Sum256([]byte("manifest"))
	commitValue := credentialprotocol.HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifestDigest}
	commitBytes, _ := credentialprotocol.EncodeHelperPrepareCommitBody(commitValue)
	commit := receiveCanonicalForTest(t, credentialprotocol.PacketTypePrepareCommit, commitBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedPrepareCommitPacket(context.Background(), request, header, credential, 1, body, 0, commitValue)
	})
	commitArm, ok := commit.PrepareCommit()
	if !ok || commitArm.Revision() != 1 || commitArm.ManifestSHA256() != manifestDigest {
		t.Fatal("prepare commit arm mismatch")
	}

	renewValue := credentialprotocol.HelperRenewBody{Revision: 2, ExpiryUnixNano: 1234, PriorProofID: "proof-1"}
	renewBytes, _ := credentialprotocol.EncodeHelperRenewBody(renewValue)
	renew := receiveCanonicalForTest(t, credentialprotocol.PacketTypeRenew, renewBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedRenewPacket(context.Background(), request, header, credential, 1, body, 0, 2, 1234, "proof-1")
	})
	renewArm, ok := renew.Renew()
	if !ok || renewArm.Revision() != 2 || renewArm.ExpiryUnixNano() != 1234 || renewArm.PriorProofSHA256() == ([32]byte{}) {
		t.Fatal("renew arm mismatch")
	}

	revokeValue := credentialprotocol.HelperRevokeBody{Revision: 2, Reason: credentialprotocol.RevokeReasonRequested}
	revokeBytes, _ := credentialprotocol.EncodeHelperRevokeBody(revokeValue)
	revoke := receiveCanonicalForTest(t, credentialprotocol.PacketTypeRevoke, revokeBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedRevokePacket(context.Background(), request, header, credential, 1, body, 0, revokeValue)
	})
	revokeArm, ok := revoke.Revoke()
	if !ok || revokeArm.Revision() != 2 || revokeArm.Reason() != credentialprotocol.RevokeReasonRequested {
		t.Fatal("revoke arm mismatch")
	}

	planValue := transportExecPlan()
	plan, err := NewExecPlanCapability(planValue)
	if err != nil {
		t.Fatal(err)
	}
	execValue := credentialprotocol.HelperExecBody{Revision: 2, ExecBindingID: "exec-1", Plan: planValue}
	execBytes, err := credentialprotocol.EncodeHelperExecBody(execValue)
	if err != nil {
		t.Fatal(err)
	}
	execPacket := receiveCanonicalForTest(t, credentialprotocol.PacketTypeExec, execBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedExecPacket(context.Background(), request, header, credential, 1, body, 0, execValue, plan)
	})
	execArm, ok := execPacket.Exec()
	if !ok || execArm.Revision() != 2 || execArm.ExecBindingID() != "exec-1" || execArm.PrivateBindingLength() != 0 || execArm.Plan().SHA256() != plan.SHA256() {
		t.Fatal("exec arm mismatch")
	}
	execTransaction, err := execArm.transactionSeed.Begin()
	if err != nil {
		t.Fatalf("exec arm did not retain usable protocol transaction seed: %v", err)
	}
	execTransaction.Close()
	if _, err := execArm.transactionSeed.Begin(); err == nil {
		t.Fatal("exec transaction seed alias was not one-use")
	}
	plan.destroy()

	privatePayload := []byte("private")
	privateDigest := sha256.Sum256(privatePayload)
	privateBytes := make([]byte, 44+len(privatePayload))
	binary.BigEndian.PutUint64(privateBytes[:8], 2)
	binary.BigEndian.PutUint32(privateBytes[8:12], uint32(len(privatePayload)))
	copy(privateBytes[12:44], privateDigest[:])
	copy(privateBytes[44:], privatePayload)
	privateRequest, _ := NewReceiveRequest(2, uint32(len(privateBytes)), 0)
	privateBody := newTransportTestBody(privateBytes, 256)
	privatePacket, err := NewReceivedExecPrivatePacket(context.Background(), privateRequest, transportJobHeader(credentialprotocol.PacketTypeExecPrivate, 2, uint32(len(privateBytes))), credential, 1, privateBody, 0, 2, uint32(len(privatePayload)), privateDigest)
	if err != nil {
		t.Fatal(err)
	}
	privateArm, ok := privatePacket.ExecPrivate()
	if !ok || privateArm.Revision() != 2 || privateArm.PrivateBindingLength() != uint32(len(privatePayload)) || privateArm.PrivateBindingSHA256() != privateDigest {
		t.Fatal("exec private arm mismatch")
	}
	assertRetainedPayloadSubview(t, privatePacket, privateBody, privateBytes, 44, privatePayload, privateDigest)
	if err := privatePacket.body.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, privateBody)

	streamPayload := []byte("stdin")
	streamDigest := sha256.Sum256(streamPayload)
	streamBytes := transportStreamBody(2, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagsNone, 0, streamPayload, streamDigest)
	streamRequest, _ := NewReceiveRequest(2, uint32(len(streamBytes)), 0)
	streamBody := newTransportTestBody(streamBytes, 256)
	streamPacket, err := NewReceivedExecStreamPacket(context.Background(), streamRequest, transportJobHeader(credentialprotocol.PacketTypeExecStream, 2, uint32(len(streamBytes))), credential, 1, streamBody, 0, 2, credentialprotocol.HelperExecStreamStdin, credentialprotocol.HelperExecStreamFlagsNone, 0, uint32(len(streamPayload)), streamDigest)
	if err != nil {
		t.Fatal(err)
	}
	streamArm, ok := streamPacket.ExecStream()
	if !ok || streamArm.Revision() != 2 || streamArm.StreamKind() != credentialprotocol.HelperExecStreamStdin || streamArm.Flags() != credentialprotocol.HelperExecStreamFlagsNone || streamArm.Offset() != 0 || streamArm.PayloadLength() != uint32(len(streamPayload)) || streamArm.PayloadSHA256() != streamDigest {
		t.Fatal("exec stream arm mismatch")
	}
	assertRetainedPayloadSubview(t, streamPacket, streamBody, streamBytes, 56, streamPayload, streamDigest)
	if err := streamPacket.body.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, streamBody)

	creditValue := credentialprotocol.HelperExecCreditBody{Revision: 2, StreamKind: credentialprotocol.HelperExecStreamStdout, NextOffset: 10}
	creditBytes, _ := credentialprotocol.EncodeHelperExecCreditBody(creditValue)
	credit := receiveCanonicalForTest(t, credentialprotocol.PacketTypeExecCredit, creditBytes, func(request ReceiveRequest, header credentialprotocol.HelperPacketHeader, body transportTestBody) (ReceivedPacket, error) {
		return NewReceivedExecCreditPacket(context.Background(), request, header, credential, 1, body, 0, creditValue)
	})
	creditArm, ok := credit.ExecCredit()
	if !ok || creditArm.Revision() != 2 || creditArm.StreamKind() != credentialprotocol.HelperExecStreamStdout || creditArm.NextOffset() != 10 {
		t.Fatal("exec credit arm mismatch")
	}
}

func receiveCanonicalForTest(t *testing.T, packetType credentialprotocol.PacketType, encoded []byte, construct func(ReceiveRequest, credentialprotocol.HelperPacketHeader, transportTestBody) (ReceivedPacket, error)) ReceivedPacket {
	t.Helper()
	request, err := NewReceiveRequest(2, uint32(len(encoded)), 0)
	if err != nil {
		t.Fatal(err)
	}
	body := newTransportTestBody(encoded, credentialprotocol.MaxHelperPacketBodyBytes)
	packet, err := construct(request, transportJobHeader(packetType, 2, uint32(len(encoded))), body)
	if err != nil {
		t.Fatal(err)
	}
	assertBodyDestroyedAndWiped(t, body)
	return packet
}

func transportExecPlan() credentialprotocol.HelperExecPlan {
	return credentialprotocol.HelperExecPlan{
		Arguments:      []string{"/bin/true"},
		WorkDirectory:  "/workspace",
		StdinMode:      credentialprotocol.HelperExecStreamModePipe,
		StdoutMode:     credentialprotocol.HelperExecStreamModePipe,
		StderrMode:     credentialprotocol.HelperExecStreamModePipe,
		StdinMaxBytes:  1024,
		StdoutMaxBytes: 1024,
		StderrMaxBytes: 1024,
		Timing:         credentialprotocol.HelperExecTiming{Kind: credentialprotocol.HelperExecTimingTimeoutMillis, Value: 1000},
	}
}

func transportStreamBody(revision uint64, kind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, offset uint64, payload []byte, digest [32]byte) []byte {
	body := make([]byte, 56+len(payload))
	binary.BigEndian.PutUint64(body[:8], revision)
	body[8] = byte(kind)
	body[9] = byte(flags)
	binary.BigEndian.PutUint64(body[12:20], offset)
	binary.BigEndian.PutUint32(body[20:24], uint32(len(payload)))
	copy(body[24:56], digest[:])
	copy(body[56:], payload)
	return body
}

func transportAgentHelloBody(t *testing.T, bootstrapDigest [32]byte, boot, helper credentialprotocol.SafeID, declared uint16, descriptor []byte) []byte {
	t.Helper()
	bootToken, err := credentialprotocol.EncodeBodyToken(string(boot))
	if err != nil {
		t.Fatal(err)
	}
	helperToken, err := credentialprotocol.EncodeBodyToken(string(helper))
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 32, 32+len(bootToken)+len(helperToken)+2+len(descriptor))
	copy(body, bootstrapDigest[:])
	body = append(body, bootToken...)
	body = append(body, helperToken...)
	body = binary.BigEndian.AppendUint16(body, declared)
	body = append(body, descriptor...)
	return body
}

func assertRetainedPayloadSubview(t *testing.T, packet ReceivedPacket, body transportTestBody, canonical []byte, offset int, payload []byte, digest [32]byte) {
	t.Helper()
	if packet.body.Len() != uint32(len(payload)) || packet.body.SHA256() != digest {
		t.Fatalf("private retained payload body = %d/%x", packet.body.Len(), packet.body.SHA256())
	}
	body.state.mu.Lock()
	if !reflect.DeepEqual(body.state.region[:body.state.length], canonical) {
		body.state.mu.Unlock()
		t.Fatal("retained transport owner no longer holds the full canonical body")
	}
	payloadAddress := reflect.ValueOf(body.state.region[offset : offset+len(payload)]).Pointer()
	body.state.mu.Unlock()
	borrowCalls := 0
	err := packet.body.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
		borrowCalls++
		if view.Len() != len(payload) {
			t.Fatalf("borrowed payload length = %d, want %d", view.Len(), len(payload))
		}
		sink := &transportSubviewTestSink{maximum: len(payload), want: payload, wantAddress: payloadAddress}
		if writeErr := view.WriteTo(context.Background(), sink); writeErr != nil {
			return writeErr
		}
		if !sink.called || !sink.sameBacking {
			t.Fatal("service payload subview copied or did not synchronously write")
		}
		return nil
	})
	if err != nil || borrowCalls != 1 {
		t.Fatalf("borrow retained payload = %v, calls %d", err, borrowCalls)
	}
}

func assertPublicMethods(t *testing.T, value reflect.Type, want []string) {
	t.Helper()
	got := make([]string, value.NumMethod())
	for index := 0; index < value.NumMethod(); index++ {
		got[index] = value.Method(index).Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s methods = %v, want %v", value, got, want)
	}
}

func transportHeader(packetType credentialprotocol.PacketType, sequence uint64, bodyLength uint32) credentialprotocol.HelperPacketHeader {
	return credentialprotocol.HelperPacketHeader{Type: packetType, Sequence: sequence, BodyLength: bodyLength, BootNonce: sha256.Sum256([]byte("boot nonce"))}
}

func transportJobHeader(packetType credentialprotocol.PacketType, sequence uint64, bodyLength uint32) credentialprotocol.HelperPacketHeader {
	header := transportHeader(packetType, sequence, bodyLength)
	header.RequestID[0] = 1
	header.GuestCredentialIdentityDigest = sha256.Sum256([]byte("identity"))
	return header
}

func transportCredential(t *testing.T) ReceivedKernelCredential {
	t.Helper()
	credential, err := NewReceivedKernelCredential(42, 998, 998)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func transportBootstrapBody(t *testing.T, pid, uid, gid uint32, boot, helper credentialprotocol.SafeID) []byte {
	t.Helper()
	bootWire, err := credentialprotocol.EncodeBodyToken(string(boot))
	if err != nil {
		t.Fatal(err)
	}
	helperWire, err := credentialprotocol.EncodeBodyToken(string(helper))
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 12, 12+len(bootWire)+len(helperWire))
	body[0], body[1], body[2], body[3] = byte(pid>>24), byte(pid>>16), byte(pid>>8), byte(pid)
	body[4], body[5], body[6], body[7] = byte(uid>>24), byte(uid>>16), byte(uid>>8), byte(uid)
	body[8], body[9], body[10], body[11] = byte(gid>>24), byte(gid>>16), byte(gid>>8), byte(gid)
	body = append(body, bootWire...)
	body = append(body, helperWire...)
	return body
}

func assertBodyDestroyedAndWiped(t *testing.T, body transportTestBody) {
	t.Helper()
	body.state.mu.Lock()
	defer body.state.mu.Unlock()
	if !body.state.destroyed {
		t.Fatal("body was not destroyed")
	}
	for index, value := range body.state.region {
		if value != 0 {
			t.Fatalf("body full-capacity byte %d was not wiped", index)
		}
	}
}

func assertLiveOpaque(t *testing.T, value any) {
	t.Helper()
	for _, formatted := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
		if formatted != "credentialhelper.live[redacted]" {
			t.Fatalf("opaque formatting = %q", formatted)
		}
	}
	if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrContractInvalidArgument) {
		t.Fatalf("JSON marshal = %q, %v", encoded, err)
	}
}

func allZeroBytes(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}
