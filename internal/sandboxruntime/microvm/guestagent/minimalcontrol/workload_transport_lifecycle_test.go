package minimalcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

type workloadTransportVerifier struct{}

func (workloadTransportVerifier) VerifyWorkloadIsolation(context.Context) (server.IsolationProofResult, error) {
	return server.IsolationProofResult{RestrictedIdentity: true, CapabilitiesCleared: true,
		NoNewPrivileges: true, SupplementaryGroupsCleared: true, RawPacketSocketDenied: true,
		Network: server.NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified,
			SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}, nil
}

type workloadTransportBackend struct {
	ready         func(context.Context) error
	exec          func(context.Context, server.ExecPlan) (server.ExecResult, error)
	copyIn        func(context.Context, server.CopyInPlan) (server.CopyResult, error)
	copyOut       func(context.Context, server.CopyOutPlan) (server.CopyResult, error)
	calls, closes atomic.Int32
}

func (backend *workloadTransportBackend) Ready(ctx context.Context) error {
	if backend.ready != nil {
		return backend.ready(ctx)
	}
	return nil
}
func (backend *workloadTransportBackend) Exec(ctx context.Context, plan server.ExecPlan) (server.ExecResult, error) {
	backend.calls.Add(1)
	if backend.exec != nil {
		return backend.exec(ctx, plan)
	}
	return server.ExecResult{Stdout: []byte("exact output\n"), ExitCode: 7}, nil
}
func (backend *workloadTransportBackend) CopyIn(ctx context.Context, plan server.CopyInPlan) (server.CopyResult, error) {
	if backend.copyIn != nil {
		return backend.copyIn(ctx, plan)
	}
	return server.CopyResult{}, errors.New("unused copy")
}
func (backend *workloadTransportBackend) CopyOut(ctx context.Context, plan server.CopyOutPlan) (server.CopyResult, error) {
	if backend.copyOut != nil {
		return backend.copyOut(ctx, plan)
	}
	return server.CopyResult{}, errors.New("unused copy")
}
func (backend *workloadTransportBackend) Close(context.Context) error {
	backend.closes.Add(1)
	return nil
}

func newWorkloadTransportFixture(t *testing.T, backend *workloadTransportBackend, change ...func(*server.Options)) *bootstrapFixture {
	t.Helper()
	common := testOptions()
	owner := make(chan struct{})
	transport, err := NewWorkloadTransport(BootstrapOptions{Listener: common.Listener, Boot: testBoot(t), OwnerDone: owner,
		Clock: common.Clock, Random: bytes.NewReader(bytes.Repeat([]byte{73}, 32*session.MaxPreAuthConnections))})
	if err != nil {
		t.Fatal(err)
	}
	options := server.Options{Transport: transport, Backend: backend, WorkloadIsolationVerifier: workloadTransportVerifier{},
		RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true}
	for _, mutate := range change {
		mutate(&options)
	}
	enclosing, err := server.New(options)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding(testIdentity(), testBindingFields())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fixture := &bootstrapFixture{testFixture: &testFixture{server: transport.(*workloadTransport).bootstrap,
		listener: common.Listener.(*testListener), clock: common.Clock.(*testClock), owner: owner, cancel: cancel,
		key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize)), result: make(chan error, 1)}, binding: binding}
	go func() { fixture.result <- enclosing.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		for _, peer := range fixture.peers {
			_ = peer.Close()
		}
		if !fixture.waited {
			fixture.wait(t)
		}
		if backend.closes.Load() != 1 {
			t.Fatal("backend cleanup not joined exactly once")
		}
	})
	return fixture
}

func workloadInnerExec(t *testing.T) []byte {
	t.Helper()
	request := guestagent.ExecRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationExec,
		Args: []string{"hal", "--version"}, WorkDir: "/workspace", Stdout: guestagent.StreamMetadata{MaxBytes: 64}, Stderr: guestagent.StreamMetadata{MaxBytes: 64}}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func workloadRecord(t *testing.T, fixture *bootstrapFixture, state *session.State, inner []byte, ordinal uint64) []byte {
	t.Helper()
	payload, err := fixture.binding.EncodeWorkload(inner, ordinal, state.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	wire, err := state.SealApplication(session.FrameTypeControlRequest, payload)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func workloadResponse(t *testing.T, fixture *bootstrapFixture, peer *testPipe, state *session.State, ordinal uint64) []byte {
	t.Helper()
	var header [session.SecureRecordHeaderBytes]byte
	if _, err := io.ReadFull(peer, header[:]); err != nil {
		t.Fatal(err)
	}
	parsed, err := session.ParseRecordHeaderPrefix(header[:], session.ChannelControl)
	if err != nil || parsed.CiphertextLength > MaxWorkloadMessageBytes+session.GCMTagBytes {
		t.Fatal("invalid response header")
	}
	wire := append(header[:], make([]byte, parsed.CiphertextLength)...)
	defer clear(wire)
	if _, err := io.ReadFull(peer, wire[len(header):]); err != nil {
		t.Fatal(err)
	}
	id := state.SessionID()
	var inner []byte
	plaintext, err := state.OpenApplication(wire, func(kind session.FrameType, payload []byte) error {
		var decodeErr error
		inner, decodeErr = fixture.binding.DecodeWorkloadResponse(kind, payload, ordinal, id)
		return decodeErr
	})
	clear(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

func TestWorkloadTransportPreparationPrecedesReadinessAndObservesLoss(t *testing.T) {
	for _, loss := range []string{"eof", "owner", "cancel", "deadline"} {
		t.Run(loss, func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			backend := &workloadTransportBackend{ready: func(ctx context.Context) error {
				close(entered)
				<-ctx.Done()
				close(canceled)
				return ctx.Err()
			}}
			fixture := newWorkloadTransportFixture(t, backend)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			wire, err := state.SealApplication(session.FrameTypeControlRequest, testRequest(t, fixture.binding, state.SessionID()))
			if err != nil {
				t.Fatal(err)
			}
			write(t, peer, wire)
			await(t, entered, "actual selected preparation")
			if peer.other.writes.Load() != 2 {
				t.Fatal("readiness emitted before preparation finished")
			}
			switch loss {
			case "eof":
				_ = peer.writer.Close()
			case "owner":
				close(fixture.owner)
			case "cancel":
				fixture.cancel()
			case "deadline":
				fixture.clock.advance(session.HandshakeDeadline)
			}
			await(t, canceled, "preparation cancellation before any test rescue")
			fixture.wait(t)
			if backend.calls.Load() != 0 || peer.other.writes.Load() != 2 {
				t.Fatal("failed preparation produced readiness or work")
			}
		})
	}
}

func TestWorkloadTransportAuthenticatedSequentialReplies(t *testing.T) {
	backend := &workloadTransportBackend{}
	fixture := newWorkloadTransportFixture(t, backend)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	fixture.readiness(t, peer, state, fixture.binding)
	for ordinal := uint64(1); ordinal <= 50; ordinal++ {
		wire := workloadRecord(t, fixture, state, workloadInnerExec(t), ordinal)
		write(t, peer, wire)
		clear(wire)
		inner := workloadResponse(t, fixture, peer, state, ordinal)
		var response guestagent.ExecResponse
		if json.Unmarshal(inner, &response) != nil || response.ExitCode != 7 || response.Stdout.Data != base64.StdEncoding.EncodeToString([]byte("exact output\n")) {
			t.Fatalf("response was not exact existing v1 output: %s", inner)
		}
		clear(inner)
	}
	if backend.calls.Load() != 50 {
		t.Fatal("work was duplicated or dropped")
	}
}

// A peer can consume an entire response before its writer resumes. This is a
// real io.Writer ordering, not a delay pretending that an incomplete write won.
type workloadHeldWrite struct {
	*testPipe
	held, release chan struct{}
	call          int32
	once          sync.Once
}

func (stream *workloadHeldWrite) Write(value []byte) (int, error) {
	n, err := stream.testPipe.Write(value)
	if stream.writes.Load() == stream.call && n == len(value) && err == nil {
		stream.once.Do(func() { close(stream.held) })
		select {
		case <-stream.release:
		case <-stream.closed:
		}
	}
	return n, err
}

func connectHeldWorkloadWriter(t *testing.T, fixture *bootstrapFixture, call int32) (*testPipe, *workloadHeldWrite) {
	t.Helper()
	guestRead, controllerWrite := io.Pipe()
	controllerRead, guestWrite := io.Pipe()
	guest := &testPipe{reader: guestRead, writer: guestWrite, readStarted: make(chan struct{}, 16), writeStarted: make(chan struct{}, 16), closed: make(chan struct{})}
	peer := &testPipe{reader: controllerRead, writer: controllerWrite, other: guest}
	held := &workloadHeldWrite{testPipe: guest, held: make(chan struct{}), release: make(chan struct{}), call: call}
	fixture.peers = append(fixture.peers, peer)
	fixture.listener.connections <- held
	await(t, guest.readStarted, "selected stream first read")
	return peer, held
}

func TestWorkloadTransportConsumedReplyBeforeWriterReturns(t *testing.T) {
	for _, responseCall := range []int32{3, 4} {
		backend := &workloadTransportBackend{}
		fixture := newWorkloadTransportFixture(t, backend)
		peer, held := connectHeldWorkloadWriter(t, fixture, responseCall)
		state := fixture.authenticate(t, peer, true)
		defer state.Revoke()
		fixture.readiness(t, peer, state, fixture.binding)
		next := uint64(1)
		if responseCall == 4 {
			write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 1))
			clear(workloadResponse(t, fixture, peer, state, 1))
			next = 2
		}
		await(t, held.held, "full response consumed before held writer return")
		write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), next))
		if backend.calls.Load() != int32(next-1) {
			t.Fatal("next backend ran before previous writer joined")
		}
		close(held.release)
		clear(workloadResponse(t, fixture, peer, state, next))
		if backend.calls.Load() != int32(next) {
			t.Fatal("valid sequential request was lost or duplicated")
		}
	}
}

func TestWorkloadTransportPendingWriterSlotIsBoundedAndCanceled(t *testing.T) {
	for _, loss := range []string{"third-frame", "eof", "owner"} {
		t.Run(loss, func(t *testing.T) {
			backend := &workloadTransportBackend{}
			fixture := newWorkloadTransportFixture(t, backend)
			peer, held := connectHeldWorkloadWriter(t, fixture, 4)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			fixture.readiness(t, peer, state, fixture.binding)
			write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 1))
			clear(workloadResponse(t, fixture, peer, state, 1))
			await(t, held.held, "completed response with held return")
			write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 2))
			switch loss {
			case "third-frame":
				write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 3))
			case "eof":
				_ = peer.writer.Close()
			case "owner":
				close(fixture.owner)
			}
			fixture.wait(t)
			if backend.calls.Load() != 1 {
				t.Fatal("pending request dispatched after transport loss")
			}
		})
	}
}

func TestWorkloadTransportBlockedExecCanceledWithoutBackendRelease(t *testing.T) {
	for _, loss := range []string{"eof", "owner", "cancel", "hard-expiry", "second-request", "partial-header-eof", "partial-body-eof"} {
		t.Run(loss, func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			backend := &workloadTransportBackend{exec: func(ctx context.Context, _ server.ExecPlan) (server.ExecResult, error) {
				close(entered)
				<-ctx.Done()
				close(canceled)
				return server.ExecResult{}, ctx.Err()
			}}
			fixture := newWorkloadTransportFixture(t, backend)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			fixture.readiness(t, peer, state, fixture.binding)
			write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 1))
			await(t, entered, "actual authenticated exec")
			switch loss {
			case "eof":
				_ = peer.writer.Close()
			case "owner":
				close(fixture.owner)
			case "cancel":
				fixture.cancel()
			case "hard-expiry":
				fixture.clock.awaitDelay(t, session.MaxGuestCredentialSessionLifetime)
				fixture.clock.advance(session.MaxGuestCredentialSessionLifetime)
			case "second-request":
				write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 2))
			case "partial-header-eof":
				write(t, peer, []byte{1, 2})
				_ = peer.writer.Close()
			case "partial-body-eof":
				wire := workloadRecord(t, fixture, state, workloadInnerExec(t), 2)
				write(t, peer, wire[:session.SecureRecordHeaderBytes+1])
				_ = peer.writer.Close()
			}
			await(t, canceled, "blocked exec observed actual transport loss")
			fixture.wait(t)
			if backend.calls.Load() != 1 {
				t.Fatal("busy transport queued another backend call")
			}
		})
	}
}

func TestWorkloadTransportRejectsAuthenticatedBadEnvelopeBeforeBackend(t *testing.T) {
	for _, mutation := range []string{"ordinal-gap", "wrong-binding", "wrong-session", "wrong-frame", "oversized-header"} {
		t.Run(mutation, func(t *testing.T) {
			backend := &workloadTransportBackend{}
			fixture := newWorkloadTransportFixture(t, backend)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			fixture.readiness(t, peer, state, fixture.binding)
			id := state.SessionID()
			ordinal := uint64(1)
			if mutation == "ordinal-gap" {
				ordinal = 2
			}
			if mutation == "wrong-session" {
				id[0]++
			}
			payload, err := fixture.binding.EncodeWorkload(workloadInnerExec(t), ordinal, id)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "wrong-binding" {
				payload[40] ^= 1
			}
			kind := session.FrameTypeControlRequest
			if mutation == "wrong-frame" {
				kind = session.FrameTypeControlPrivate
			}
			wire, err := state.SealApplication(kind, payload)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "oversized-header" {
				binary.BigEndian.PutUint32(wire[16:20], MaxWorkloadMessageBytes+session.GCMTagBytes+1)
				wire = wire[:session.SecureRecordHeaderBytes]
			}
			write(t, peer, wire)
			assertClosed(t, peer)
			fixture.wait(t)
			if backend.calls.Load() != 0 {
				t.Fatal("invalid outer envelope crossed backend boundary")
			}
		})
	}
}

func TestWorkloadTransportBlockedResponseWriteObservesEOF(t *testing.T) {
	fixture := newWorkloadTransportFixture(t, &workloadTransportBackend{})
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	fixture.readiness(t, peer, state, fixture.binding)
	write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 1))
	peer.other.awaitIO(t, 11, 4)
	_ = peer.writer.Close()
	await(t, fixture.server.Done(), "blocked response write joined after EOF")
	fixture.wait(t)
}

func TestWorkloadTransportInvalidServeConsumesOriginalOneShot(t *testing.T) {
	common := testOptions()
	transport, err := NewWorkloadTransport(BootstrapOptions{Listener: common.Listener, Boot: testBoot(t), OwnerDone: common.OwnerDone})
	if err != nil {
		t.Fatal(err)
	}
	limits := server.Limits{MaxRequestBytes: server.DefaultMaxRequestBytes, MaxResponseBytes: server.DefaultMaxResponseBytes}
	if err := transport.Serve(context.Background(), limits, nil); err != ErrInvalid {
		t.Fatal("invalid handler accepted")
	}
	select {
	case <-transport.(*workloadTransport).bootstrap.Done():
	default:
		t.Fatal("invalid selected Serve failed to consume and finish original one-shot")
	}
	if err := transport.Serve(context.Background(), limits, nil); err != ErrUsed {
		t.Fatal("invalid first Serve permitted reuse")
	}
}

func TestWorkloadTransportMaximumCopyUsesExistingV1BytesAndDigest(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 127, 255}, int(server.DefaultCopyBytes)/4)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	var copied atomic.Int32
	backend := &workloadTransportBackend{
		copyIn: func(_ context.Context, plan server.CopyInPlan) (server.CopyResult, error) {
			if plan.DestinationPath != "/workspace/payload.bin" || plan.MaxBytes != server.DefaultCopyBytes || plan.Digest != digest || !bytes.Equal(plan.Data, data) {
				return server.CopyResult{}, errors.New("copy plan differs")
			}
			copied.Add(1)
			return server.CopyResult{Published: true, SizeBytes: int64(len(data)), Digest: digest}, nil
		},
		copyOut: func(_ context.Context, plan server.CopyOutPlan) (server.CopyResult, error) {
			if plan.SourcePath != "/workspace/payload.bin" || plan.MaxBytes != server.DefaultCopyBytes {
				return server.CopyResult{}, errors.New("copy plan differs")
			}
			copied.Add(1)
			return server.CopyResult{Data: data, SizeBytes: int64(len(data)), Digest: digest}, nil
		},
	}
	fixture := newWorkloadTransportFixture(t, backend)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	fixture.readiness(t, peer, state, fixture.binding)
	request, err := json.Marshal(guestagent.CopyInRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationCopyIn,
		DestinationPath: "/workspace/payload.bin", Payload: guestagent.PayloadMetadata{Data: base64.StdEncoding.EncodeToString(data), Encoding: guestagent.PayloadEncodingBase64,
			SizeBytes: int64(len(data)), MaxBytes: server.DefaultCopyBytes, Digest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	write(t, peer, workloadRecord(t, fixture, state, request, 1))
	response := workloadResponse(t, fixture, peer, state, 1)
	var in guestagent.CopyInResponse
	if json.Unmarshal(response, &in) != nil || in.Error != nil || in.Written.Digest != digest || in.Written.SizeBytes != int64(len(data)) {
		t.Fatal("copy publication response differs")
	}
	clear(response)
	request, err = json.Marshal(guestagent.CopyOutRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationCopyOut,
		SourcePath: "/workspace/payload.bin", Payload: guestagent.PayloadMetadata{MaxBytes: server.DefaultCopyBytes, Encoding: guestagent.PayloadEncodingBase64}})
	if err != nil {
		t.Fatal(err)
	}
	write(t, peer, workloadRecord(t, fixture, state, request, 2))
	response = workloadResponse(t, fixture, peer, state, 2)
	var out guestagent.CopyOutResponse
	if json.Unmarshal(response, &out) != nil || out.Error != nil || out.Payload.Digest != digest || out.Payload.Data != base64.StdEncoding.EncodeToString(data) {
		t.Fatal("copy-out response differs")
	}
	clear(response)
	if copied.Load() != 2 || backend.calls.Load() != 0 || !bytes.Equal(data, bytes.Repeat([]byte{0, 1, 127, 255}, len(data)/4)) {
		t.Fatal("copy output mutated or dispatched unrelated backend")
	}
}

func TestWorkloadTransportRejectsInnerReadinessAndMalformedRequest(t *testing.T) {
	backend := &workloadTransportBackend{}
	fixture := newWorkloadTransportFixture(t, backend)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	fixture.readiness(t, peer, state, fixture.binding)
	for index, inner := range []string{`{"protocolVersion":"guest-agent-v1","operation":"readiness"}`, `{"operation":`, `null`} {
		ordinal := uint64(index + 1)
		write(t, peer, workloadRecord(t, fixture, state, []byte(inner), ordinal))
		response := workloadResponse(t, fixture, peer, state, ordinal)
		if !json.Valid(response) || !bytes.Contains(response, []byte(`"error"`)) {
			t.Fatal("invalid inner request was not rejected by common parser")
		}
		clear(response)
	}
	if backend.calls.Load() != 0 {
		t.Fatal("inner protocol rejection executed work")
	}
}

func TestWorkloadTransportRequestHonorsSmallerEnclosingLimit(t *testing.T) {
	backend := &workloadTransportBackend{}
	fixture := newWorkloadTransportFixture(t, backend, func(options *server.Options) { options.MaxRequestBytes = 128 })
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	fixture.readiness(t, peer, state, fixture.binding)
	inner := workloadInnerExec(t)
	if len(inner) <= 128 {
		t.Fatal("request fixture does not cross selected lower bound")
	}
	write(t, peer, workloadRecord(t, fixture, state, inner, 1))
	assertClosed(t, peer)
	fixture.wait(t)
	if backend.calls.Load() != 0 {
		t.Fatal("request enlarged enclosing limit")
	}
}

func TestWorkloadTransportPanicRetiresWithoutRawPayload(t *testing.T) {
	for _, stage := range []string{"prepare", "exec"} {
		t.Run(stage, func(t *testing.T) {
			backend := &workloadTransportBackend{}
			if stage == "prepare" {
				backend.ready = func(context.Context) error { panic("private-panic-canary") }
			} else {
				backend.exec = func(context.Context, server.ExecPlan) (server.ExecResult, error) { panic("private-panic-canary") }
			}
			fixture := newWorkloadTransportFixture(t, backend)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			if stage == "prepare" {
				wire, err := state.SealApplication(session.FrameTypeControlRequest, testRequest(t, fixture.binding, state.SessionID()))
				if err != nil {
					t.Fatal(err)
				}
				write(t, peer, wire)
			} else {
				fixture.readiness(t, peer, state, fixture.binding)
				write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 1))
			}
			assertClosed(t, peer)
			err := fixture.wait(t)
			if err == nil || bytes.Contains([]byte(err.Error()), []byte("private-panic-canary")) {
				t.Fatal("panic became success or leaked payload")
			}
		})
	}
}
