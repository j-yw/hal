package minimalcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
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
func (*workloadTransportBackend) CopyIn(context.Context, server.CopyInPlan) (server.CopyResult, error) {
	return server.CopyResult{}, errors.New("unused copy")
}
func (*workloadTransportBackend) CopyOut(context.Context, server.CopyOutPlan) (server.CopyResult, error) {
	return server.CopyResult{}, errors.New("unused copy")
}
func (backend *workloadTransportBackend) Close(context.Context) error {
	backend.closes.Add(1)
	return nil
}

func newWorkloadTransportFixture(t *testing.T, backend *workloadTransportBackend) *bootstrapFixture {
	t.Helper()
	common := testOptions()
	owner := make(chan struct{})
	transport, err := NewWorkloadTransport(BootstrapOptions{Listener: common.Listener, Boot: testBoot(t), OwnerDone: owner,
		Clock: common.Clock, Random: bytes.NewReader(bytes.Repeat([]byte{73}, 32*session.MaxPreAuthConnections))})
	if err != nil {
		t.Fatal(err)
	}
	enclosing, err := server.New(server.Options{Transport: transport, Backend: backend, WorkloadIsolationVerifier: workloadTransportVerifier{},
		RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
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
		if json.Unmarshal(inner, &response) != nil || response.ExitCode != 7 || response.Stdout.Data != "exact output\n" {
			t.Fatalf("response was not exact existing v1 output: %s", inner)
		}
		clear(inner)
	}
	if backend.calls.Load() != 50 {
		t.Fatal("work was duplicated or dropped")
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
