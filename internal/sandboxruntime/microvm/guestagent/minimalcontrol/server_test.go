package minimalcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func TestAcceptorThreeAttemptExhaustion(t *testing.T) {
	fixture := newFixture(t, nil)
	for range 3 {
		peer := fixture.connect(t)
		if err := frame.Write(peer, []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness"}`), 512); err != nil {
			t.Fatal(err)
		}
		assertClosed(t, peer)
	}
	if err := fixture.wait(t); !errors.Is(err, session.ErrPreAuthExhausted) {
		t.Fatalf("attempt exhaustion = %v", err)
	}
	if fixture.listener.accepts.Load() != 3 {
		t.Fatalf("accepted %d connections, want exactly three", fixture.listener.accepts.Load())
	}
	if err := fixture.server.Serve(context.Background()); !errors.Is(err, ErrUsed) {
		t.Fatalf("server retry = %v", err)
	}
}

func TestAcceptorFailedAuthenticationDoesNotClaim(t *testing.T) {
	fixture := newFixture(t, nil)
	peer := fixture.connect(t)
	wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, ed25519.SeedSize))
	state := fixture.authenticate(t, peer, wrongKey, false)
	defer state.Revoke()
	assertClosed(t, peer)
	good := fixture.connect(t)
	state = fixture.authenticate(t, good, fixture.key, true)
	defer state.Revoke()
	fixture.readiness(t, good, state)
	if fixture.listener.accepts.Load() != 2 {
		t.Fatal("failed authentication was not isolated from the next bounded attempt")
	}
	fixture.cancel()
	if err := fixture.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel claimed session = %v", err)
	}
}

func TestAcceptorSingleClaimAndReplayLoss(t *testing.T) {
	fixture := newFixture(t, nil)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, fixture.key, true)
	defer state.Revoke()
	wire := fixture.readiness(t, peer, state)
	// There is no Accept after the first authenticated claim; closing the
	// listener seals the backlog rather than allowing another v1/minimal job.
	await(t, fixture.listener.closed, "listener closure after readiness")
	write(t, peer, wire)
	assertClosed(t, peer)
	if err := fixture.wait(t); err == nil {
		t.Fatal("replay loss reported success")
	}
	if fixture.listener.accepts.Load() != 1 {
		t.Fatal("a second connection was accepted after the claim")
	}
}

func TestAcceptorPendingCancellationAndOwnerLoss(t *testing.T) {
	for _, stage := range []string{"accept", "prelude read", "hello write", "auth read", "finished write", "readiness read", "response write", "established read"} {
		for _, ownerLoss := range []bool{false, true} {
			name := stage + "/cancel"
			if ownerLoss {
				name = stage + "/owner loss"
			}
			t.Run(name, func(t *testing.T) {
				fixture := newFixture(t, nil)
				var peer *testPipe
				if stage != "accept" {
					peer = fixture.connect(t)
				}
				fixture.reachStage(t, peer, stage)
				if ownerLoss {
					close(fixture.owner)
				} else {
					fixture.cancel()
				}
				err := fixture.wait(t)
				want := error(context.Canceled)
				if ownerLoss {
					want = ErrOwnerLost
				}
				if !errors.Is(err, want) {
					t.Fatalf("terminal cause=%v, want %v", err, want)
				}
				if peer != nil {
					assertClosed(t, peer)
				}
			})
		}
	}
}

func TestAcceptorClockBoundsIdleBootHandshakeReadinessAndLifetime(t *testing.T) {
	t.Run("idle accept boot budget", func(t *testing.T) {
		fixture := newFixture(t, nil)
		await(t, fixture.listener.started, "pending accept")
		fixture.clock.advance(3 * session.HandshakeDeadline)
		if err := fixture.wait(t); !errors.Is(err, ErrTimeout) {
			t.Fatalf("idle boot expiry = %v", err)
		}
	})
	for _, stage := range []string{"prelude read", "hello write", "auth read", "finished write", "readiness read", "response write"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newFixture(t, nil)
			peer := fixture.connect(t)
			fixture.reachStage(t, peer, stage)
			fixture.clock.advance(session.HandshakeDeadline)
			await(t, peer.other.closed, "product timeout stream closure")
			assertClosed(t, peer)
			// A pre-auth timeout consumes an attempt; a post-auth timeout is
			// terminal. Either way no ready response was manufactured.
			fixture.cancel()
			if err := fixture.wait(t); err == nil {
				t.Fatal("expiry reported success")
			}
		})
	}
	t.Run("established hard expiry", func(t *testing.T) {
		fixture := newFixture(t, nil)
		peer := fixture.connect(t)
		state := fixture.authenticate(t, peer, fixture.key, true)
		defer state.Revoke()
		fixture.readiness(t, peer, state)
		fixture.clock.awaitDelay(t, session.MaxGuestCredentialSessionLifetime)
		fixture.clock.advance(session.MaxGuestCredentialSessionLifetime - time.Nanosecond)
		select {
		case <-fixture.server.Done():
			t.Fatal("session expired before the hard deadline")
		default:
		}
		fixture.clock.advance(time.Nanosecond)
		if err := fixture.wait(t); !errors.Is(err, ErrTimeout) {
			t.Fatalf("hard expiry = %v", err)
		}
		assertClosed(t, peer)
	})
}

func TestAcceptorShortAndErrorEntropyFailWithoutOutput(t *testing.T) {
	for name, random := range map[string]io.Reader{
		"short": bytes.NewReader([]byte{1, 2, 3}),
		"error": iotest.ErrReader(errors.New("private entropy adapter detail")),
	} {
		t.Run(name, func(t *testing.T) {
			options := testOptions()
			options.Random = random
			listener := options.Listener.(*testListener)
			var streams []*entropyStream
			for range session.MaxPreAuthConnections {
				stream := new(entropyStream)
				streams = append(streams, stream)
				listener.connections <- stream
			}
			agent, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.Serve(context.Background()); !errors.Is(err, session.ErrPreAuthExhausted) {
				t.Fatalf("entropy failure = %v", err)
			}
			await(t, agent.Done(), "entropy-failed acceptor cleanup")
			for _, stream := range streams {
				if stream.writes.Load() != 0 || !stream.closed.Load() {
					t.Fatal("entropy failure emitted bytes or retained transport")
				}
			}
		})
	}
}

func TestAcceptorParentCauseIsSanitized(t *testing.T) {
	options := testOptions()
	agent, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("private caller cancellation detail"))
	if err := agent.Serve(ctx); !errors.Is(err, context.Canceled) || err.Error() != context.Canceled.Error() {
		t.Fatalf("caller cause escaped the control boundary: %v", err)
	}
	if options.Listener.(*testListener).accepts.Load() != 0 {
		t.Fatal("canceled server accepted a connection")
	}
}

func TestAcceptorClosesPartialAcceptAndInvalidStart(t *testing.T) {
	t.Run("partial accept", func(t *testing.T) {
		stream := new(entropyStream)
		listener := &errorListener{stream: stream, err: errors.New("private accept error")}
		options := testOptions()
		options.Listener = listener
		agent, err := New(options)
		if err != nil {
			t.Fatal(err)
		}
		if err := agent.Serve(context.Background()); !errors.Is(err, ErrUnavailable) || !stream.closed.Load() || !listener.closed.Load() {
			t.Fatalf("partial accept cleanup: result=%v, streamClosed=%v, listenerClosed=%v", err, stream.closed.Load(), listener.closed.Load())
		}
	})
	t.Run("nil context", func(t *testing.T) {
		options := testOptions()
		agent, err := New(options)
		if err != nil {
			t.Fatal(err)
		}
		if err := agent.Serve(nil); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
		select {
		case <-options.Listener.(*testListener).closed:
		default:
			t.Fatal("one-shot invalid Serve retained its listener")
		}
	})
}

type errorListener struct {
	stream io.ReadWriteCloser
	err    error
	closed atomic.Bool
}

func (listener *errorListener) Accept(context.Context) (io.ReadWriteCloser, error) {
	return listener.stream, listener.err
}
func (listener *errorListener) Close() error { listener.closed.Store(true); return nil }

type entropyStream struct {
	writes atomic.Int32
	closed atomic.Bool
}

func (*entropyStream) Read([]byte) (int, error) { return 0, io.EOF }
func (stream *entropyStream) Write(value []byte) (int, error) {
	stream.writes.Add(1)
	return len(value), nil
}
func (stream *entropyStream) Close() error { stream.closed.Store(true); return nil }

func TestAcceptorImmutableOptionsAndInvalidConfiguration(t *testing.T) {
	t.Run("caller mutations do not alter pins", func(t *testing.T) {
		fixture := newFixture(t, func(options *Options) {
			options.Identity.RuntimeID = "other"
			options.Binding["workerJobId"] = "other"
			for i := range options.PinnedControllerPublicKey {
				options.PinnedControllerPublicKey[i] = 0
			}
		})
		peer := fixture.connect(t)
		state := fixture.authenticate(t, peer, fixture.key, true)
		defer state.Revoke()
		fixture.readiness(t, peer, state)
		fixture.cancel()
		_ = fixture.wait(t)
	})
	for _, change := range []func(*Options){
		func(options *Options) { options.Listener = nil },
		func(options *Options) { options.Listener = (*testListener)(nil) },
		func(options *Options) { options.OwnerDone = nil },
		func(options *Options) { options.PinnedControllerPublicKey = nil },
		func(options *Options) { options.PinnedControllerPublicKey = make([]byte, 31) },
		func(options *Options) { options.Clock = (*testClock)(nil) },
		func(options *Options) { options.Random = (*bytes.Reader)(nil) },
		func(options *Options) { options.Binding = nil },
	} {
		options := testOptions()
		change(&options)
		if _, err := New(options); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid configuration error=%v", err)
		}
	}
}

func TestAcceptorRejectsOversizedFramesBeforeAllocation(t *testing.T) {
	fixture := newFixture(t, nil)
	peer := fixture.connect(t)
	write(t, peer, []byte{0xff, 0xff, 0xff, 0xff})
	assertClosed(t, peer)
	peer = fixture.connect(t)
	state := fixture.authenticate(t, peer, fixture.key, true)
	defer state.Revoke()
	wire, err := state.SealApplication(session.FrameTypeControlRequest, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(wire[16:20], MaxMessageBytes+session.GCMTagBytes+1)
	write(t, peer, wire[:session.SecureRecordHeaderBytes])
	assertClosed(t, peer)
	if err := fixture.wait(t); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized record = %v", err)
	}
}

type testFixture struct {
	server   *Server
	listener *testListener
	clock    *testClock
	key      ed25519.PrivateKey
	owner    chan struct{}
	cancel   context.CancelFunc
	result   chan error
	peers    []*testPipe
	waited   bool
}

func testOptions() Options {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	return Options{
		Listener: &testListener{connections: make(chan io.ReadWriteCloser, 4), closed: make(chan struct{}), started: make(chan struct{}, 8)},
		Identity: testIdentity(), Binding: testBindingFields(), PinnedControllerPublicKey: key.Public().(ed25519.PublicKey),
		OwnerDone: make(chan struct{}), Clock: &testClock{now: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC), changed: make(chan struct{}, 16)},
	}
}

func newFixture(t *testing.T, mutateAfterNew func(*Options)) *testFixture {
	t.Helper()
	options := testOptions()
	owner := make(chan struct{})
	options.OwnerDone = owner
	agent, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &testFixture{server: agent, listener: options.Listener.(*testListener), clock: options.Clock.(*testClock), owner: owner,
		key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize)), result: make(chan error, 1)}
	if mutateAfterNew != nil {
		mutateAfterNew(&options)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fixture.cancel = cancel
	go func() { fixture.result <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		// No test watchdog closes streams to manufacture a product pass.
		// Cleanup closes them only after assertions, to avoid leaking a failed
		// test's fixture. A missing Serve join remains an explicit failure.
		for _, peer := range fixture.peers {
			_ = peer.Close()
		}
		if !fixture.waited {
			fixture.wait(t)
		}
	})
	return fixture
}

func (fixture *testFixture) connect(t *testing.T) *testPipe {
	t.Helper()
	guestRead, controllerWrite := io.Pipe()
	controllerRead, guestWrite := io.Pipe()
	guest := &testPipe{reader: guestRead, writer: guestWrite, readStarted: make(chan struct{}, 16), writeStarted: make(chan struct{}, 16), closed: make(chan struct{})}
	peer := &testPipe{reader: controllerRead, writer: controllerWrite, other: guest}
	fixture.peers = append(fixture.peers, peer)
	fixture.listener.connections <- guest
	await(t, guest.readStarted, "prelude read started")
	return peer
}

func (fixture *testFixture) wait(t *testing.T) error {
	t.Helper()
	select {
	case result := <-fixture.result:
		fixture.waited = true
		await(t, fixture.server.Done(), "server Done")
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("product did not stop/join; watchdog is not cleanup evidence")
		return nil
	}
}

func (fixture *testFixture) authenticate(t *testing.T, peer *testPipe, key ed25519.PrivateKey, finish bool) *session.State {
	t.Helper()
	if err := frame.Write(peer, []byte(prelude), 512); err != nil {
		t.Fatal(err)
	}
	hello, err := readHandshake(peer)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := session.NewControllerHandshake(session.ControllerHandshakeConfig{
		ExpectedIdentity: testIdentity(), SigningKey: key, Dependencies: session.Dependencies{Now: fixture.clock.Now},
	})
	if err != nil {
		t.Fatal(err)
	}
	state, auth, err := controller.AcceptGuestHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	write(t, peer, auth)
	if finish {
		wire, err := readRecord(peer)
		if err != nil || state.OpenFinished(wire) != nil {
			t.Fatalf("guest Finished = %v", err)
		}
		wire, err = state.SealFinished()
		if err != nil {
			t.Fatal(err)
		}
		write(t, peer, wire)
	}
	return state
}

func (fixture *testFixture) readiness(t *testing.T, peer *testPipe, state *session.State) []byte {
	t.Helper()
	payload := testRequest(t, fixture.server.binding, state.SessionID())
	wire, err := state.SealApplication(session.FrameTypeControlRequest, payload)
	if err != nil {
		t.Fatal(err)
	}
	write(t, peer, wire)
	response, err := readRecord(peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.OpenApplication(response, nil); err != nil {
		t.Fatal(err)
	}
	return wire
}

func (fixture *testFixture) reachStage(t *testing.T, peer *testPipe, stage string) {
	t.Helper()
	switch stage {
	case "accept":
		await(t, fixture.listener.started, "pending accept")
	case "prelude read":
		// connect waited for the product's first Read.
	case "hello write", "auth read":
		if err := frame.Write(peer, []byte(prelude), 512); err != nil {
			t.Fatal(err)
		}
		await(t, peer.other.writeStarted, "hello write")
		if stage == "auth read" {
			if _, err := readHandshake(peer); err != nil {
				t.Fatal(err)
			}
			peer.other.awaitIO(t, 3, 1)
		}
	case "finished write":
		state := fixture.authenticate(t, peer, fixture.key, false)
		t.Cleanup(state.Revoke)
		peer.other.awaitIO(t, 4, 2)
	case "readiness read", "response write", "established read":
		state := fixture.authenticate(t, peer, fixture.key, true)
		t.Cleanup(state.Revoke)
		if stage == "established read" {
			fixture.readiness(t, peer, state)
			peer.other.awaitIO(t, 9, 3)
		} else if stage == "response write" {
			wire, err := state.SealApplication(session.FrameTypeControlRequest, testRequest(t, fixture.server.binding, state.SessionID()))
			if err != nil {
				t.Fatal(err)
			}
			write(t, peer, wire)
			peer.other.awaitIO(t, 8, 3)
		} else {
			peer.other.awaitIO(t, 7, 2)
		}
	default:
		t.Fatalf("unknown test stage %s", stage)
	}
}

func write(t *testing.T, writer io.Writer, value []byte) {
	t.Helper()
	if n, err := writer.Write(value); n != len(value) || err != nil {
		t.Fatalf("write = %d/%d, %v", n, len(value), err)
	}
}

func assertClosed(t *testing.T, reader io.Reader) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		var next [1]byte
		n, err := reader.Read(next[:])
		if n > 0 || err == nil {
			err = errors.New("unexpected response bytes")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("stream was not closed without response: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("product did not close stream; watchdog is not cleanup evidence")
	}
}

func await(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

type testPipe struct {
	reader       *io.PipeReader
	writer       *io.PipeWriter
	other        *testPipe
	readStarted  chan struct{}
	writeStarted chan struct{}
	reads        atomic.Int32
	writes       atomic.Int32
	closed       chan struct{}
	closeOnce    sync.Once
}

func (pipe *testPipe) Read(value []byte) (int, error) {
	pipe.reads.Add(1)
	select {
	case pipe.readStarted <- struct{}{}:
	default:
	}
	return pipe.reader.Read(value)
}
func (pipe *testPipe) Write(value []byte) (int, error) {
	pipe.writes.Add(1)
	select {
	case pipe.writeStarted <- struct{}{}:
	default:
	}
	return pipe.writer.Write(value)
}
func (pipe *testPipe) Close() error {
	pipe.closeOnce.Do(func() {
		_ = pipe.reader.Close()
		_ = pipe.writer.Close()
		if pipe.closed != nil {
			close(pipe.closed)
		}
	})
	return nil
}

func (pipe *testPipe) awaitIO(t *testing.T, reads, writes int32) {
	t.Helper()
	for pipe.reads.Load() < reads || pipe.writes.Load() < writes {
		select {
		case <-pipe.readStarted:
		case <-pipe.writeStarted:
		case <-time.After(2 * time.Second):
			t.Fatalf("product did not reach pending I/O: read %d/%d, write %d/%d", pipe.reads.Load(), reads, pipe.writes.Load(), writes)
		}
	}
}

type testListener struct {
	connections chan io.ReadWriteCloser
	closed      chan struct{}
	started     chan struct{}
	once        sync.Once
	accepts     atomic.Int32
}

func (listener *testListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	listener.accepts.Add(1)
	listener.started <- struct{}{}
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.closed:
		return nil, io.EOF
	}
}
func (listener *testListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

type testClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*testTimer
	changed chan struct{}
}
type testTimer struct {
	clock  *testClock
	when   time.Time
	fire   func()
	active bool
}

func (clock *testClock) Now() time.Time { clock.mu.Lock(); defer clock.mu.Unlock(); return clock.now }
func (clock *testClock) AfterFunc(delay time.Duration, fire func()) Timer {
	clock.mu.Lock()
	timer := &testTimer{clock: clock, when: clock.now.Add(delay), fire: fire, active: true}
	clock.timers = append(clock.timers, timer)
	clock.mu.Unlock()
	select {
	case clock.changed <- struct{}{}:
	default:
	}
	return timer
}
func (timer *testTimer) Stop() bool {
	timer.clock.mu.Lock()
	defer timer.clock.mu.Unlock()
	active := timer.active
	timer.active = false
	return active
}
func (clock *testClock) advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	var callbacks []func()
	for _, timer := range clock.timers {
		if timer.active && !timer.when.After(clock.now) {
			timer.active = false
			callbacks = append(callbacks, timer.fire)
		}
	}
	clock.mu.Unlock()
	for _, fire := range callbacks {
		fire()
	}
}
func (clock *testClock) awaitDelay(t *testing.T, delay time.Duration) {
	t.Helper()
	for {
		clock.mu.Lock()
		found := false
		for _, timer := range clock.timers {
			found = found || timer.active && timer.when.Equal(clock.now.Add(delay))
		}
		clock.mu.Unlock()
		if found {
			return
		}
		await(t, clock.changed, "timer installation")
	}
}
