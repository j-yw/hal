package minimalcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

type bootstrapFixture struct {
	*testFixture
	binding Binding
}

func newBootstrapFixture(t *testing.T, mutate func(*BootstrapOptions)) *bootstrapFixture {
	t.Helper()
	common := testOptions()
	owner := make(chan struct{})
	options := BootstrapOptions{Listener: common.Listener, Boot: testBoot(t), OwnerDone: owner, Clock: common.Clock,
		Random: bytes.NewReader(bytes.Repeat([]byte{73}, 32*session.MaxPreAuthConnections))}
	if mutate != nil {
		mutate(&options)
	}
	agent, err := NewBootstrap(options)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding(testIdentity(), testBindingFields())
	if err != nil {
		t.Fatal(err)
	}
	fixture := &bootstrapFixture{testFixture: &testFixture{server: agent, listener: common.Listener.(*testListener), clock: common.Clock.(*testClock), owner: owner,
		key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize)), result: make(chan error, 1)}, binding: binding}
	ctx, cancel := context.WithCancel(context.Background())
	fixture.cancel = cancel
	go func() { fixture.result <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		for _, peer := range fixture.peers {
			_ = peer.Close()
		}
		if !fixture.waited {
			fixture.wait(t)
		}
	})
	return fixture
}

func (fixture *bootstrapFixture) authenticate(t *testing.T, peer *testPipe, finish bool) *session.State {
	t.Helper()
	return fixture.authenticateIdentity(t, peer, testIdentity(), fixture.binding, fixture.key, finish)
}

func (fixture *bootstrapFixture) authenticateIdentity(t *testing.T, peer *testPipe, identity session.Identity, binding Binding, key ed25519.PrivateKey, finish bool) *session.State {
	t.Helper()
	payload, err := binding.BootstrapPrelude()
	if err != nil {
		t.Fatal(err)
	}
	if err := frame.Write(peer, payload, MaxMessageBytes); err != nil {
		t.Fatal(err)
	}
	hello, err := readHandshake(peer)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := session.NewControllerHandshake(session.ControllerHandshakeConfig{
		ExpectedIdentity: identity, SigningKey: key, Dependencies: session.Dependencies{Now: fixture.clock.Now, Random: bytes.NewReader(bytes.Repeat([]byte{89}, 32))},
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
			t.Fatalf("guest Finished: %v", err)
		}
		wire, err = state.SealFinished()
		if err != nil {
			t.Fatal(err)
		}
		write(t, peer, wire)
	}
	return state
}

func (fixture *bootstrapFixture) readiness(t *testing.T, peer *testPipe, state *session.State, binding Binding) []byte {
	t.Helper()
	wire, err := state.SealApplication(session.FrameTypeControlRequest, testRequest(t, binding, state.SessionID()))
	if err != nil {
		t.Fatal(err)
	}
	write(t, peer, wire)
	response, err := readRecord(peer)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := binding.Digest(state.SessionID())
	plaintext, err := state.OpenApplication(response, func(kind session.FrameType, payload []byte) error {
		if kind != session.FrameTypeControlResponse {
			return ErrInvalid
		}
		var body struct {
			OK   bool `json:"ok"`
			Body struct {
				Capabilities  []string `json:"capabilities"`
				BindingDigest string   `json:"bindingDigest"`
			} `json:"body"`
		}
		if json.Unmarshal(payload, &body) != nil || !body.OK || len(body.Body.Capabilities) != 1 || body.Body.Capabilities[0] != "authenticated_minimal_control" || body.Body.BindingDigest != digest {
			return ErrInvalid
		}
		return nil
	})
	session.DestroyBytes(plaintext)
	if err != nil {
		t.Fatalf("authenticated minimal-only response: %v", err)
	}
	return wire
}

func TestBootstrapAcceptorProvisionalFailuresShareThreeAttemptsAndSingleClaim(t *testing.T) {
	fixture := newBootstrapFixture(t, nil)
	first := fixture.connect(t)
	if err := frame.Write(first, []byte(prelude), MaxMessageBytes); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, first)
	second := fixture.connect(t)
	changed := bytes.Replace(testBootstrapPrelude(t), []byte(`"workerId":"worker-1"`), []byte(`"workerId":"substituted"`), 1)
	if err := frame.Write(second, changed, MaxMessageBytes); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, second)
	third := fixture.connect(t)
	// The third attempt uses actual different late generations, demonstrating
	// that the per-connection tuple is completed rather than a shared mutable
	// original/failure tuple or a synthetic NewBinding placeholder.
	identity := testIdentity()
	identity.FirecrackerProcessGeneration, identity.VsockGeneration = "process-actual-3", "vsock-actual-3"
	fields := testBindingFields()
	fields["processGeneration"], fields["vsockGeneration"] = identity.FirecrackerProcessGeneration, identity.VsockGeneration
	binding, err := NewBinding(identity, fields)
	if err != nil {
		t.Fatal(err)
	}
	state := fixture.authenticateIdentity(t, third, identity, binding, fixture.key, true)
	defer state.Revoke()
	wire := fixture.readiness(t, third, state, binding)
	await(t, fixture.listener.closed, "minimal listener sealed")
	write(t, third, wire)
	assertClosed(t, third)
	if err := fixture.wait(t); err == nil {
		t.Fatal("replay claimed success")
	}
	if fixture.listener.accepts.Load() != 3 {
		t.Fatal("provisional failure reset attempts or claimed session reaccepted")
	}
	if err := fixture.server.Serve(context.Background()); err != ErrUsed {
		t.Fatal("bootstrap server was reusable")
	}
}

func TestBootstrapAcceptorExhaustionAndTruncationNeverEmitHello(t *testing.T) {
	fixture := newBootstrapFixture(t, nil)
	for index := range 3 {
		peer := fixture.connect(t)
		switch index {
		case 0:
			write(t, peer, []byte{0xff, 0xff, 0xff, 0xff})
		case 1:
			write(t, peer, []byte{0, 0})
			_ = peer.writer.Close() // peer EOF, not a product-cleanup watchdog
		case 2:
			write(t, peer, []byte{0, 0, 0, 10, '{'})
			_ = peer.writer.Close()
		}
		assertClosed(t, peer)
	}
	if err := fixture.wait(t); !errors.Is(err, session.ErrPreAuthExhausted) {
		t.Fatalf("exhaustion: %v", err)
	}
	if fixture.listener.accepts.Load() != 3 {
		t.Fatal("wrong attempt count")
	}
}

func TestBootstrapAcceptorLateIdentityAndBootPinsRequireOriginalCrypto(t *testing.T) {
	for _, kind := range []string{"process", "vsock", "nonce", "image", "runtime", "controller-generation", "controller-key"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newBootstrapFixture(t, nil)
			peer := fixture.connect(t)
			if err := frame.Write(peer, testBootstrapPrelude(t), MaxMessageBytes); err != nil {
				t.Fatal(err)
			}
			hello, err := readHandshake(peer)
			if err != nil {
				t.Fatal(err)
			}
			identity := testIdentity()
			key := fixture.key
			switch kind {
			case "process":
				identity.FirecrackerProcessGeneration += "-wrong"
			case "vsock":
				identity.VsockGeneration += "-wrong"
			case "nonce":
				identity.GuestBootNonce[0]++
			case "image":
				identity.ImageSHA256[0]++
			case "runtime":
				identity.RuntimeID += "-wrong"
			case "controller-generation":
				identity.ControllerKeyGeneration += "-wrong"
			case "controller-key":
				key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, 32))
			}
			controller, err := session.NewControllerHandshake(session.ControllerHandshakeConfig{ExpectedIdentity: identity, SigningKey: key,
				Dependencies: session.Dependencies{Now: fixture.clock.Now, Random: bytes.NewReader(bytes.Repeat([]byte{89}, 32))}})
			if err != nil {
				t.Fatal(err)
			}
			state, auth, err := controller.AcceptGuestHello(hello)
			if kind == "controller-key" {
				if err != nil {
					t.Fatal(err)
				}
				defer state.Revoke()
				write(t, peer, auth)
				assertClosed(t, peer)
			} else {
				if err == nil || state != nil || len(auth) != 0 {
					t.Fatal("substituted identity authenticated")
				}
				_ = peer.Close()
			}
			good := fixture.connect(t)
			state = fixture.authenticate(t, good, true)
			defer state.Revoke()
			fixture.readiness(t, good, state, fixture.binding)
			fixture.cancel()
			if err := fixture.wait(t); !errors.Is(err, context.Canceled) {
				t.Fatalf("terminal cancellation: %v", err)
			}
		})
	}
}

func TestBootstrapAcceptorClaimedInvalidReadinessCannotReadmit(t *testing.T) {
	for _, kind := range []string{"wrong-late-binding", "wrong-prelaunch-binding", "wrong-session", "unknown-operation"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newBootstrapFixture(t, nil)
			peer := fixture.connect(t)
			state := fixture.authenticate(t, peer, true)
			defer state.Revoke()
			payload := testRequest(t, fixture.binding, state.SessionID())
			switch kind {
			case "wrong-late-binding":
				payload = bytes.Replace(payload, []byte("process-generation-1"), []byte("process-replaced"), 1)
			case "wrong-prelaunch-binding":
				payload = bytes.Replace(payload, []byte("worker-1"), []byte("worker-replaced"), 1)
			case "wrong-session":
				payload = testRequest(t, fixture.binding, [32]byte{9})
			case "unknown-operation":
				payload = bytes.Replace(payload, []byte(`"readiness"`), []byte(`"exec"`), 1)
			}
			wire, err := state.SealApplication(session.FrameTypeControlRequest, payload)
			if err != nil {
				t.Fatal(err)
			}
			write(t, peer, wire)
			assertClosed(t, peer)
			if err := fixture.wait(t); err != ErrInvalid {
				t.Fatalf("invalid claimed readiness: %v", err)
			}
			if fixture.listener.accepts.Load() != 1 {
				t.Fatal("claimed failure reaccepted")
			}
		})
	}
}

// All new provisional I/O plus the unchanged crypto phases are driven using
// owned io.Pipe streams. Watchdogs only fail tests; they never close product
// resources to manufacture cancellation/timeout evidence.
func (fixture *bootstrapFixture) reachStage(t *testing.T, peer *testPipe, stage string) {
	t.Helper()
	switch stage {
	case "accept":
		await(t, fixture.listener.started, "pending accept")
	case "prelude-header": // connect observed the first product Read
	case "partial-prelude-header":
		write(t, peer, []byte{0, 0})
		peer.other.awaitIO(t, 2, 0)
	case "partial-prelude-body":
		payload := testBootstrapPrelude(t)
		prefix := make([]byte, 5)
		binary.BigEndian.PutUint32(prefix, uint32(len(payload)))
		prefix[4] = payload[0]
		write(t, peer, prefix)
		peer.other.awaitIO(t, 3, 0)
	case "hello-write", "partial-hello-write", "auth-read", "partial-auth-read":
		if err := frame.Write(peer, testBootstrapPrelude(t), MaxMessageBytes); err != nil {
			t.Fatal(err)
		}
		await(t, peer.other.writeStarted, "hello write")
		if stage == "partial-hello-write" {
			var first [4]byte
			if _, err := io.ReadFull(peer, first[:]); err != nil {
				t.Fatal(err)
			}
		}
		if stage == "auth-read" || stage == "partial-auth-read" {
			if _, err := readHandshake(peer); err != nil {
				t.Fatal(err)
			}
			peer.other.awaitIO(t, 3, 1)
			if stage == "partial-auth-read" {
				write(t, peer, []byte{0, 0})
				peer.other.awaitIO(t, 4, 1)
			}
		}
	case "finished-write", "partial-finished-read":
		state := fixture.authenticate(t, peer, false)
		t.Cleanup(state.Revoke)
		peer.other.awaitIO(t, 4, 2)
		if stage == "partial-finished-read" {
			wire, err := readRecord(peer)
			if err != nil || state.OpenFinished(wire) != nil {
				t.Fatal("guest Finished invalid")
			}
			wire, err = state.SealFinished()
			if err != nil {
				t.Fatal(err)
			}
			write(t, peer, wire[:2])
			peer.other.awaitIO(t, 6, 2)
		}
	case "readiness-read", "response-write", "established-read":
		state := fixture.authenticate(t, peer, true)
		t.Cleanup(state.Revoke)
		if stage == "established-read" {
			fixture.readiness(t, peer, state, fixture.binding)
			peer.other.awaitIO(t, 9, 3)
		} else if stage == "response-write" {
			wire, err := state.SealApplication(session.FrameTypeControlRequest, testRequest(t, fixture.binding, state.SessionID()))
			if err != nil {
				t.Fatal(err)
			}
			write(t, peer, wire)
			peer.other.awaitIO(t, 8, 3)
		} else {
			peer.other.awaitIO(t, 7, 2)
		}
	default:
		t.Fatalf("unknown stage %s", stage)
	}
}

func TestBootstrapAcceptorEveryPendingPhaseClosesOnCancelOwnerLossAndDeadline(t *testing.T) {
	stages := []string{"accept", "prelude-header", "partial-prelude-header", "partial-prelude-body", "hello-write", "partial-hello-write", "auth-read", "partial-auth-read", "finished-write", "partial-finished-read", "readiness-read", "response-write", "established-read"}
	for _, stage := range stages {
		for _, cause := range []string{"cancel", "owner", "deadline"} {
			t.Run(stage+"/"+cause, func(t *testing.T) {
				fixture := newBootstrapFixture(t, nil)
				var peer *testPipe
				if stage != "accept" {
					peer = fixture.connect(t)
				}
				fixture.reachStage(t, peer, stage)
				want := error(context.Canceled)
				switch cause {
				case "cancel":
					fixture.cancel()
				case "owner":
					close(fixture.owner)
					want = ErrOwnerLost
				case "deadline":
					delay := session.HandshakeDeadline
					if stage == "accept" {
						delay *= 3
					}
					if stage == "established-read" {
						delay = session.MaxGuestCredentialSessionLifetime
						fixture.clock.awaitDelay(t, delay)
					}
					fixture.clock.advance(delay)
					want = ErrTimeout
					if peer != nil {
						await(t, peer.other.closed, "product deadline closes stream")
					}
					// A preclaim attempt deadline consumes a slot but retains the
					// original boot budget. Expire that same clock to join Serve.
					if stage != "accept" && stage != "established-read" && stage != "readiness-read" && stage != "response-write" {
						fixture.clock.advance(2 * session.HandshakeDeadline)
					}
				}
				if err := fixture.wait(t); !errors.Is(err, want) {
					t.Fatalf("termination = %v, want %v", err, want)
				}
				if peer != nil {
					assertClosed(t, peer)
				}
			})
		}
	}
}

func TestBootstrapAcceptorPartialPreludeTimeoutConsumesAttemptNotBootReset(t *testing.T) {
	fixture := newBootstrapFixture(t, nil)
	for range 2 {
		peer := fixture.connect(t)
		fixture.reachStage(t, peer, "partial-prelude-body")
		fixture.clock.advance(session.HandshakeDeadline)
		assertClosed(t, peer)
	}
	third := fixture.connect(t)
	state := fixture.authenticate(t, third, true)
	defer state.Revoke()
	fixture.readiness(t, third, state, fixture.binding)
	fixture.cancel()
	if err := fixture.wait(t); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if fixture.listener.accepts.Load() != 3 {
		t.Fatal("attempt deadline created a fresh gate")
	}

	fixture = newBootstrapFixture(t, nil)
	peer := fixture.connect(t)
	if err := frame.Write(peer, []byte("null"), MaxMessageBytes); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, peer)
	fixture.clock.advance(3 * session.HandshakeDeadline)
	if err := fixture.wait(t); !errors.Is(err, ErrTimeout) {
		t.Fatal("failure reset boot deadline")
	}
}

func TestBootstrapAcceptorEntropyFailureAfterValidPreludeNeverWrites(t *testing.T) {
	for name, random := range map[string]io.Reader{
		"short": bytes.NewReader([]byte{1, 2, 3}),
		"error": iotest.ErrReader(errors.New("private entropy canary")),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newBootstrapFixture(t, func(options *BootstrapOptions) { options.Random = random })
			for range 3 {
				peer := fixture.connect(t)
				if err := frame.Write(peer, testBootstrapPrelude(t), MaxMessageBytes); err != nil {
					t.Fatal(err)
				}
				assertClosed(t, peer)
				if peer.other.writes.Load() != 0 {
					t.Fatal("failed entropy emitted hello")
				}
			}
			if err := fixture.wait(t); !errors.Is(err, session.ErrPreAuthExhausted) || strings.Contains(err.Error(), "canary") {
				t.Fatalf("entropy failure: %v", err)
			}
		})
	}
}

func TestBootstrapAcceptorConstructorPinsAndDependencies(t *testing.T) {
	common := testOptions()
	options := BootstrapOptions{Listener: common.Listener, Boot: testBoot(t), OwnerDone: common.OwnerDone}
	agent, err := NewBootstrap(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := agent.options.Random.(bootstrapEntropy); !ok {
		t.Fatal("bootstrap defaulted to blocking session randomness")
	}
	if agent.options.Clock == nil {
		t.Fatal("missing default clock")
	}
	before := *agent.boot
	options.Boot = BootConfig{}
	if *agent.boot != before {
		t.Fatal("caller replaced pinned boot config")
	}
	for _, change := range []func(*BootstrapOptions){
		func(options *BootstrapOptions) { options.Listener = nil },
		func(options *BootstrapOptions) { options.Listener = (*testListener)(nil) },
		func(options *BootstrapOptions) { options.OwnerDone = nil },
		func(options *BootstrapOptions) { options.Boot = BootConfig{} },
		func(options *BootstrapOptions) { options.Clock = (*testClock)(nil) },
		func(options *BootstrapOptions) { options.Random = (*bytes.Reader)(nil) },
	} {
		invalid := BootstrapOptions{Listener: common.Listener, Boot: testBoot(t), OwnerDone: common.OwnerDone}
		change(&invalid)
		if _, err := NewBootstrap(invalid); err != ErrInvalid {
			t.Fatal("invalid bootstrap dependency accepted")
		}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("private cancellation canary"))
	if err := agent.Serve(ctx); !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("canceled bootstrap start: %v", err)
	}
	if common.Listener.(*testListener).accepts.Load() != 0 {
		t.Fatal("canceled bootstrap accepted")
	}
}

func TestBootstrapAcceptorCancellationAtProvisionalAndEntropyBoundaries(t *testing.T) {
	for _, stage := range []string{"completed-prelude", "completed-entropy"} {
		t.Run(stage, func(t *testing.T) {
			common := testOptions()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var framed bytes.Buffer
			if err := frame.Write(&framed, testBootstrapPrelude(t), MaxMessageBytes); err != nil {
				t.Fatal(err)
			}
			stream := &bootstrapBoundaryStream{Reader: bytes.NewReader(framed.Bytes())}
			if stage == "completed-prelude" {
				stream.afterPrelude = cancel
			}
			listener := common.Listener.(*testListener)
			listener.connections <- stream
			entropyCalls := 0
			random := bootstrapRandomFunc(func(value []byte) (int, error) {
				entropyCalls++
				copy(value, bytes.Repeat([]byte{73}, len(value)))
				if stage == "completed-entropy" {
					cancel()
				}
				return len(value), nil
			})
			agent, err := NewBootstrap(BootstrapOptions{Listener: listener, Boot: testBoot(t), OwnerDone: common.OwnerDone, Clock: common.Clock, Random: random})
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.Serve(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("boundary cancellation: %v", err)
			}
			if stream.writes.Load() != 0 || stream.closes.Load() != 1 || stage == "completed-prelude" && entropyCalls != 0 {
				t.Fatalf("canceled bootstrap crossed next boundary: writes=%d closes=%d entropy=%d", stream.writes.Load(), stream.closes.Load(), entropyCalls)
			}
		})
	}
}

type bootstrapRandomFunc func([]byte) (int, error)

func (read bootstrapRandomFunc) Read(value []byte) (int, error) { return read(value) }

type bootstrapBoundaryStream struct {
	*bytes.Reader
	afterPrelude   func()
	writes, closes atomic.Int32
}

func (stream *bootstrapBoundaryStream) Read(value []byte) (int, error) {
	n, err := stream.Reader.Read(value)
	if stream.Reader.Len() == 0 && stream.afterPrelude != nil {
		stream.afterPrelude()
		stream.afterPrelude = nil
	}
	return n, err
}
func (stream *bootstrapBoundaryStream) Write([]byte) (int, error) {
	stream.writes.Add(1)
	return 0, io.ErrClosedPipe
}
func (stream *bootstrapBoundaryStream) Close() error { stream.closes.Add(1); return nil }
