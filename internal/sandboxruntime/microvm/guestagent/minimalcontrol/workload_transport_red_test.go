package minimalcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// This first RED exercises actual Server.Serve and selected bootstrap/crypto.
// The backend is explicitly fake, with no filesystem, network, isolation or
// credential claim. Future local-proof setup belongs in the fixture constructor,
// not in these behavior assertions or a synthetic v1 readiness request.
func TestMinimalWorkloadAuthenticatedExecReachesServingBackend(t *testing.T) {
	fixture, enclosing, backend := newMinimalWorkloadFixture(t)
	peer := fixture.connect(t)
	if enclosing.State() != server.StateServing || backend.execCalls.Load() != 0 {
		t.Fatal("actual enclosing lifecycle did not reach serving before work")
	}
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	if backend.execCalls.Load() != 0 {
		t.Fatal("backend executed before authenticated readiness")
	}
	fixture.readiness(t, peer, state, fixture.binding)
	await(t, fixture.listener.closed, "single authenticated bootstrap claim")
	if !state.Established() || enclosing.State() != server.StateServing {
		t.Fatal("actual readiness did not retain the serving session")
	}
	wire := minimalWorkloadExecRecord(t, fixture.binding, state)
	defer clear(wire)
	write(t, peer, wire)
	select {
	case plan := <-backend.plans:
		if backend.execCalls.Load() != 1 || !reflect.DeepEqual(plan.Args, []string{"hal", "--version"}) ||
			plan.WorkDir != "/workspace" || len(plan.Environment) != 0 || len(plan.Stdin) != 0 ||
			plan.StdoutMaxBytes != 64 || plan.StderrMaxBytes != 64 {
			t.Fatal("authenticated exec did not preserve the exact bounded plan")
		}
	case err := <-fixture.result:
		fixture.waited = true
		await(t, fixture.server.Done(), "readiness bootstrap joined")
		t.Fatalf("authenticated exact-bound exec stopped before backend dispatch: calls=%d, result=%v", backend.execCalls.Load(), err)
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated exact-bound exec never reached backend; watchdog is not dispatch evidence")
	}
}

func TestMinimalWorkloadServingReadinessControl(t *testing.T) {
	fixture, enclosing, backend := newMinimalWorkloadFixture(t)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	fixture.readiness(t, peer, state, fixture.binding)
	await(t, fixture.listener.closed, "readiness claim")
	if !state.Established() || enclosing.State() != server.StateServing || backend.execCalls.Load() != 0 {
		t.Fatal("readiness alone executed work or bypassed the real serving lifecycle")
	}
}

func TestMinimalWorkloadDefaultBootstrapRemainsReadinessOnly(t *testing.T) {
	fixture := newBootstrapFixture(t, nil)
	peer := fixture.connect(t)
	state := fixture.authenticate(t, peer, true)
	defer state.Revoke()
	fixture.readiness(t, peer, state, fixture.binding)
	wire := minimalWorkloadExecRecord(t, fixture.binding, state)
	defer clear(wire)
	write(t, peer, wire)
	assertClosed(t, peer)
	if err := fixture.wait(t); err == nil || fixture.listener.accepts.Load() != 1 {
		t.Fatal("default readiness-only constructor accepted work or another session")
	}
}

func TestMinimalWorkloadEnclosingServerStillRequiresBackend(t *testing.T) {
	common := testOptions()
	listener := common.Listener.(*testListener)
	defer listener.Close()
	transport, err := NewWorkloadTransport(BootstrapOptions{Listener: listener, Boot: testBoot(t), OwnerDone: common.OwnerDone})
	if err != nil {
		t.Fatal(err)
	}
	if enclosing, err := server.New(server.Options{Transport: transport}); err == nil || enclosing != nil || listener.accepts.Load() != 0 {
		t.Fatal("missing backend was accepted or started bootstrap")
	}
}

func newMinimalWorkloadFixture(t *testing.T) (*bootstrapFixture, *server.Server, *minimalWorkloadBackend) {
	t.Helper()
	common := testOptions()
	owner := make(chan struct{})
	transport, err := NewWorkloadTransport(BootstrapOptions{Listener: common.Listener, Boot: testBoot(t), OwnerDone: owner,
		Clock: common.Clock, Random: bytes.NewReader(bytes.Repeat([]byte{73}, 32*session.MaxPreAuthConnections))})
	if err != nil {
		t.Fatal(err)
	}
	backend := &minimalWorkloadBackend{plans: make(chan server.ExecPlan, 1)}
	// The selected transport requires the accepted local-proof mode. This fake
	// inspector is setup only, not evidence of real Linux isolation.
	enclosing, err := server.New(server.Options{Transport: transport, Backend: backend,
		WorkloadIsolationVerifier: workloadTransportVerifier{}, RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
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
		if backend.closeCalls.Load() != 1 || backend.copyCalls.Load() != 0 {
			t.Fatal("enclosing Serve did not join backend close exactly once or dispatched unrelated copy")
		}
	})
	return fixture, enclosing, backend
}

// Independent test-only encoding of the proposed outer bytes. No operation
// codec exists yet. Actual v1 validation proves the inner request itself is
// valid, and the actual retained Binding/session supplies the exact correlation.
func minimalWorkloadExecRecord(t *testing.T, binding Binding, state *session.State) []byte {
	t.Helper()
	request := guestagent.ExecRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationExec,
		Args: []string{"hal", "--version"}, WorkDir: "/workspace",
		Stdout: guestagent.StreamMetadata{MaxBytes: 64}, Stderr: guestagent.StreamMetadata{MaxBytes: 64}}
	if err := guestagent.ValidateExecRequest(request); err != nil {
		t.Fatalf("inner fixture request is invalid: %v", err)
	}
	inner, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(inner)
	id := state.SessionID()
	digest, err := binding.Digest(id)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"body":{"bindingDigest":"` + digest + `","guestSessionGeneration":"` + base64.RawURLEncoding.EncodeToString(id[:]) +
		`","payload":"` + base64.StdEncoding.EncodeToString(inner) + `"},"operation":"workload","protocolVersion":"guest-agent-minimal-v1","requestId":"00000000000000000000000000000001"}`)
	defer clear(payload)
	if !json.Valid(payload) || len(payload) > MaxMessageBytes || !state.Established() {
		t.Fatal("fixture is malformed, exceeds even the old readiness bound, or lacks actual authentication")
	}
	wire, err := state.SealApplication(session.FrameTypeControlRequest, payload)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

type minimalWorkloadBackend struct {
	execCalls  atomic.Int32
	copyCalls  atomic.Int32
	closeCalls atomic.Int32
	plans      chan server.ExecPlan
}

func (*minimalWorkloadBackend) Ready(context.Context) error { return nil }
func (backend *minimalWorkloadBackend) Exec(_ context.Context, plan server.ExecPlan) (server.ExecResult, error) {
	backend.execCalls.Add(1)
	backend.plans <- plan
	return server.ExecResult{ExitCode: 0}, nil
}
func (backend *minimalWorkloadBackend) CopyIn(context.Context, server.CopyInPlan) (server.CopyResult, error) {
	backend.copyCalls.Add(1)
	return server.CopyResult{}, nil
}
func (backend *minimalWorkloadBackend) CopyOut(context.Context, server.CopyOutPlan) (server.CopyResult, error) {
	backend.copyCalls.Add(1)
	return server.CopyResult{}, nil
}
func (backend *minimalWorkloadBackend) Close(context.Context) error {
	backend.closeCalls.Add(1)
	return nil
}
