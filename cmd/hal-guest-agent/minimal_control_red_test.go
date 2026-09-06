package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
)

const minimalREDProtocol = "guest-agent-minimal-v1"

// This is an executable protocol-gap RED, not an existing minimal endpoint.
// Only newMinimalREDAdapter may change to the reviewed minimal constructor in
// GREEN. The controller transcript and acceptance/rejection assertions must
// survive that change. No test listener binds a socket or starts a process.
func TestMinimalControlREDReadinessAndBinding(t *testing.T) {
	t.Run("authenticated readiness has exactly the implemented capability", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		state := fixture.handshake(t, fixture.identity, fixture.key)
		request, digest := minimalREDRequest(t, state, fixture.binding)
		wire := minimalREDSeal(t, state, request)
		minimalREDWrite(t, fixture.controller, wire)
		minimalREDAssertReadiness(t, fixture.controller, state, digest)
	})
	for _, field := range []string{"executionId", "workerId", "workerJobId", "jobGeneration", "networkPlanId", "proxyGenerationId", "ruleGenerationId", "runtimeId", "imageDigest"} {
		t.Run("missing "+field, func(t *testing.T) {
			fixture := newMinimalREDFixture(t)
			state := fixture.handshake(t, fixture.identity, fixture.key)
			binding := maps.Clone(fixture.binding)
			delete(binding, field)
			request, _ := minimalREDRequest(t, state, binding)
			minimalREDWrite(t, fixture.controller, minimalREDSeal(t, state, request))
			minimalREDAssertClosed(t, fixture.controller)
		})
		t.Run("different "+field, func(t *testing.T) {
			fixture := newMinimalREDFixture(t)
			state := fixture.handshake(t, fixture.identity, fixture.key)
			binding := maps.Clone(fixture.binding)
			binding[field] += "-other"
			request, _ := minimalREDRequest(t, state, binding)
			minimalREDWrite(t, fixture.controller, minimalREDSeal(t, state, request))
			minimalREDAssertClosed(t, fixture.controller)
		})
	}
	t.Run("digest mismatch", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		state := fixture.handshake(t, fixture.identity, fixture.key)
		request, digest := minimalREDRequest(t, state, fixture.binding)
		request = bytes.Replace(request, []byte(digest), []byte("sha256-"+string(bytes.Repeat([]byte("0"), 64))), 1)
		minimalREDWrite(t, fixture.controller, minimalREDSeal(t, state, request))
		minimalREDAssertClosed(t, fixture.controller)
	})
	t.Run("duplicate proof-bearing key", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		state := fixture.handshake(t, fixture.identity, fixture.key)
		request, _ := minimalREDRequest(t, state, fixture.binding)
		request = bytes.Replace(request, []byte(`"workerJobId":"job-1"`), []byte(`"workerJobId":"job-other","workerJobId":"job-1"`), 1)
		minimalREDWrite(t, fixture.controller, minimalREDSeal(t, state, request))
		minimalREDAssertClosed(t, fixture.controller)
	})
}

func TestMinimalControlREDTranscriptIsolation(t *testing.T) {
	t.Run("wrong controller key", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, ed25519.SeedSize))
		controller, hello := fixture.controllerHello(t, fixture.identity, wrongKey)
		state, auth, err := controller.AcceptGuestHello(hello)
		if err != nil {
			t.Fatalf("valid guest hello was rejected before controller authentication: %v", err)
		}
		defer state.Revoke()
		minimalREDWrite(t, fixture.controller, auth)
		minimalREDAssertClosed(t, fixture.controller)
	})
	t.Run("cross runtime", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		expected := fixture.identity
		expected.RuntimeID = "runtime-other"
		controller, hello := fixture.controllerHello(t, expected, fixture.key)
		if _, _, err := controller.AcceptGuestHello(hello); !errors.Is(err, session.ErrIdentityMismatch) {
			t.Fatalf("cross-runtime hello error = %v, want identity mismatch", err)
		}
	})
	t.Run("same ciphertext cannot replay readiness", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		state := fixture.handshake(t, fixture.identity, fixture.key)
		request, digest := minimalREDRequest(t, state, fixture.binding)
		wire := minimalREDSeal(t, state, request)
		minimalREDWrite(t, fixture.controller, wire)
		minimalREDAssertReadiness(t, fixture.controller, state, digest)
		minimalREDWrite(t, fixture.controller, wire)
		minimalREDAssertClosed(t, fixture.controller)
	})
	t.Run("new sequence cannot re-admit the same job", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		state := fixture.handshake(t, fixture.identity, fixture.key)
		request, digest := minimalREDRequest(t, state, fixture.binding)
		minimalREDWrite(t, fixture.controller, minimalREDSeal(t, state, request))
		minimalREDAssertReadiness(t, fixture.controller, state, digest)
		minimalREDWrite(t, fixture.controller, minimalREDSeal(t, state, request))
		minimalREDAssertClosed(t, fixture.controller)
	})
	t.Run("cancellation closes the established session", func(t *testing.T) {
		fixture := newMinimalREDFixture(t)
		state := fixture.handshake(t, fixture.identity, fixture.key)
		request, digest := minimalREDRequest(t, state, fixture.binding)
		minimalREDWrite(t, fixture.controller, minimalREDSeal(t, state, request))
		minimalREDAssertReadiness(t, fixture.controller, state, digest)
		fixture.cancel()
		minimalREDAssertClosed(t, fixture.controller)
	})
}

// This separate compatibility assertion must keep exercising the OLD
// constructor after the RED adapter is replaced. A v1 server must never be
// changed to silently claim minimal or historical helper-based v2 readiness.
func TestMinimalControlLegacyV1StillRejectsOtherProfiles(t *testing.T) {
	for _, protocol := range []string{minimalREDProtocol, "guest-agent-v2"} {
		t.Run(protocol, func(t *testing.T) {
			fixture := newMinimalREDFixtureWithAdapter(t, newMinimalREDLegacyAdapter)
			payload, err := json.Marshal(map[string]string{"protocolVersion": protocol, "operation": "readiness"})
			if err != nil {
				t.Fatal(err)
			}
			if err := frame.Write(fixture.controller, payload, 512); err != nil {
				t.Fatal(err)
			}
			response, err := frame.Read(fixture.controller, 512)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				ProtocolVersion string `json:"protocolVersion"`
				OK              bool   `json:"ok"`
				Error           struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response, &decoded); err != nil || decoded.ProtocolVersion != "guest-agent-v1" || decoded.OK || decoded.Error.Code != "unsupported_protocol_version" {
				t.Fatalf("legacy rejection = %s, decode error %v", response, err)
			}
		})
	}
}

type minimalREDGuestConfig struct {
	identity session.Identity
	binding  map[string]string
	public   ed25519.PublicKey
}

type minimalREDServe func(context.Context) error
type minimalREDAdapter func(*testing.T, vsock.Listener, *minimalREDBackend, minimalREDGuestConfig) minimalREDServe

func newMinimalREDAdapter(t *testing.T, listener vsock.Listener, backend *minimalREDBackend, config minimalREDGuestConfig) minimalREDServe {
	// Intentionally delegate to today's selected v1 construction. Identity,
	// binding and pinned key have no consumer yet. Do not implement a fake
	// guest here: GREEN must supply the real, separately reviewed constructor.
	return newMinimalREDLegacyAdapter(t, listener, backend, config)
}

func newMinimalREDLegacyAdapter(t *testing.T, listener vsock.Listener, backend *minimalREDBackend, _ minimalREDGuestConfig) minimalREDServe {
	t.Helper()
	transport, err := vsock.NewTransport(vsock.Options{Listener: listener})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := server.New(server.Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	return agent.Serve
}

type minimalREDFixture struct {
	controller io.ReadWriteCloser
	identity   session.Identity
	binding    map[string]string
	key        ed25519.PrivateKey
	cancel     context.CancelFunc
}

func newMinimalREDFixture(t *testing.T) *minimalREDFixture {
	t.Helper()
	return newMinimalREDFixtureWithAdapter(t, newMinimalREDAdapter)
}

func newMinimalREDFixtureWithAdapter(t *testing.T, adapter minimalREDAdapter) *minimalREDFixture {
	t.Helper()
	guestReader, controllerWriter := io.Pipe()
	controllerReader, guestWriter := io.Pipe()
	guest := &minimalREDPipe{reader: guestReader, writer: guestWriter}
	controller := &minimalREDPipe{reader: controllerReader, writer: controllerWriter}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	identity := session.Identity{
		Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		GuestBootNonce: [32]byte{1}, ControllerKeyGeneration: "controller-key-1",
		RuntimeID: "runtime-1", RuntimeGeneration: "runtime-generation-1",
		FirecrackerProcessGeneration: "process-generation-1", VsockGeneration: "vsock-generation-1",
		BootGeneration: "boot-generation-1", ImageGeneration: "image-generation-1", ImageSHA256: [32]byte{2},
	}
	fixture := &minimalREDFixture{controller: controller, identity: identity, key: key, binding: minimalREDBinding(identity)}
	listener := &minimalREDListener{connections: make(chan io.ReadWriteCloser, 1)}
	listener.connections <- guest
	backend := new(minimalREDBackend)
	serve := adapter(t, listener, backend, minimalREDGuestConfig{identity: identity, binding: maps.Clone(fixture.binding), public: key.Public().(ed25519.PublicKey)})
	ctx, cancel := context.WithCancel(context.Background())
	fixture.cancel = cancel
	// The independent watchdog is a test failure, never evidence of product
	// cancellation or rejection. Calling fixture.cancel does NOT close pipes.
	var timedOut atomic.Bool
	watch := time.AfterFunc(2*time.Second, func() {
		timedOut.Store(true)
		_ = guest.Close()
		_ = controller.Close()
	})
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = guest.Close()
		_ = controller.Close()
		watch.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("guest server did not join after bounded cancellation")
		}
		if backend.operations.Load() != 0 {
			t.Error("minimal control dispatched a v1 backend operation")
		}
		if timedOut.Load() {
			t.Error("test watchdog closed a stuck protocol stream; rejection/cancellation was not observed")
		}
	})
	return fixture
}

func (fixture *minimalREDFixture) controllerHello(t *testing.T, identity session.Identity, key ed25519.PrivateKey) (*session.ControllerHandshake, []byte) {
	t.Helper()
	controller, err := session.NewControllerHandshake(session.ControllerHandshakeConfig{ExpectedIdentity: identity, SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	// A never-used handshake has no public Close; consuming malformed input
	// exercises its normal destroy-on-attempt path without keeping a key copy.
	t.Cleanup(func() { _, _, _ = controller.AcceptGuestHello(nil) })
	if err := frame.Write(fixture.controller, []byte(`{"protocolVersion":"guest-agent-minimal-v1","operation":"readiness"}`), 512); err != nil {
		t.Fatal(err)
	}
	inner, err := frame.Read(fixture.controller, session.MaxHandshakeInnerBytes)
	if err != nil {
		t.Fatalf("minimal GuestHello frame unavailable: %v", err)
	}
	var hello bytes.Buffer
	if err := frame.Write(&hello, inner, session.MaxHandshakeInnerBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := session.ParseGuestHello(hello.Bytes()); err != nil {
		t.Fatalf("current selected adapter has no authenticated minimal GuestHello: %v; response=%q", err, inner)
	}
	return controller, hello.Bytes()
}

func (fixture *minimalREDFixture) handshake(t *testing.T, identity session.Identity, key ed25519.PrivateKey) *session.State {
	t.Helper()
	controller, hello := fixture.controllerHello(t, identity, key)
	state, auth, err := controller.AcceptGuestHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.Revoke)
	minimalREDWrite(t, fixture.controller, auth)
	finished := minimalREDReadRecord(t, fixture.controller)
	if err := state.OpenFinished(finished); err != nil {
		t.Fatalf("guest Finished authentication failed: %v", err)
	}
	finished, err = state.SealFinished()
	if err != nil {
		t.Fatal(err)
	}
	minimalREDWrite(t, fixture.controller, finished)
	if !state.Established() {
		t.Fatal("Finished exchange did not establish the controller session")
	}
	return state
}

func minimalREDBinding(identity session.Identity) map[string]string {
	return map[string]string{
		"sandboxId": "sandbox-1", "executionId": "execution-1", "workerId": "worker-1", "hostId": "host-1",
		"runtimeDriver": "microvm", "runtimeId": identity.RuntimeID, "runtimeGeneration": identity.RuntimeGeneration,
		"processGeneration": identity.FirecrackerProcessGeneration, "vsockGeneration": identity.VsockGeneration,
		"bootGeneration": identity.BootGeneration, "imageGeneration": identity.ImageGeneration,
		"imageDigest": "sha256-" + hex.EncodeToString(identity.ImageSHA256[:]),
		"workerJobId": "job-1", "submissionId": "submission-1", "planId": "plan-1", "jobGeneration": "job-generation-1",
		"admissionGrantId": "admission-1", "admissionRevision": "1", "principalId": "principal-1",
		"templatePolicyId": "template-policy-1", "workspacePolicyId": "workspace-policy-1",
		"networkPlanId": "network-plan-1", "policySnapshotId": "policy-snapshot-1", "proxySessionId": "proxy-session-1",
		"proxyGenerationId": "proxy-generation-1", "topologyGenerationId": "topology-generation-1", "ruleGenerationId": "rule-generation-1",
	}
}

func minimalREDRequest(t *testing.T, state *session.State, binding map[string]string) ([]byte, string) {
	t.Helper()
	// Independent controller oracle, not a replacement production codec. All
	// fields, including intentionally invalid ones, are encoded without local
	// validation so rejection must happen in the actual guest implementation.
	var canonical bytes.Buffer
	canonical.WriteString("hal/guest-agent-minimal-v1/readiness-binding/v1\x00")
	sessionID := state.SessionID()
	canonical.Write(sessionID[:])
	keys := slices.Sorted(maps.Keys(binding))
	_ = binary.Write(&canonical, binary.BigEndian, uint16(len(keys)))
	for _, key := range keys {
		for _, value := range []string{key, binding[key]} {
			_ = binary.Write(&canonical, binary.BigEndian, uint16(len(value)))
			canonical.WriteString(value)
		}
	}
	digestBytes := sha256.Sum256(canonical.Bytes())
	digest := "sha256-" + hex.EncodeToString(digestBytes[:])
	request, err := json.Marshal(map[string]any{
		"protocolVersion": minimalREDProtocol, "operation": "readiness", "requestId": "0102030405060708090a0b0c0d0e0f10",
		"body": map[string]any{"binding": binding, "bindingDigest": digest},
	})
	if err != nil {
		t.Fatal(err)
	}
	return request, digest
}

func minimalREDSeal(t *testing.T, state *session.State, payload []byte) []byte {
	t.Helper()
	wire, err := state.SealApplication(session.FrameTypeControlRequest, payload)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func minimalREDAssertReadiness(t *testing.T, reader io.Reader, state *session.State, digest string) {
	t.Helper()
	payload, err := state.OpenApplication(minimalREDReadRecord(t, reader), func(kind session.FrameType, _ []byte) error {
		if kind != session.FrameTypeControlResponse {
			return session.ErrUnexpectedFrame
		}
		return nil
	})
	if err != nil {
		t.Fatalf("authenticated readiness response failed: %v", err)
	}
	sessionID := state.SessionID()
	want, err := json.Marshal(map[string]any{
		"protocolVersion": minimalREDProtocol, "operation": "readiness", "requestId": "0102030405060708090a0b0c0d0e0f10", "ok": true,
		"body": map[string]any{"bindingDigest": digest, "guestSessionGeneration": base64.RawURLEncoding.EncodeToString(sessionID[:]), "capabilities": []string{"authenticated_minimal_control"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("canonical readiness must correlate the full binding and claim only authenticated minimal control: got %s, want %s", payload, want)
	}
}

func minimalREDReadRecord(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	header := make([]byte, session.SecureRecordHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(header[16:20])
	if size < session.GCMTagBytes || size > 8192+session.GCMTagBytes {
		t.Fatalf("unbounded readiness record length %d", size)
	}
	wire := append(header, make([]byte, int(size))...)
	if _, err := io.ReadFull(reader, wire[len(header):]); err != nil {
		t.Fatal(err)
	}
	return wire
}

func minimalREDWrite(t *testing.T, writer io.Writer, value []byte) {
	t.Helper()
	if n, err := writer.Write(value); err != nil || n != len(value) {
		t.Fatalf("write protocol record: wrote %d/%d, error %v", n, len(value), err)
	}
}

func minimalREDAssertClosed(t *testing.T, reader io.Reader) {
	t.Helper()
	var next [1]byte
	if n, err := reader.Read(next[:]); n != 0 || err == nil {
		t.Fatalf("invalid/replayed/canceled request must close without another response: bytes=%d, error=%v", n, err)
	}
}

type minimalREDPipe struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func (pipe *minimalREDPipe) Read(value []byte) (int, error)  { return pipe.reader.Read(value) }
func (pipe *minimalREDPipe) Write(value []byte) (int, error) { return pipe.writer.Write(value) }
func (pipe *minimalREDPipe) Close() error {
	return errors.Join(pipe.reader.Close(), pipe.writer.Close())
}

type minimalREDListener struct{ connections chan io.ReadWriteCloser }

func (listener *minimalREDListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*minimalREDListener) Close() error { return nil }

type minimalREDBackend struct{ operations atomic.Int32 }

func (backend *minimalREDBackend) Ready(context.Context) error { backend.operations.Add(1); return nil }
func (backend *minimalREDBackend) Exec(context.Context, server.ExecPlan) (server.ExecResult, error) {
	backend.operations.Add(1)
	return server.ExecResult{}, errors.New("unexpected work")
}
func (backend *minimalREDBackend) CopyIn(context.Context, server.CopyInPlan) (server.CopyResult, error) {
	backend.operations.Add(1)
	return server.CopyResult{}, errors.New("unexpected work")
}
func (backend *minimalREDBackend) CopyOut(context.Context, server.CopyOutPlan) (server.CopyResult, error) {
	backend.operations.Add(1)
	return server.CopyResult{}, errors.New("unexpected work")
}
func (*minimalREDBackend) Close(context.Context) error { return nil }
