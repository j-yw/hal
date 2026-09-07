//go:build linux

package firecrackerhost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// Real ordinary Unix I/O, sealed admission and shared guest cryptography;
// fake process bookkeeping and caller-UID admission are not live Jailer proof.
type minimalControllerFixture struct {
	bridge    l5ProductionBridgeFixture
	transport *minimalControlTransport
	guest     *minimalcontrol.Server
	listener  *minimalControllerGuestListener
	identity  session.Identity
	fields    map[string]string
	cancel    context.CancelFunc
}

type minimalControllerGuestListener struct {
	listener net.Listener
	mu       sync.Mutex
	closed   bool
	pending  net.Conn
	connects atomic.Int32
}

func (l *minimalControllerGuestListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed || ctx.Err() != nil {
		l.mu.Unlock()
		_ = conn.Close()
		return nil, context.Canceled
	}
	// Close also owns a connection still blocked before the guest server gets
	// it. Never strand a fixture in the CONNECT/ACK adapter during RED cleanup.
	l.pending = conn
	l.mu.Unlock()
	reader := bufio.NewReaderSize(conn, maxVsockHandshakeBytes)
	line, err := reader.ReadSlice('\n')
	if err != nil || string(line) != "CONNECT 1025\n" || reader.Buffered() != 0 {
		_ = conn.Close()
		return nil, errors.New("invalid fixture CONNECT")
	}
	if _, err := io.WriteString(conn, "OK 1073741824\n"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	l.mu.Lock()
	l.pending = nil
	closed := l.closed
	l.mu.Unlock()
	if closed {
		_ = conn.Close()
		return nil, context.Canceled
	}
	// The guest server now owns this active connection. Its readiness callback
	// closes only further acceptance, not the authenticated stream.
	l.connects.Add(1)
	return conn, nil
}

func (l *minimalControllerGuestListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	pending := l.pending
	l.mu.Unlock()
	_ = l.listener.Close()
	if pending != nil {
		_ = pending.Close()
	}
	return nil
}

func newMinimalControllerFixture(t *testing.T, admission *minimalControlSupervisorAdmission) *minimalControllerFixture {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("ordinary nonzero-UID strict-owner fixture required")
	}
	f := &minimalControllerFixture{bridge: newL5ProductionBridgeFixture(t, os.Getpid())}
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{RuntimeID: admission.config.Job.RuntimeID, BaseStateDir: filepath.Dir(f.bridge.paths.StateDir)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.bridge.paths = paths
	parent, err := statPrivateFirecrackerStateDir(paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	f.bridge.handle = f.bridge.bridge.lifecycle.storeStrictJailerProcess(f.bridge.process, paths, parent, true, parent.uid)
	f.transport, err = newMinimalControlTransport(f.bridge.bridge.lifecycle, f.bridge.handle, admission.config.Job.RuntimeID)
	if err != nil {
		t.Fatal(err)
	}
	c := admission.config.Control
	public, publicOK := minimalControlConfigBase64(c.ControllerPublicKey)
	nonce, nonceOK := minimalControlConfigBase64(c.BootNonce)
	image, err := hex.DecodeString(admission.config.Rootfs.SHA256)
	if !publicOK || !nonceOK || err != nil || len(image) != 32 {
		t.Fatal("invalid admitted fixture pins")
	}
	f.identity = session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: admission.config.Job.RuntimeID, RuntimeGeneration: admission.config.Job.RuntimeGeneration,
		BootGeneration: c.Prelaunch["bootGeneration"], ImageGeneration: c.Prelaunch["imageGeneration"],
		ControllerKeyGeneration: c.ControllerKeyGeneration, GuestBootNonce: nonce}
	copy(f.identity.ImageSHA256[:], image)
	f.fields = maps.Clone(c.Prelaunch)
	line, err := minimalcontrol.RenderBootCommandLine("", f.identity, public[:], f.fields)
	if err != nil {
		t.Fatal(err)
	}
	boot, present, err := minimalcontrol.ParseBootCommandLine(line)
	if err != nil || !present {
		t.Fatal("shared boot fixture failed")
	}
	f.listener = &minimalControllerGuestListener{listener: l5ListenBridgeSocket(t, paths.VsockSocketPath)}
	// The server closes acceptance at readiness. Keep the original pinned
	// socket inode until task-owned directory cleanup, as Firecracker does.
	f.listener.listener.(*net.UnixListener).SetUnlinkOnClose(false)
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.guest, err = minimalcontrol.NewBootstrap(minimalcontrol.BootstrapOptions{Listener: f.listener, Boot: boot, OwnerDone: ctx.Done(),
		Random: bytes.NewReader(bytes.Repeat([]byte{73}, 96))})
	if err != nil {
		cancel()
		_ = f.listener.Close()
		t.Fatal(err)
	}
	go func() { _ = f.guest.Serve(ctx) }()
	t.Cleanup(func() { f.close(t) })
	return f
}

func (f *minimalControllerFixture) close(t *testing.T) {
	t.Helper()
	f.cancel()
	_ = f.listener.Close()
	select {
	case <-f.guest.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("guest fixture failed to quiesce")
	}
}

func (f *minimalControllerFixture) binding(t *testing.T, generation uint64) (session.Identity, minimalcontrol.Binding) {
	t.Helper()
	identity := f.identity
	identity.FirecrackerProcessGeneration = f.bridge.handle.ID
	identity.VsockGeneration = strconv.FormatUint(generation, 10)
	fields := maps.Clone(f.fields)
	fields["processGeneration"], fields["vsockGeneration"] = identity.FirecrackerProcessGeneration, identity.VsockGeneration
	binding, err := minimalcontrol.NewBinding(identity, fields)
	if err != nil {
		t.Fatal(err)
	}
	return identity, binding
}

// Independently execute the actual fixture before relying on the unavailable
// production consumer RED. This test-only reference transcript is not a second
// production connector/controller and does not assert lifecycle fault coverage.
func TestMinimalControlControllerFixtureCompletesSharedBootstrap(t *testing.T) {
	a := newMinimalControlAdmissionFixture(t)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f := newMinimalControllerFixture(t, admission)
		defer f.close(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d := time.Now().Add(3 * time.Second)
		stream, err := f.transport.OpenWhenAvailable(ctx, d)
		if err != nil {
			t.Fatal("actual retained transport fixture failed", err)
		}
		defer stream.Close()
		handle, generation := stream.Correlation()
		if handle != f.bridge.handle || generation == 0 || stream.SetDeadline(d) != nil {
			t.Fatal("actual stream correlation failed")
		}
		identity, binding := f.binding(t, generation)
		prelude, err := binding.BootstrapPrelude()
		if err != nil || frame.Write(stream, prelude, minimalcontrol.MaxMessageBytes) != nil {
			t.Fatal("shared bootstrap prelude failed")
		}
		defer clear(prelude)
		hello, err := l8D6ReadHandshakeWire(stream)
		if err != nil {
			t.Fatal("real guest Hello failed", err)
		}
		defer clear(hello)
		handshake, err := session.NewControllerHandshake(session.ControllerHandshakeConfig{ExpectedIdentity: identity, SigningKey: admission.controllerKey,
			Dependencies: session.Dependencies{Random: bytes.NewReader(bytes.Repeat([]byte{29}, 32))}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _, _ = handshake.AcceptGuestHello(nil) }()
		state, auth, err := handshake.AcceptGuestHello(hello)
		if err != nil {
			t.Fatal(err)
		}
		defer state.Revoke()
		defer clear(auth)
		if n, err := stream.Write(auth); err != nil || n != len(auth) {
			t.Fatal("ControllerAuth write failed")
		}
		guestFinished, err := l8D6ReadSecureWire(stream)
		defer clear(guestFinished)
		if err != nil || state.OpenFinished(guestFinished) != nil {
			t.Fatal("real guest Finished failed")
		}
		finished, err := state.SealFinished()
		defer clear(finished)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := stream.Write(finished); err != nil || n != len(finished) || !state.Established() {
			t.Fatal("controller Finished failed")
		}
		const requestID = "00112233445566778899aabbccddeeff"
		request, err := binding.EncodeReadinessRequest(requestID, state.SessionID())
		defer clear(request)
		if err != nil || state.WriteApplication(stream, session.FrameTypeControlRequest, request) != nil {
			t.Fatal("readiness request failed")
		}
		wire, err := l8D6ReadSecureWire(stream)
		defer clear(wire)
		if err != nil {
			t.Fatal(err)
		}
		sessionID := state.SessionID()
		plaintext, err := state.OpenApplication(wire, func(kind session.FrameType, payload []byte) error {
			if kind != session.FrameTypeControlResponse {
				return minimalcontrol.ErrInvalid
			}
			return binding.ValidateReadinessResponse(payload, requestID, sessionID)
		})
		clear(plaintext)
		if err != nil || f.listener.connects.Load() != 1 || f.bridge.bridge.session(admission.config.Job.RuntimeID) != nil {
			t.Fatal("real shared readiness transcript failed", err)
		}
		return nil
	})
	if code != 0 || a.admissions != 1 || a.legacy != 0 {
		t.Fatalf("actual fixture prerequisite failed: exit=%d admitted=%d legacy=%d", code, a.admissions, a.legacy)
	}
}

func TestMinimalControlControllerConsumesRetainedTransportAndAdmittedKey(t *testing.T) {
	a := newMinimalControlAdmissionFixture(t)
	entered := false
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f := newMinimalControllerFixture(t, admission)
		defer f.close(t) // unavailable consumer must quiesce the blocked guest
		key := admission.controllerKey
		return withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(controller *minimalControlController) error {
			entered = true
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ready, err := controller.WaitReady(ctx)
			if err != nil || ready == nil || !ready.Current() {
				t.Fatal("selected controller did not authenticate shared bootstrap", err)
			}
			_, expected := f.binding(t, ready.transportGeneration)
			want, err := expected.Digest(ready.sessionID)
			got, gotErr := ready.binding.Digest(ready.sessionID)
			if err != nil || gotErr != nil || got != want || ready.handle != f.bridge.handle || ready.transportGeneration == 0 || f.listener.connects.Load() != 1 || !bytes.Equal(key, make([]byte, ed25519.PrivateKeySize)) {
				t.Fatal("readiness lost exact binding/transport or retained signing key")
			}
			if f.bridge.bridge.session(admission.config.Job.RuntimeID) != nil {
				t.Fatal("minimal authentication created a legacy bridge session")
			}
			if controller.Close() != nil || ready.Current() {
				t.Fatal("joined close left local readiness current")
			}
			return nil
		})
	})
	if code != 0 || !entered {
		t.Fatalf("missing selected controller consumer: exit=%d entered=%v; shared fixture control must pass separately", code, entered)
	}
}

func TestMinimalControlControllerInvalidScopeClearsBorrowedKey(t *testing.T) {
	for _, name := range []string{"nil_context", "canceled", "zero_deadline", "expired_deadline", "beyond_preparation", "nil_transport", "nil_consumer"} {
		t.Run(name, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerFixture(t, admission)
				defer f.close(t)
				ctx := context.Background()
				d := time.Now().Add(3 * time.Second)
				transport := f.transport
				called := false
				consume := func(*minimalControlController) error { called = true; return nil }
				switch name {
				case "nil_context":
					ctx = nil
				case "canceled":
					canceled, cancel := context.WithCancel(ctx)
					cancel()
					ctx = canceled
				case "zero_deadline":
					d = time.Time{}
				case "expired_deadline":
					d = time.Now().Add(-time.Second)
				case "beyond_preparation":
					d = time.Unix(0, admission.config.Control.PreparationDeadlineUnixNano).Add(time.Second)
				case "nil_transport":
					transport = nil
				case "nil_consumer":
					consume = nil
				}
				if err := withMinimalControlController(ctx, transport, admission, d, consume); err == nil || called || f.listener.connects.Load() != 0 || !bytes.Equal(admission.controllerKey, make([]byte, ed25519.PrivateKeySize)) {
					t.Fatal("invalid scope reached transcript or retained borrowed key")
				}
				return nil
			})
			if code != 0 || a.admissions != 1 || a.legacy != 0 {
				t.Fatal("early-rejection fixture did not reach selected byte admission")
			}
		})
	}
}
