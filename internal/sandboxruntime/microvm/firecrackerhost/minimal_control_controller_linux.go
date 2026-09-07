//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

var errMinimalControlController = errors.New("minimal control controller unavailable")

// This owns only one authenticated minimal stream. It is not a runtime owner,
// credential grant, original-channel event or proof of resource cleanup.
type minimalControlController struct {
	ctx       context.Context
	cancel    context.CancelFunc
	transport *minimalControlTransport
	readyDone chan struct{}
	loss      chan struct{}
	done      chan struct{}
	mu        sync.Mutex
	stream    *minimalControlStream
	ready     *minimalControlReadiness
	retired   bool
	// Historical local transcript completion, not retained readiness authority.
	authenticated bool
}

type minimalControlReadiness struct {
	binding             minimalcontrol.Binding
	sessionID           [32]byte
	handle              firecracker.ProcessHandleMetadata
	transportGeneration uint64
	controller          *minimalControlController
	self                *minimalControlReadiness
	hardExpiry          time.Time
	admissionDeadline   time.Time
}

type minimalControlControllerPins struct {
	identity session.Identity
	fields   map[string]string
}

// The task and idle reader must finish while admission's key remains borrowed.
// Neither a waiter nor the consume callback can transfer the key or controller
// lifetime out of this scope. Callback panics still close/join and clear the key.
func withMinimalControlController(ctx context.Context, transport *minimalControlTransport, admission *minimalControlSupervisorAdmission, deadline time.Time, consume func(*minimalControlController) error) error {
	if admission != nil {
		defer clear(admission.controllerKey)
	}
	pins, err := minimalControlPins(ctx, transport, admission, deadline)
	if err != nil || consume == nil {
		return errMinimalControlController
	}
	owned, cancel := context.WithCancel(ctx)
	c := &minimalControlController{ctx: owned, cancel: cancel, transport: transport,
		readyDone: make(chan struct{}), loss: make(chan struct{}), done: make(chan struct{})}
	defer c.Close()
	go c.run(pins, admission.controllerKey, deadline)
	if consume(c) != nil {
		return errMinimalControlController
	}
	c.mu.Lock()
	authenticated := c.authenticated
	c.mu.Unlock()
	if authenticated {
		return nil
	}
	return errMinimalControlController
}

func minimalControlPins(ctx context.Context, transport *minimalControlTransport, admission *minimalControlSupervisorAdmission, deadline time.Time) (minimalControlControllerPins, error) {
	var pins minimalControlControllerPins
	if ctx == nil || ctx.Err() != nil || transport == nil || admission == nil || deadline.IsZero() || !time.Now().Before(deadline) ||
		admission.config.Version != minimalControlSupervisorConfigVersion || admission.configDigest == ([32]byte{}) ||
		admission.config.Control.PreparationDeadlineUnixNano <= 0 || deadline.After(time.Unix(0, admission.config.Control.PreparationDeadlineUnixNano)) {
		return pins, errMinimalControlController
	}
	c, j := admission.config.Control, admission.config.Job
	public, publicOK := minimalControlConfigBase64(c.ControllerPublicKey)
	nonce, nonceOK := minimalControlConfigBase64(c.BootNonce)
	image, imageErr := hex.DecodeString(admission.config.Rootfs.SHA256)
	if !publicOK || !nonceOK || imageErr != nil || len(image) != 32 || hex.EncodeToString(image) != admission.config.Rootfs.SHA256 ||
		transport.runtimeID != j.RuntimeID || len(admission.controllerKey) != ed25519.PrivateKeySize {
		return pins, errMinimalControlController
	}
	derived := ed25519.NewKeyFromSeed(admission.controllerKey[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(derived, admission.controllerKey) || !bytes.Equal(derived[ed25519.SeedSize:], public[:]) {
		return pins, errMinimalControlController
	}
	pins.fields = maps.Clone(c.Prelaunch)
	for name, expected := range map[string]string{"sandboxId": j.SandboxID, "executionId": j.ExecutionID, "workerId": j.WorkerID,
		"hostId": j.HostID, "runtimeId": j.RuntimeID, "runtimeGeneration": j.RuntimeGeneration, "imageDigest": "sha256-" + admission.config.Rootfs.SHA256} {
		if pins.fields[name] != expected {
			return minimalControlControllerPins{}, errMinimalControlController
		}
	}
	pins.identity = session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: j.RuntimeID, RuntimeGeneration: j.RuntimeGeneration, BootGeneration: pins.fields["bootGeneration"],
		ImageGeneration: pins.fields["imageGeneration"], ControllerKeyGeneration: c.ControllerKeyGeneration, GuestBootNonce: nonce}
	copy(pins.identity.ImageSHA256[:], image)
	// Pure validation only: this cannot attest the actual sealed FC/NIC bytes.
	if _, err := minimalcontrol.RenderBootCommandLine("", pins.identity, public[:], pins.fields); err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return minimalControlControllerPins{}, errMinimalControlController
	}
	return pins, nil
}

func (c *minimalControlController) WaitReady(ctx context.Context) (*minimalControlReadiness, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, errMinimalControlController
	}
	select {
	case <-ctx.Done():
		return nil, errMinimalControlController
	case <-c.loss:
		return nil, errMinimalControlController
	case <-c.readyDone:
	}
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if !ready.Current() || ctx.Err() != nil {
		return nil, errMinimalControlController
	}
	return ready, nil
}

func (c *minimalControlController) Loss() <-chan struct{} { return c.loss }

// Called by both the task and idle reader: revoke the local latch, but never
// join here. In particular an idle read must not wait for itself.
func (c *minimalControlController) retire() {
	c.mu.Lock()
	if !c.retired {
		c.retired = true
		c.ready = nil
		close(c.loss)
	}
	c.mu.Unlock()
	c.cancel()
}

func (c *minimalControlController) Close() error {
	if c == nil {
		return nil
	}
	c.retire()
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()
	// WriteApplication holds State.mu across I/O. Close first, outside our
	// mutex, then join the task; only that task may revoke its session state.
	if stream != nil {
		_ = stream.Close()
	}
	<-c.done
	return nil
}

func (r *minimalControlReadiness) Current() bool {
	if r == nil || r.self != r || r.controller == nil {
		return false
	}
	c := r.controller
	c.mu.Lock()
	current := !c.retired && c.ready == r && c.ctx.Err() == nil && time.Now().Before(r.hardExpiry)
	stream := c.stream
	c.mu.Unlock()
	if !current || stream == nil {
		return false
	}
	handle, generation := stream.Correlation()
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.retired && c.ready == r && c.ctx.Err() == nil && time.Now().Before(r.hardExpiry) &&
		handle == r.handle && generation != 0 && generation == r.transportGeneration
}

func (c *minimalControlController) run(pins minimalControlControllerPins, key ed25519.PrivateKey, deadline time.Time) {
	var stream *minimalControlStream
	var state *session.State
	var idleDone chan struct{}
	defer func() {
		_ = recover() // No panic payload or partially completed readiness escapes.
		c.retire()
		if stream != nil {
			_ = stream.Close()
		}
		if idleDone != nil {
			<-idleDone
		}
		if state != nil {
			state.Revoke()
		}
		clear(key)
		close(c.done)
	}()
	var err error
	stream, err = c.transport.OpenWhenAvailable(c.ctx, deadline)
	if err != nil || stream == nil {
		return
	}
	c.mu.Lock()
	retired := c.retired
	if !retired {
		c.stream = stream
	}
	c.mu.Unlock()
	if retired {
		return
	}
	var ready *minimalControlReadiness
	var admissionDeadline time.Time
	state, ready, admissionDeadline, err = c.authenticate(stream, pins, key, deadline, &state)
	if err != nil {
		return
	}
	hard := earlierMinimalControlTime(stream.hardDeadline, state.HardExpiry())
	if ownedDeadline, ok := c.ctx.Deadline(); ok {
		hard = earlierMinimalControlTime(hard, ownedDeadline)
	}
	if stream.SetDeadline(hard) != nil {
		return
	}
	idleDone = make(chan struct{})
	armed := make(chan struct{})
	go func() {
		defer close(idleDone)
		defer c.retire()
		var unexpected [1]byte
		defer clear(unexpected[:])
		close(armed)
		_, _ = stream.Read(unexpected[:]) // Any byte, EOF or error retires readiness.
	}()
	<-armed
	if !c.admissionCurrent(stream, admissionDeadline, ready.handle, ready.transportGeneration) || !time.Now().Before(hard) {
		return
	}
	ready.controller, ready.self, ready.hardExpiry = c, ready, hard
	ready.admissionDeadline = admissionDeadline
	c.mu.Lock()
	published := !c.retired && c.ctx.Err() == nil && time.Now().Before(admissionDeadline) && time.Now().Before(hard)
	if published {
		c.ready, c.authenticated = ready, true
		close(c.readyDone)
	}
	c.mu.Unlock()
	if !published {
		return
	}
	select {
	case <-c.ctx.Done():
	case <-stream.Done():
	case <-idleDone:
	}
}

func (c *minimalControlController) admissionCurrent(stream *minimalControlStream, deadline time.Time, handle firecracker.ProcessHandleMetadata, generation uint64) bool {
	if c.ctx.Err() != nil || !time.Now().Before(deadline) {
		return false
	}
	actual, current := stream.Correlation()
	return c.ctx.Err() == nil && time.Now().Before(deadline) && generation != 0 && actual == handle && current == generation
}
