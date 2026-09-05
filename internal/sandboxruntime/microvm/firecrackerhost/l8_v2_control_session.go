package firecrackerhost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	guestsession "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

const (
	l8V2ControlCompatibilityPayload = `{"protocolVersion":"guest-agent-v2","operation":"readiness"}`
	l8V2ControlLegacyUnsupported    = `{"protocolVersion":"guest-agent-v1","operation":"readiness","error":{"code":"unsupported_protocol_version","operation":"readiness","field":"protocolVersion","message":"guest agent protocol version is unsupported"}}`
	l8V2ControlValuePlaceholder     = "[firecracker-l8-v2-control]"
	l8V2ControlCompatibilityLimit   = 512
)

var (
	ErrL8V2ControlUnavailable   = errors.New("Firecracker L8 v2 control session unavailable")
	ErrL8V2ControlInvalid       = errors.New("Firecracker L8 v2 control session invalid")
	ErrL8V2ControlUnsupported   = errors.New("Firecracker L8 v2 control protocol unsupported")
	ErrL8V2ControlSerialization = errors.New("Firecracker L8 v2 control serialization denied")
)

type l8V2ControlConnector interface {
	OpenL8V2Control(context.Context, sandboxruntime.Target) (l8V2ControlStream, error)
}

type l8V2ControlStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
	ProcessDone() <-chan struct{}
}

// ProductionL8V2ControlBridge is an explicit, one-shot, process-local owner
// for the authenticated port-1025 readiness session. It is not a credential
// lifecycle runtime and is never constructed by default paths.
type ProductionL8V2ControlBridge struct {
	mu            sync.Mutex
	connector     l8V2ControlConnector
	seed          sandboxruntime.JobCredentialIdentitySeed
	signing       ed25519.PrivateKey
	bootNonce     [32]byte
	random        io.Reader
	now           func() time.Time
	attemptCancel context.CancelFunc
	attemptDone   chan struct{}
	inFlight      *l8V2ControlInFlight
	attempted     bool
	closed        bool
	closeDone     chan struct{}
	active        *L8V2ControlReadinessSession
	closeErr      error
}

type l8V2ControlInFlight struct {
	stream    l8V2ControlStream
	closing   bool
	closeOnce sync.Once
	closeErr  error
}

// L8V2ControlReadiness exposes only the two authenticated safe generations
// learned from canonical readiness.
type L8V2ControlReadiness struct {
	guestSessionGeneration string
	guestHelperGeneration  string
}

// L8V2ControlReadinessSession owns the authenticated stream until one
// terminal close. It deliberately exposes no application send/receive API.
type L8V2ControlReadinessSession struct {
	mu        sync.Mutex
	readiness L8V2ControlReadiness
	state     *guestsession.State
	stream    l8V2ControlStream
	done      chan struct{}
	stopWatch chan struct{}
	watchDone chan struct{}
	closeOnce sync.Once
	closeErr  error
	onClose   func(*L8V2ControlReadinessSession, error)
}

// NewProductionL8V2ControlBridge constructs the explicit production
// connector over one retained Firecracker VSOCK bridge and one exact seed.
func NewProductionL8V2ControlBridge(
	vsock *ProductionVsockBridge,
	seed sandboxruntime.JobCredentialIdentitySeed,
	signingKey ed25519.PrivateKey,
	bootNonce [32]byte,
) (*ProductionL8V2ControlBridge, error) {
	if vsock == nil || vsock.lifecycle == nil {
		return nil, ErrL8V2ControlInvalid
	}
	return newProductionL8V2ControlBridgeWithDependencies(
		&productionL8V2ControlConnector{bridge: vsock},
		seed,
		signingKey,
		bootNonce,
		rand.Reader,
		time.Now,
	)
}

func newProductionL8V2ControlBridgeWithDependencies(
	connector l8V2ControlConnector,
	seed sandboxruntime.JobCredentialIdentitySeed,
	signingKey ed25519.PrivateKey,
	bootNonce [32]byte,
	random io.Reader,
	now func() time.Time,
) (*ProductionL8V2ControlBridge, error) {
	cloned, err := sandboxruntime.CloneJobCredentialIdentitySeed(seed)
	if err != nil || l8V2ControlValueIsNil(connector) || l8V2ControlValueIsNil(random) || now == nil ||
		len(signingKey) != ed25519.PrivateKeySize || bootNonce == ([32]byte{}) {
		return nil, ErrL8V2ControlInvalid
	}
	return &ProductionL8V2ControlBridge{
		connector:   connector,
		seed:        cloned,
		signing:     append(ed25519.PrivateKey(nil), signingKey...),
		bootNonce:   bootNonce,
		random:      random,
		now:         now,
		attemptDone: make(chan struct{}),
	}, nil
}

// OpenReadiness consumes the one-shot bridge and returns only after the exact
// compatibility, handshake, Finished, and canonical readiness exchange.
func (bridge *ProductionL8V2ControlBridge) OpenReadiness(
	ctx context.Context,
	target sandboxruntime.Target,
) (*L8V2ControlReadinessSession, error) {
	if bridge == nil || l8V2ControlValueIsNil(ctx) || !bridge.targetMatchesSeed(target) {
		return nil, ErrL8V2ControlInvalid
	}

	bridge.mu.Lock()
	if bridge.closed || bridge.attempted || l8V2ControlValueIsNil(bridge.connector) ||
		len(bridge.signing) != ed25519.PrivateKeySize || bridge.bootNonce == ([32]byte{}) ||
		l8V2ControlValueIsNil(bridge.random) || bridge.now == nil {
		bridge.mu.Unlock()
		return nil, ErrL8V2ControlInvalid
	}
	bridge.attempted = true
	attemptCtx, attemptCancel := context.WithCancel(ctx)
	bridge.attemptCancel = attemptCancel
	attemptDone := bridge.attemptDone
	connector := bridge.connector
	seed, seedErr := sandboxruntime.CloneJobCredentialIdentitySeed(bridge.seed)
	signing := append(ed25519.PrivateKey(nil), bridge.signing...)
	nonce := bridge.bootNonce
	randomSource := bridge.random
	now := bridge.now
	bridge.mu.Unlock()
	defer close(attemptDone)
	if seedErr != nil {
		bridge.finishAttempt(nil, nil)
		zeroL8V2ControlBytes(signing)
		return nil, ErrL8V2ControlInvalid
	}

	stream, openErr := callL8V2ControlConnector(connector, attemptCtx, target)
	if bridge.attemptIsClosed() {
		if !l8V2ControlValueIsNil(stream) {
			_ = closeL8V2ControlStream(stream)
		}
		bridge.finishAttempt(nil, nil)
		zeroL8V2ControlBytes(signing)
		return nil, ErrL8V2ControlUnavailable
	}
	if openErr != nil || l8V2ControlValueIsNil(stream) {
		if !l8V2ControlValueIsNil(stream) {
			_ = closeL8V2ControlStream(stream)
		}
		resultErr := ErrL8V2ControlInvalid
		if openErr != nil {
			resultErr = ErrL8V2ControlUnavailable
		}
		bridge.finishAttempt(nil, nil)
		zeroL8V2ControlBytes(signing)
		return nil, resultErr
	}
	inFlight, admitted := bridge.admitInFlight(stream)
	if !admitted {
		_ = closeL8V2ControlStream(stream)
		bridge.finishAttempt(nil, nil)
		zeroL8V2ControlBytes(signing)
		return nil, ErrL8V2ControlUnavailable
	}
	stopCancellation := context.AfterFunc(attemptCtx, func() {
		_ = bridge.closeInFlight(inFlight)
	})
	defer stopCancellation()
	processDone, doneErr := callL8V2ControlProcessDone(stream)
	if doneErr != nil || processDone == nil {
		_ = bridge.closeInFlight(inFlight)
		bridge.finishAttempt(inFlight, nil)
		zeroL8V2ControlBytes(signing)
		return nil, ErrL8V2ControlInvalid
	}
	select {
	case <-processDone:
		_ = bridge.closeInFlight(inFlight)
		bridge.finishAttempt(inFlight, nil)
		zeroL8V2ControlBytes(signing)
		return nil, ErrL8V2ControlUnavailable
	default:
	}

	readiness, state, readinessErr := callL8V2ControlReadiness(attemptCtx, stream, seed, signing, nonce, randomSource, now)
	zeroL8V2ControlBytes(signing)
	if readinessErr != nil || state == nil {
		_ = bridge.closeInFlight(inFlight)
		resultErr := sanitizeL8V2ControlError(readinessErr)
		bridge.finishAttempt(inFlight, nil)
		return nil, resultErr
	}
	select {
	case <-processDone:
		state.Revoke()
		_ = bridge.closeInFlight(inFlight)
		bridge.finishAttempt(inFlight, nil)
		return nil, ErrL8V2ControlUnavailable
	default:
	}

	owned := &L8V2ControlReadinessSession{
		readiness: readiness,
		state:     state,
		stream:    stream,
		done:      make(chan struct{}),
		stopWatch: make(chan struct{}),
		watchDone: make(chan struct{}),
	}
	owned.onClose = bridge.sessionClosed
	if !bridge.finishAttempt(inFlight, owned) {
		state.Revoke()
		owned.state = nil
		owned.stream = nil
		return nil, ErrL8V2ControlUnavailable
	}
	go owned.watchProcess(processDone)
	return owned, nil
}

func (bridge *ProductionL8V2ControlBridge) targetMatchesSeed(target sandboxruntime.Target) bool {
	if bridge == nil {
		return false
	}
	bridge.mu.Lock()
	seed, err := sandboxruntime.CloneJobCredentialIdentitySeed(bridge.seed)
	bridge.mu.Unlock()
	return err == nil && target.Provider == firecracker.BackendID && target.ID == seed.RuntimeID &&
		target.Runtime.Driver == sandboxruntime.DriverMicroVM && target.Runtime.RuntimeID == seed.RuntimeID
}

func (bridge *ProductionL8V2ControlBridge) attemptIsClosed() bool {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	return bridge.closed
}

func (bridge *ProductionL8V2ControlBridge) admitInFlight(stream l8V2ControlStream) (*l8V2ControlInFlight, bool) {
	inFlight := &l8V2ControlInFlight{stream: stream}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.inFlight != nil {
		return nil, false
	}
	bridge.inFlight = inFlight
	return inFlight, true
}

func (bridge *ProductionL8V2ControlBridge) closeInFlight(inFlight *l8V2ControlInFlight) error {
	if bridge == nil || inFlight == nil {
		return nil
	}
	bridge.mu.Lock()
	if bridge.inFlight != inFlight {
		bridge.mu.Unlock()
		return nil
	}
	inFlight.closing = true
	bridge.mu.Unlock()
	return inFlight.close()
}

func (inFlight *l8V2ControlInFlight) close() error {
	if inFlight == nil {
		return nil
	}
	inFlight.closeOnce.Do(func() {
		inFlight.closeErr = closeL8V2ControlStream(inFlight.stream)
	})
	return inFlight.closeErr
}

func (bridge *ProductionL8V2ControlBridge) finishAttempt(
	inFlight *l8V2ControlInFlight,
	session *L8V2ControlReadinessSession,
) bool {
	bridge.mu.Lock()
	cancel := bridge.attemptCancel
	bridge.attemptCancel = nil
	zeroL8V2ControlBytes(bridge.signing)
	bridge.signing = nil
	bridge.bootNonce = [32]byte{}
	bridge.random = nil
	bridge.connector = nil
	published := !bridge.closed && session != nil && inFlight != nil &&
		bridge.inFlight == inFlight && !inFlight.closing
	if published {
		bridge.active = session
	}
	if inFlight != nil && bridge.inFlight == inFlight {
		bridge.inFlight = nil
	}
	bridge.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return published
}

func (bridge *ProductionL8V2ControlBridge) sessionClosed(session *L8V2ControlReadinessSession, err error) {
	if bridge == nil {
		return
	}
	bridge.mu.Lock()
	if bridge.active == session {
		bridge.active = nil
	}
	if err != nil && bridge.closeErr == nil {
		bridge.closeErr = sanitizeL8V2ControlError(err)
	}
	bridge.mu.Unlock()
}

// Close terminally releases the active process-local session. It does not
// assert guest resource cleanup or any wider runtime state.
func (bridge *ProductionL8V2ControlBridge) Close() error {
	if bridge == nil {
		return nil
	}
	bridge.mu.Lock()
	if bridge.closed {
		done := bridge.closeDone
		bridge.mu.Unlock()
		if done != nil {
			<-done
		}
		bridge.mu.Lock()
		latched := bridge.closeErr
		bridge.mu.Unlock()
		return latched
	}
	bridge.closed = true
	if bridge.closeDone == nil {
		bridge.closeDone = make(chan struct{})
	}
	closeDone := bridge.closeDone
	active := bridge.active
	inFlight := bridge.inFlight
	if inFlight != nil {
		inFlight.closing = true
	}
	attemptDone := bridge.attemptDone
	cancel := bridge.attemptCancel
	bridge.attemptCancel = nil
	zeroL8V2ControlBytes(bridge.signing)
	bridge.signing = nil
	bridge.bootNonce = [32]byte{}
	bridge.random = nil
	bridge.connector = nil
	latched := bridge.closeErr
	bridge.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if inFlight != nil {
		inFlightCloseErr := inFlight.close()
		if inFlightCloseErr != nil && latched == nil {
			latched = sanitizeL8V2ControlError(inFlightCloseErr)
		}
		if inFlightCloseErr == nil && attemptDone != nil {
			<-attemptDone
		}
	}
	if active != nil {
		if err := active.Close(); err != nil && latched == nil {
			latched = sanitizeL8V2ControlError(err)
		}
	}
	bridge.mu.Lock()
	if bridge.closeErr == nil && latched != nil {
		bridge.closeErr = latched
	}
	latched = bridge.closeErr
	close(closeDone)
	bridge.mu.Unlock()
	return latched
}

// Readiness returns a copy of the safe authenticated readiness generations.
func (session *L8V2ControlReadinessSession) Readiness() L8V2ControlReadiness {
	if session == nil {
		return L8V2ControlReadiness{}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.readiness
}

// Done closes exactly once when explicit close, bridge close, or process loss
// terminalizes this owner.
func (session *L8V2ControlReadinessSession) Done() <-chan struct{} {
	if session == nil {
		return nil
	}
	return session.done
}

// Close is terminal and idempotent. It owns only the controller stream and
// session key state, never a resource-absence acknowledgement.
func (session *L8V2ControlReadinessSession) Close() error {
	if session == nil {
		return nil
	}
	session.terminalize()
	if session.watchDone != nil {
		<-session.watchDone
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.closeErr
}

func (session *L8V2ControlReadinessSession) terminalize() {
	session.closeOnce.Do(func() {
		if session.stopWatch != nil {
			close(session.stopWatch)
		}
		if session.state != nil {
			session.state.Revoke()
		}
		err := closeL8V2ControlStream(session.stream)
		session.mu.Lock()
		session.state = nil
		session.stream = nil
		session.readiness = L8V2ControlReadiness{}
		if err != nil {
			session.closeErr = ErrL8V2ControlUnavailable
		}
		latched := session.closeErr
		session.mu.Unlock()
		if session.done != nil {
			close(session.done)
		}
		if session.onClose != nil {
			session.onClose(session, latched)
		}
	})
}

func (session *L8V2ControlReadinessSession) watchProcess(processDone <-chan struct{}) {
	defer close(session.watchDone)
	select {
	case <-processDone:
		session.terminalize()
	case <-session.stopWatch:
	}
}

func (readiness L8V2ControlReadiness) GuestSessionGeneration() string {
	return readiness.guestSessionGeneration
}

func (readiness L8V2ControlReadiness) GuestHelperGeneration() string {
	return readiness.guestHelperGeneration
}

func (*ProductionL8V2ControlBridge) String() string { return l8V2ControlValuePlaceholder }
func (*L8V2ControlReadinessSession) String() string { return l8V2ControlValuePlaceholder }
func (L8V2ControlReadiness) String() string         { return l8V2ControlValuePlaceholder }
func (*ProductionL8V2ControlBridge) MarshalJSON() ([]byte, error) {
	return nil, ErrL8V2ControlSerialization
}
func (*L8V2ControlReadinessSession) MarshalJSON() ([]byte, error) {
	return nil, ErrL8V2ControlSerialization
}
func (L8V2ControlReadiness) MarshalJSON() ([]byte, error) {
	return nil, ErrL8V2ControlSerialization
}
func (bridge *ProductionL8V2ControlBridge) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8V2ControlValuePlaceholder)
}
func (session *L8V2ControlReadinessSession) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8V2ControlValuePlaceholder)
}
func (L8V2ControlReadiness) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8V2ControlValuePlaceholder)
}

func callL8V2ControlConnector(
	connector l8V2ControlConnector,
	ctx context.Context,
	target sandboxruntime.Target,
) (stream l8V2ControlStream, err error) {
	defer func() {
		if recover() != nil {
			stream = nil
			err = ErrL8V2ControlUnavailable
		}
	}()
	return connector.OpenL8V2Control(ctx, target)
}

func callL8V2ControlProcessDone(stream l8V2ControlStream) (done <-chan struct{}, err error) {
	defer func() {
		if recover() != nil {
			done = nil
			err = ErrL8V2ControlInvalid
		}
	}()
	return stream.ProcessDone(), nil
}

func callL8V2ControlReadiness(
	ctx context.Context,
	stream l8V2ControlStream,
	seed sandboxruntime.JobCredentialIdentitySeed,
	signing ed25519.PrivateKey,
	nonce [32]byte,
	randomSource io.Reader,
	now func() time.Time,
) (readiness L8V2ControlReadiness, state *guestsession.State, err error) {
	defer func() {
		if recover() != nil {
			readiness = L8V2ControlReadiness{}
			if state != nil {
				state.Revoke()
			}
			state = nil
			err = ErrL8V2ControlUnavailable
		}
	}()
	return performL8V2ControlReadiness(ctx, stream, seed, signing, nonce, randomSource, now)
}

func performL8V2ControlReadiness(
	ctx context.Context,
	stream l8V2ControlStream,
	seed sandboxruntime.JobCredentialIdentitySeed,
	signing ed25519.PrivateKey,
	nonce [32]byte,
	randomSource io.Reader,
	now func() time.Time,
) (readiness L8V2ControlReadiness, state *guestsession.State, err error) {
	defer func() {
		if recover() != nil {
			readiness = L8V2ControlReadiness{}
			if state != nil {
				state.Revoke()
			}
			state = nil
			err = ErrL8V2ControlUnavailable
		}
	}()
	if ctx.Err() != nil {
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlUnavailable
	}
	identity, err := l8V2ControlExpectedIdentity(seed, nonce)
	if err != nil {
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	handshake, err := guestsession.NewControllerHandshake(guestsession.ControllerHandshakeConfig{
		ExpectedIdentity: identity,
		SigningKey:       signing,
		Dependencies:     guestsession.Dependencies{Random: randomSource, Now: now},
	})
	if err != nil {
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	deadline := handshake.Deadline()
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if stream.SetDeadline(deadline) != nil {
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlUnavailable
	}
	if err := frame.Write(stream, []byte(l8V2ControlCompatibilityPayload), l8V2ControlCompatibilityLimit); err != nil {
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlUnavailable
	}
	hello, err := readL8V2ControlHandshake(stream)
	if err != nil {
		return L8V2ControlReadiness{}, nil, err
	}
	state, controllerAuth, err := handshake.AcceptGuestHello(hello)
	guestsession.DestroyBytes(hello)
	if err != nil || state == nil {
		guestsession.DestroyBytes(controllerAuth)
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	if err := writeL8V2ControlBytes(stream, controllerAuth); err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlUnavailable
	}
	guestFinished, err := readL8V2ControlRecord(stream)
	if err != nil || state.OpenFinished(guestFinished) != nil {
		guestsession.DestroyBytes(guestFinished)
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	guestsession.DestroyBytes(guestFinished)
	controllerFinished, err := state.SealFinished()
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	if err := writeL8V2ControlBytes(stream, controllerFinished); err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlUnavailable
	}
	var requestIDBytes [16]byte
	if _, err := io.ReadFull(randomSource, requestIDBytes[:]); err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlUnavailable
	}
	requestID, err := v2control.NewRequestID(requestIDBytes)
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	request, err := v2control.NewReadinessRequest(requestID, v2control.NewIdentityDigest(state.SessionID()))
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	payload, err := v2control.EncodeReadinessRequest(request)
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	requestWire, err := state.SealApplication(guestsession.FrameTypeControlRequest, payload)
	guestsession.DestroyBytes(payload)
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	if err := writeL8V2ControlBytes(stream, requestWire); err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlUnavailable
	}
	responseWire, err := readL8V2ControlRecord(stream)
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, err
	}
	header, err := guestsession.ParseRecordHeader(responseWire, guestsession.ChannelControl)
	if err != nil || header.Type != guestsession.FrameTypeControlResponse {
		guestsession.DestroyBytes(responseWire)
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	responsePayload, err := state.OpenApplication(responseWire, nil)
	guestsession.DestroyBytes(responseWire)
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	response, err := v2control.DecodeReadinessSuccessResponse(request, responsePayload)
	guestsession.DestroyBytes(responsePayload)
	if err != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	readiness = L8V2ControlReadiness{
		guestSessionGeneration: response.GuestSessionGeneration(),
		guestHelperGeneration:  response.HelperGeneration(),
	}
	if readiness.guestSessionGeneration == "" || readiness.guestHelperGeneration == "" || stream.SetDeadline(time.Time{}) != nil {
		state.Revoke()
		return L8V2ControlReadiness{}, nil, ErrL8V2ControlInvalid
	}
	return readiness, state, nil
}

func l8V2ControlExpectedIdentity(seed sandboxruntime.JobCredentialIdentitySeed, nonce [32]byte) (guestsession.Identity, error) {
	if sandboxruntime.ValidateJobCredentialIdentitySeed(seed) != nil || nonce == ([32]byte{}) || !strings.HasPrefix(seed.GuestImageDigest, "sha256-") {
		return guestsession.Identity{}, ErrL8V2ControlInvalid
	}
	image, err := hex.DecodeString(strings.TrimPrefix(seed.GuestImageDigest, "sha256-"))
	if err != nil || len(image) != 32 {
		return guestsession.Identity{}, ErrL8V2ControlInvalid
	}
	identity := guestsession.Identity{
		Channel:                      guestsession.ChannelControl,
		GuestBootNonce:               nonce,
		GuestCID:                     guestsession.GuestCID,
		GuestPort:                    guestsession.ControlPort,
		ControllerKeyGeneration:      seed.ControllerKeyGeneration,
		RuntimeID:                    seed.RuntimeID,
		RuntimeGeneration:            seed.RuntimeGeneration,
		FirecrackerProcessGeneration: seed.FirecrackerProcessGeneration,
		VsockGeneration:              seed.VsockGeneration,
		BootGeneration:               seed.GuestBootGeneration,
		ImageGeneration:              seed.GuestImageGeneration,
	}
	copy(identity.ImageSHA256[:], image)
	zeroL8V2ControlBytes(image)
	return identity, nil
}

func readL8V2ControlHandshake(reader io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, ErrL8V2ControlUnavailable
	}
	length, err := guestsession.ParseHandshakeLength(prefix[:])
	if err != nil {
		return nil, ErrL8V2ControlInvalid
	}
	wire := make([]byte, 4+int(length))
	copy(wire, prefix[:])
	if _, err := io.ReadFull(reader, wire[4:]); err != nil {
		guestsession.DestroyBytes(wire)
		return nil, ErrL8V2ControlUnavailable
	}
	inner := wire[4:]
	if len(inner) > 0 && inner[0] == '{' {
		legacy := string(inner) == l8V2ControlLegacyUnsupported
		guestsession.DestroyBytes(wire)
		if legacy {
			return nil, ErrL8V2ControlUnsupported
		}
		return nil, ErrL8V2ControlInvalid
	}
	return wire, nil
}

func readL8V2ControlRecord(reader io.Reader) ([]byte, error) {
	prefix := make([]byte, guestsession.SecureRecordHeaderBytes)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, ErrL8V2ControlUnavailable
	}
	header, err := guestsession.ParseRecordHeaderPrefix(prefix, guestsession.ChannelControl)
	if err != nil {
		guestsession.DestroyBytes(prefix)
		return nil, ErrL8V2ControlInvalid
	}
	wire := make([]byte, len(prefix)+int(header.CiphertextLength))
	copy(wire, prefix)
	guestsession.DestroyBytes(prefix)
	if _, err := io.ReadFull(reader, wire[guestsession.SecureRecordHeaderBytes:]); err != nil {
		guestsession.DestroyBytes(wire)
		return nil, ErrL8V2ControlUnavailable
	}
	return wire, nil
}

func writeL8V2ControlBytes(writer io.Writer, payload []byte) error {
	defer guestsession.DestroyBytes(payload)
	if err := writeFull(writer, payload); err != nil {
		return ErrL8V2ControlUnavailable
	}
	return nil
}

func closeL8V2ControlStream(stream l8V2ControlStream) (err error) {
	if l8V2ControlValueIsNil(stream) {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = ErrL8V2ControlUnavailable
		} else if err != nil {
			err = ErrL8V2ControlUnavailable
		}
	}()
	return stream.Close()
}

func sanitizeL8V2ControlError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrL8V2ControlUnsupported):
		return ErrL8V2ControlUnsupported
	case errors.Is(err, ErrL8V2ControlInvalid):
		return ErrL8V2ControlInvalid
	default:
		return ErrL8V2ControlUnavailable
	}
}

func l8V2ControlValueIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func zeroL8V2ControlBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
