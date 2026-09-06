package minimalcontrol

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

var (
	ErrUnavailable = errors.New("minimal control connection is unavailable")
	ErrOwnerLost   = errors.New("minimal control owner is unavailable")
	ErrTimeout     = errors.New("minimal control deadline expired")
	ErrUsed        = errors.New("minimal control server was already used")
)

// Listener must unblock Accept on context cancellation or Close. Returned
// streams must unblock Read and Write when closed. Implementations own their
// unaccepted backlog. The package never creates an OS listener or process.
type Listener interface {
	Accept(context.Context) (io.ReadWriteCloser, error)
	Close() error
}

// Clock keeps protocol time and cancellation timers on the same clock.
// AfterFunc/Stop have time.AfterFunc/time.Timer semantics. Dependencies are
// trusted injected implementations; Random must be bounded and nonblocking.
type Clock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) Timer
}
type Timer interface{ Stop() bool }

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }
func (wallClock) AfterFunc(delay time.Duration, fire func()) Timer {
	return time.AfterFunc(delay, fire)
}

type Options struct {
	Listener                  Listener
	Identity                  session.Identity
	Binding                   map[string]string
	PinnedControllerPublicKey ed25519.PublicKey
	OwnerDone                 <-chan struct{}
	Clock                     Clock
	Random                    io.Reader
}

// Server owns one boot's bounded attempts and at most one claimed session.
// Done means this injected server stopped, not that host resources are absent.
type Server struct {
	options Options
	binding Binding
	used    atomic.Bool
	done    chan struct{}
}

func New(options Options) (*Server, error) {
	if nilDependency(options.Listener) || options.OwnerDone == nil || len(options.PinnedControllerPublicKey) != ed25519.PublicKeySize ||
		options.Clock != nil && nilDependency(options.Clock) || options.Random != nil && nilDependency(options.Random) {
		return nil, ErrInvalid
	}
	binding, err := NewBinding(options.Identity, options.Binding)
	if err != nil {
		return nil, ErrInvalid
	}
	options.Binding = nil
	options.PinnedControllerPublicKey = append(ed25519.PublicKey(nil), options.PinnedControllerPublicKey...)
	if options.Clock == nil {
		options.Clock = wallClock{}
	}
	return &Server{options: options, binding: binding, done: make(chan struct{})}, nil
}

func (server *Server) Done() <-chan struct{} { return server.done }

func (server *Server) Serve(parent context.Context) (result error) {
	if server == nil || !server.used.CompareAndSwap(false, true) {
		return ErrUsed
	}
	defer close(server.done)
	if parent == nil {
		_ = server.options.Listener.Close()
		return ErrInvalid
	}
	ctx, cancel := context.WithCancelCause(parent)
	var mu sync.Mutex
	var current *ownedStream
	var closeListener sync.Once
	closeAccept := func() { closeListener.Do(func() { _ = server.options.Listener.Close() }) }
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-server.options.OwnerDone:
			cancel(ErrOwnerLost)
		case <-ctx.Done():
		}
		<-ctx.Done()
		closeAccept()
		mu.Lock()
		active := current
		mu.Unlock()
		if active != nil {
			_ = active.Close()
		}
	}()
	defer func() { cancel(result); <-watchDone }()
	bootTimer := server.options.Clock.AfterFunc(session.MaxPreAuthConnections*session.HandshakeDeadline, func() { cancel(ErrTimeout) })
	defer bootTimer.Stop()
	gate, _ := session.NewGenerationGate(server.options.Identity.BootGeneration, session.GateHooks{})
	defer gate.Lose(session.LossReasonEOF)
	for range session.MaxPreAuthConnections {
		if cause := terminationCause(ctx); cause != nil {
			return cause
		}
		select {
		case <-server.options.OwnerDone:
			return ErrOwnerLost
		default:
		}
		raw, err := server.options.Listener.Accept(ctx)
		if err != nil {
			if !nilDependency(raw) {
				_ = raw.Close()
			}
			if terminationCause(ctx) != nil {
				return terminationCause(ctx)
			}
			return ErrUnavailable
		}
		if nilDependency(raw) {
			return ErrInvalid
		}
		stream := &ownedStream{ReadWriteCloser: raw}
		mu.Lock()
		current = stream
		canceled := ctx.Err() != nil
		mu.Unlock()
		if canceled {
			_ = stream.Close()
			return terminationCause(ctx)
		}
		attempt, err := gate.Begin()
		if err != nil {
			_ = stream.Close()
			return err
		}
		claimed, err := server.connection(ctx, stream, attempt, func() {
			bootTimer.Stop()
			closeAccept()
		})
		attempt.Fail()
		_ = stream.Close()
		mu.Lock()
		current = nil
		mu.Unlock()
		if terminationCause(ctx) != nil {
			return terminationCause(ctx)
		}
		if claimed {
			return err
		}
	}
	return session.ErrPreAuthExhausted
}

func (server *Server) connection(parent context.Context, stream *ownedStream, attempt *session.Attempt, ready func()) (claimed bool, result error) {
	ctx, cancel := context.WithCancelCause(parent)
	closed := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() { _ = stream.Close(); close(closed) })
	defer func() {
		if cause := terminationCause(ctx); cause != nil {
			result = cause
		}
		cancel(result)
		if stopWatch() {
			_ = stream.Close()
		} else {
			<-closed
		}
	}()
	clock := server.options.Clock
	deadline := clock.Now().Add(session.HandshakeDeadline)
	timer := clock.AfterFunc(session.HandshakeDeadline, func() { cancel(ErrTimeout) })
	defer timer.Stop()
	handshake, hello, err := session.NewGuestHandshake(session.GuestHandshakeConfig{
		Identity: server.options.Identity, PinnedControllerPublicKey: server.options.PinnedControllerPublicKey,
		Dependencies: session.Dependencies{Random: server.options.Random, Now: clock.Now},
	})
	if err != nil {
		return false, ErrUnavailable
	}
	defer func() { _, _ = handshake.AcceptControllerAuth(nil) }()
	start, err := frame.Read(stream, 512)
	if err != nil || string(start) != prelude || writeAll(stream, hello) != nil {
		return false, ErrInvalid
	}
	auth, err := readHandshake(stream)
	if err != nil {
		return false, ErrInvalid
	}
	state, err := handshake.AcceptControllerAuth(auth)
	session.DestroyBytes(auth)
	if err != nil {
		return false, ErrInvalid
	}
	defer state.Revoke()
	finished, err := state.SealFinished()
	if err != nil || writeAll(stream, finished) != nil {
		return false, ErrInvalid
	}
	peerFinished, err := readRecord(stream)
	if err != nil || state.OpenFinished(peerFinished) != nil || attempt.Authenticate(state) != nil {
		return false, ErrInvalid
	}
	claimed = true
	wire, err := readRecord(stream)
	if err != nil {
		return true, ErrInvalid
	}
	var request readinessRequest
	sessionID := state.SessionID()
	plaintext, err := state.OpenApplication(wire, func(kind session.FrameType, payload []byte) error {
		if kind != session.FrameTypeControlRequest {
			return ErrInvalid
		}
		var decodeErr error
		request, decodeErr = server.binding.decodeReadiness(payload, sessionID)
		return decodeErr
	})
	session.DestroyBytes(plaintext)
	if err != nil || ctx.Err() != nil || !clock.Now().Before(deadline) {
		return true, ErrInvalid
	}
	response, err := encodeReadiness(request, state.SessionID())
	if err != nil || state.WriteApplication(stream, session.FrameTypeControlResponse, response) != nil || !timer.Stop() || ctx.Err() != nil || !clock.Now().Before(deadline) {
		return true, ErrInvalid
	}
	ready()
	hardTimer := clock.AfterFunc(state.HardExpiry().Sub(clock.Now()), func() { cancel(ErrTimeout) })
	defer hardTimer.Stop()
	// No second readiness, exec or credential operation exists in this slice.
	// Still authenticate the next record so replay is rejected by session itself.
	wire, err = readRecord(stream)
	if err == nil {
		_, _ = state.OpenApplication(wire, func(session.FrameType, []byte) error { return ErrInvalid })
	}
	return true, ErrUnavailable
}

type ownedStream struct {
	io.ReadWriteCloser
	once sync.Once
}

func (stream *ownedStream) Close() error {
	stream.once.Do(func() { _ = stream.ReadWriteCloser.Close() })
	return nil
}

func writeAll(writer io.Writer, value []byte) error {
	n, err := writer.Write(value)
	if err != nil || n != len(value) {
		return ErrUnavailable
	}
	return nil
}

func readHandshake(reader io.Reader) ([]byte, error) {
	inner, err := frame.Read(reader, session.MaxHandshakeInnerBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	wire := make([]byte, 4+len(inner))
	// Handshake outer framing is the same four-byte length prefix as frame.
	wire[0], wire[1], wire[2], wire[3] = byte(len(inner)>>24), byte(len(inner)>>16), byte(len(inner)>>8), byte(len(inner))
	copy(wire[4:], inner)
	return wire, nil
}

func readRecord(reader io.Reader) ([]byte, error) {
	header := make([]byte, session.SecureRecordHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, ErrUnavailable
	}
	parsed, err := session.ParseRecordHeaderPrefix(header, session.ChannelControl)
	if err != nil || parsed.CiphertextLength > MaxMessageBytes+session.GCMTagBytes {
		return nil, ErrInvalid
	}
	wire := append(header, make([]byte, int(parsed.CiphertextLength))...)
	if _, err := io.ReadFull(reader, wire[len(header):]); err != nil {
		return nil, ErrUnavailable
	}
	return wire, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}

func terminationCause(ctx context.Context) error {
	switch cause := context.Cause(ctx); cause {
	case nil, ErrOwnerLost, ErrTimeout:
		return cause
	default:
		return ctx.Err()
	}
}
