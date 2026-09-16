package minimalcontrol

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// NewWorkloadTransport explicitly selects authenticated work on the original
// bootstrap connection. The enclosing server owns backend/proof admission.
func NewWorkloadTransport(options BootstrapOptions) (server.Transport, error) {
	bootstrap, err := NewBootstrap(options)
	if err != nil {
		return nil, err
	}
	return &workloadTransport{bootstrap: bootstrap}, nil
}

type workloadTransport struct{ bootstrap *Server }

func (transport *workloadTransport) Serve(ctx context.Context, limits server.Limits, handler server.Handler) error {
	selected, _ := handler.(server.WorkloadHandler)
	if transport == nil || transport.bootstrap == nil {
		return ErrInvalid
	}
	limits.MaxRequestBytes = min(limits.MaxRequestBytes, MaxWorkloadPayloadBytes)
	limits.MaxResponseBytes = min(limits.MaxResponseBytes, MaxWorkloadPayloadBytes)
	return transport.bootstrap.serve(ctx, &workloadConnection{handler: selected, limits: limits})
}

type workloadConnection struct {
	handler server.WorkloadHandler
	limits  server.Limits
}

func (workload *workloadConnection) valid() bool {
	return !nilDependency(workload.handler) && workload.limits.MaxRequestBytes > 0 && workload.limits.MaxResponseBytes > 0
}

type workloadPending struct {
	inner   []byte
	ordinal uint64
}

type workloadPhase uint8

const (
	workloadWorking workloadPhase = iota
	workloadWriting
	workloadIdle
)

// serve is the sole reader. At most one task owns preparation/work and output.
// Reader failure cancels that task and closes I/O before joining it. No session
// mutex is held across handler calls, transport I/O, cancellation, or joins.
func (workload *workloadConnection) serve(parent context.Context, stream *ownedStream, state *session.State, binding Binding,
	request readinessRequest, clock Clock, deadline time.Time, timer Timer, ready func()) (result error) {
	ctx, cancel := context.WithCancelCause(parent)
	var tasks sync.WaitGroup
	var mu sync.Mutex
	phase := workloadWorking
	var pending *workloadPending
	var taskErr error
	stop := func(err error) {
		mu.Lock()
		if taskErr == nil {
			taskErr = err
		}
		mu.Unlock()
		cancel(err)
		_ = stream.Close()
	}
	defer func() {
		cancel(result)
		_ = stream.Close()
		tasks.Wait()
		if pending != nil {
			clear(pending.inner)
		}
	}()
	sessionID := state.SessionID()
	hardExpiry := state.HardExpiry()
	hardTimer := clock.AfterFunc(hardExpiry.Sub(clock.Now()), func() { stop(ErrTimeout) })
	defer hardTimer.Stop()
	write := func(payload []byte) error {
		defer clear(payload)
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		wire, err := state.SealApplication(session.FrameTypeControlResponse, payload)
		if err != nil {
			return ErrInvalid
		}
		defer clear(wire)
		mu.Lock()
		phase = workloadWriting
		mu.Unlock()
		return writeAll(stream, wire)
	}
	handle := func(request *workloadPending) error {
		defer clear(request.inner)
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if !clock.Now().Before(hardExpiry) {
			return ErrTimeout
		}
		response := workload.handler.HandleWorkload(ctx, server.Request{Encoded: request.inner})
		defer clear(response.Encoded)
		if len(response.Encoded) == 0 || int64(len(response.Encoded)) > workload.limits.MaxResponseBytes {
			return ErrInvalid
		}
		payload, err := binding.EncodeWorkload(response.Encoded, request.ordinal, sessionID)
		if err != nil {
			return ErrInvalid
		}
		return write(payload)
	}
	start := func(run func() error) {
		tasks.Add(1)
		go func() {
			defer tasks.Done()
			defer func() {
				if recover() != nil {
					stop(ErrUnavailable)
				}
			}()
			for {
				if err := run(); err != nil {
					stop(err)
					return
				}
				mu.Lock()
				next := pending
				pending = nil
				if next == nil {
					phase = workloadIdle
				} else {
					phase = workloadWorking
				}
				mu.Unlock()
				if next == nil {
					return
				}
				// The preceding writer has returned. No second handler or writer
				// runs concurrently; the reader remains available for EOF/loss.
				run = func() error { return handle(next) }
			}
		}()
	}
	start(func() error {
		if ctx.Err() != nil || !clock.Now().Before(deadline) {
			return ErrTimeout
		}
		if err := workload.handler.PrepareWorkload(ctx); err != nil || ctx.Err() != nil || !clock.Now().Before(deadline) {
			return ErrUnavailable
		}
		response, err := encodeReadiness(request, sessionID)
		if err != nil {
			return ErrInvalid
		}
		if err := write(response); err != nil {
			return err
		}
		if !timer.Stop() || ctx.Err() != nil || !clock.Now().Before(deadline) {
			return ErrTimeout
		}
		ready()
		return nil
	})
	for ordinal := uint64(1); ordinal != 0; ordinal++ {
		wire, err := readWorkloadRecord(stream)
		if err != nil {
			mu.Lock()
			failure := taskErr
			mu.Unlock()
			if failure != nil {
				return failure
			}
			if cause := terminationCause(parent); cause != nil {
				return cause
			}
			return err
		}
		mu.Lock()
		occupied := phase == workloadWorking || pending != nil
		mu.Unlock()
		if occupied || ctx.Err() != nil {
			clear(wire)
			return ErrInvalid
		}
		var inner []byte
		plaintext, err := state.OpenApplication(wire, func(kind session.FrameType, payload []byte) error {
			var decodeErr error
			inner, decodeErr = binding.DecodeWorkloadRequest(kind, payload, ordinal, sessionID)
			if decodeErr == nil && int64(len(inner)) > workload.limits.MaxRequestBytes {
				clear(inner)
				inner = nil
				return ErrInvalid
			}
			return decodeErr
		})
		clear(wire)
		clear(plaintext)
		if err != nil {
			clear(inner)
			return ErrInvalid
		}
		next := &workloadPending{inner: inner, ordinal: ordinal}
		mu.Lock()
		writing := phase == workloadWriting
		if writing {
			pending = next
		} else {
			phase = workloadWorking
		}
		mu.Unlock()
		if !writing {
			start(func() error { return handle(next) })
		}
	}
	return ErrInvalid
}

func readWorkloadRecord(reader io.Reader) ([]byte, error) {
	var header [session.SecureRecordHeaderBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrUnavailable
	}
	parsed, err := session.ParseRecordHeaderPrefix(header[:], session.ChannelControl)
	if err != nil || parsed.CiphertextLength > MaxWorkloadMessageBytes+session.GCMTagBytes {
		return nil, ErrInvalid
	}
	wire := make([]byte, len(header)+int(parsed.CiphertextLength))
	copy(wire, header[:])
	if _, err := io.ReadFull(reader, wire[len(header):]); err != nil {
		clear(wire)
		return nil, ErrUnavailable
	}
	return wire, nil
}
