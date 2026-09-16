package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
)

func TestMinimalBootstrapActualAdapterRejectsV1BeforeEntropyOrBackend(t *testing.T) {
	listener := &bootstrapEntryListener{}
	for range 3 {
		var framed bytes.Buffer
		if err := frame.Write(&framed, []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness"}`), 8192); err != nil {
			t.Fatal(err)
		}
		listener.streams = append(listener.streams, &bootstrapEntryStream{Reader: bytes.NewReader(framed.Bytes())})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	constructors := 0
	err := runMinimalCommandWithTestListener(t, ctx, minimalBootstrapREDBootLine(), func() (vsock.Listener, error) { constructors++; return listener, nil })
	if !errors.Is(err, session.ErrPreAuthExhausted) || constructors != 1 || listener.accepted != 3 || listener.closed.Load() != 1 {
		t.Fatalf("actual selected server: error=%v constructors=%d accepts=%d closes=%d", err, constructors, listener.accepted, listener.closed.Load())
	}
	for _, stream := range listener.streams {
		if stream.writes != 0 || stream.closed != 1 {
			t.Fatal("v1 received output or retained selected connection")
		}
	}
}

func TestMinimalBootstrapActualAdapterValidationAndConstructionFailures(t *testing.T) {
	for _, line := range []string{"", "console=ttyS0", "hal_minimal_profile=guest-agent-v1", minimalBootstrapREDBootLine() + " hal_minimal_unknown=x"} {
		called := false
		err := runMinimalCommandWithTestListener(t, context.Background(), line, func() (vsock.Listener, error) { called = true; return nil, nil })
		if err != minimalcontrol.ErrInvalid || called {
			t.Fatal("invalid/absent selected adapter input constructed listener")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := runMinimalCommandWithTestListener(t, ctx, minimalBootstrapREDBootLine(), func() (vsock.Listener, error) { called = true; return nil, nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal("canceled adapter constructed listener")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := runMinimalCommandWithTestListener(t, ctx, minimalBootstrapREDBootLine(), func() (vsock.Listener, error) { return nil, errors.New("private listener canary") }); err != minimalcontrol.ErrUnavailable {
		t.Fatal("listener failure was not sanitized")
	}
	if err := runMinimalCommandWithTestListener(t, ctx, minimalBootstrapREDBootLine(), func() (vsock.Listener, error) { return nil, nil }); err != minimalcontrol.ErrInvalid {
		t.Fatal("missing listener accepted")
	}
	listener := &bootstrapEntryListener{}
	// A context with no owner-loss channel cannot establish boot ownership.
	if err := runMinimalCommandWithTestListener(t, context.Background(), minimalBootstrapREDBootLine(), func() (vsock.Listener, error) { return listener, nil }); err != minimalcontrol.ErrInvalid || listener.closed.Load() != 1 {
		t.Fatal("failed server construction retained listener")
	}
}

// Selected setup now requires L7/backend/proof construction. The old v1
// rejection and ownership assertions still run through the actual command.
func runMinimalCommandWithTestListener(t *testing.T, ctx context.Context, line string, listen func() (vsock.Listener, error)) error {
	t.Helper()
	backend := &minimalCommandBackend{}
	proof := &minimalCommandVerifier{}
	err := runMinimalGuestAgentWithDependencies(ctx, line+" "+minimalCommandL7Line, minimalCommandDependencies(t, backend, proof, listen))
	if backend.readyCalls.Load() != 0 || backend.execCalls.Load() != 0 || proof.calls.Load() != 0 || backend.closeCalls.Load() != backend.constructors.Load() {
		t.Error("unauthenticated selected fixture inspected, executed, or leaked a constructed backend")
	}
	return err
}

func TestMinimalBootstrapEntryValidatesReadCancellationAndDependencies(t *testing.T) {
	for _, when := range []string{"before-read", "during-read", "nil-context", "nil-reader", "nil-legacy", "nil-minimal"} {
		t.Run(when, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads, constructors := 0, 0
			dependencies := guestAgentEntryDependencies{
				readBootCommandLine: func(context.Context) (string, error) {
					reads++
					if when == "during-read" {
						cancel()
					}
					return minimalBootstrapREDBootLine(), nil
				},
				runLegacy: func() error { constructors++; return nil }, runMinimal: func(context.Context, string) error { constructors++; return nil },
			}
			switch when {
			case "before-read":
				cancel()
			case "nil-context":
				ctx = nil
			case "nil-reader":
				dependencies.readBootCommandLine = nil
			case "nil-legacy":
				dependencies.runLegacy = nil
			case "nil-minimal":
				dependencies.runMinimal = nil
			}
			err := runGuestAgentEntry(ctx, dependencies)
			if err == nil || constructors != 0 || when != "during-read" && reads != 0 {
				t.Fatal("invalid entrypoint crossed construction boundary")
			}
		})
	}
}

type bootstrapEntryListener struct {
	streams  []*bootstrapEntryStream
	accepted int
	closed   atomic.Int32
}

func (listener *bootstrapEntryListener) Accept(context.Context) (io.ReadWriteCloser, error) {
	if listener.accepted >= len(listener.streams) {
		return nil, io.EOF
	}
	stream := listener.streams[listener.accepted]
	listener.accepted++
	return stream, nil
}
func (listener *bootstrapEntryListener) Close() error { listener.closed.Add(1); return nil }

type bootstrapEntryStream struct {
	*bytes.Reader
	writes, closed int
}

func (stream *bootstrapEntryStream) Write(value []byte) (int, error) {
	stream.writes++
	return len(value), nil
}
func (stream *bootstrapEntryStream) Close() error { stream.closed++; return nil }
