package minimalcontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

type workloadReadFunc func([]byte) (int, error)

func (read workloadReadFunc) Read(value []byte) (int, error) { return read(value) }

func TestWorkloadTransportPartialReadOwnership(t *testing.T) {
	for _, boundary := range []string{"header-error", "header-panic", "body-error", "body-panic", "complete"} {
		t.Run(boundary, func(t *testing.T) {
			var aliases [][]byte
			calls := 0
			read := workloadReadFunc(func(value []byte) (int, error) {
				calls++
				aliases = append(aliases, value)
				if calls == 1 {
					if len(value) != session.SecureRecordHeaderBytes {
						t.Fatal("reader did not bound header first")
					}
					copy(value, "HL8F")
					value[4], value[5] = session.WireVersion, byte(session.FrameTypeControlRequest)
					binary.BigEndian.PutUint32(value[16:20], 20)
					if boundary == "header-error" {
						return 3, io.ErrUnexpectedEOF
					}
					if boundary == "header-panic" {
						panic("private-reader-panic")
					}
					return len(value), nil
				}
				if calls != 2 || len(value) != 20 {
					t.Fatal("body was not bounded by exact parsed header")
				}
				copy(value, "private-body-canary")
				if boundary == "body-error" {
					return 7, io.ErrUnexpectedEOF
				}
				if boundary == "body-panic" {
					panic("private-reader-panic")
				}
				return len(value), nil
			})
			var result []byte
			var err error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				result, err = readWorkloadRecord(read)
			}()
			if panicked {
				t.Error("reader panic escaped selected transport boundary")
			}
			if boundary == "complete" {
				if err != nil || len(result) != session.SecureRecordHeaderBytes+20 || !bytes.Contains(result, []byte("private-body-canary")) {
					t.Fatal("successful read did not transfer exact record ownership")
				}
				clear(result)
			} else if result != nil || err != ErrUnavailable {
				t.Errorf("partial read did not return only fixed unavailable error: %v", err)
			}
			for _, alias := range aliases {
				if !bytes.Equal(alias, make([]byte, len(alias))) {
					t.Error("owned partial/header scratch survived return")
				}
			}
		})
	}
}

type workloadPanicStream struct {
	*testPipe
	enabled atomic.Bool
	body    bool
	alias   []byte
}

func (stream *workloadPanicStream) Read(value []byte) (int, error) {
	n, err := stream.testPipe.Read(value)
	if stream.enabled.Load() && (len(value) != session.SecureRecordHeaderBytes) == stream.body {
		stream.alias = value
		panic("private-reader-panic")
	}
	return n, err
}

func TestWorkloadTransportReaderPanicCancelsAndJoinsActualExec(t *testing.T) {
	for _, body := range []bool{false, true} {
		entered, canceled := make(chan struct{}), make(chan struct{})
		backend := &workloadTransportBackend{exec: func(ctx context.Context, _ server.ExecPlan) (server.ExecResult, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			return server.ExecResult{}, ctx.Err()
		}}
		fixture := newWorkloadTransportFixture(t, backend)
		guestRead, controllerWrite := io.Pipe()
		controllerRead, guestWrite := io.Pipe()
		guest := &testPipe{reader: guestRead, writer: guestWrite, readStarted: make(chan struct{}, 16), writeStarted: make(chan struct{}, 16), closed: make(chan struct{})}
		stream := &workloadPanicStream{testPipe: guest, body: body}
		peer := &testPipe{reader: controllerRead, writer: controllerWrite, other: guest}
		fixture.peers = append(fixture.peers, peer)
		fixture.listener.connections <- stream
		await(t, guest.readStarted, "selected stream first read")
		state := fixture.authenticate(t, peer, true)
		defer state.Revoke()
		fixture.readiness(t, peer, state, fixture.binding)
		write(t, peer, workloadRecord(t, fixture, state, workloadInnerExec(t), 1))
		await(t, entered, "actual exec before reader fault")
		stream.enabled.Store(true)
		wire := workloadRecord(t, fixture, state, workloadInnerExec(t), 2)
		if !body {
			wire = wire[:2]
		}
		write(t, peer, wire)
		await(t, canceled, "reader panic canceled backend before test rescue")
		err := fixture.wait(t)
		if err == nil || bytes.Contains([]byte(err.Error()), []byte("private-reader-panic")) {
			t.Fatal("reader panic escaped safe failure")
		}
		if len(stream.alias) == 0 || !bytes.Equal(stream.alias, make([]byte, len(stream.alias))) || backend.calls.Load() != 1 {
			t.Fatal("reader retained partial bytes or launched pending work")
		}
	}
}
