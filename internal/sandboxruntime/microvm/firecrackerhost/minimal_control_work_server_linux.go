//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/hex"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

type minimalWorkFrame struct {
	header  minimalWorkHeader
	payload []byte
}

// The original serving object owns this pair before its first allocation. It
// derives its only work transport from the original controller's readiness.
type minimalControlWorkServer struct {
	serving    *minimalControlSupervisorServing
	ready      *minimalControlReadiness
	work       guestagent.Transport
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	files      [2]*os.File
	conn       *net.UnixConn
	retired    bool
	cleanupErr error
	started    bool
	active     *minimalWorkFrame
	pending    *minimalWorkFrame
	writing    bool
	ordinal    uint64
	binding    [32]byte
	wake       chan struct{}
	commit     chan struct{}
	reader     chan struct{}
	worker     chan struct{}
	watcher    chan struct{}
}

func (serving *minimalControlSupervisorServing) newWorkServer(ready *minimalControlReadiness) (*minimalControlWorkServer, error) {
	if ready == nil || !ready.Current() || ready.controller != serving.controller {
		return nil, errL8RuntimeOwnerInvalid
	}
	ctx, cancel := context.WithDeadline(serving.owned.minimalPreparation.ctx, ready.hardExpiry)
	s := &minimalControlWorkServer{serving: serving, ready: ready, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), commit: make(chan struct{})}
	serving.mu.Lock()
	if serving.closing || serving.server != nil {
		serving.mu.Unlock()
		cancel()
		return nil, errL8RuntimeOwnerInvalid
	}
	serving.server = s
	serving.mu.Unlock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return s, errL8RuntimeOwnerInvalid
	}
	// Neither a failed conversion nor later cancellation may discard a pair.
	s.files[0] = os.NewFile(uintptr(fds[0]), "minimal-work-supervisor")
	s.files[1] = os.NewFile(uintptr(fds[1]), "minimal-work-producer")
	s.conn, err = minimalWorkEndpointConn(s.files[0])
	if err != nil {
		return s, errL8RuntimeOwnerInvalid
	}
	s.work, err = ready.workloadTransport()
	if err != nil {
		return s, errL8RuntimeOwnerInvalid
	}
	digest, err := ready.binding.Digest(ready.sessionID)
	if err != nil || ctx.Err() != nil || !ready.Current() {
		return s, errL8RuntimeOwnerInvalid
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256-"))
	if err != nil || len(decoded) != len(s.binding) {
		return s, errL8RuntimeOwnerInvalid
	}
	copy(s.binding[:], decoded)
	return s, nil
}

func (s *minimalControlWorkServer) start() {
	s.reader, s.worker, s.watcher = make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.started = true
	go func() {
		defer close(s.reader)
		defer s.retire()
		defer func() { _ = recover() }()
		s.readRequests()
	}()
	go func() {
		defer close(s.worker)
		defer s.retire()
		defer func() { _ = recover() }()
		s.serveRequests()
	}()
	go func() {
		defer close(s.watcher)
		select {
		case <-s.ctx.Done():
		case <-s.ready.controller.Loss():
		}
		s.retire()
	}()
}

// Loss publication never joins a reader, writer, controller or lifecycle task.
func (s *minimalControlWorkServer) retire() {
	s.cancel()
	s.serving.owned.minimalPreparation.revoke()
	s.mu.Lock()
	if !s.retired {
		s.retired = true
		if s.files[0] != nil {
			if unix.Shutdown(int(s.files[0].Fd()), unix.SHUT_RDWR) != nil {
				s.cleanupErr = errL8RuntimeOwnerInvalid
			}
		}
		if s.conn != nil {
			if s.conn.Close() != nil {
				s.cleanupErr = errL8RuntimeOwnerInvalid
			}
		}
	}
	s.mu.Unlock()
}

// Called only by the enclosing controller consume scope, never an I/O task.
func (s *minimalControlWorkServer) close() error {
	s.retire()
	if s.started {
		<-s.reader
		<-s.worker
		<-s.watcher
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		clear(s.pending.payload)
		s.pending = nil
	}
	for index, file := range s.files {
		if file != nil {
			if file.Close() != nil {
				s.cleanupErr = errL8RuntimeOwnerInvalid
			}
			s.files[index] = nil
		}
	}
	return s.cleanupErr
}

func (s *minimalControlWorkServer) readRequests() {
	for {
		var first [1]byte
		if _, err := io.ReadFull(s.conn, first[:]); err != nil {
			return
		}
		s.mu.Lock()
		valid := !s.retired && s.ordinal != math.MaxUint64 && s.pending == nil && (s.active == nil || s.writing)
		ordinal := s.ordinal + 1
		s.mu.Unlock()
		if !valid {
			return // A full pending slot never blocks the sole EOF reader.
		}
		header, payload, err := readMinimalWorkFrame(s.conn, first[0], func(header minimalWorkHeader) bool {
			return header.direction == minimalWorkRequest && header.ordinal == ordinal && header.session == s.ready.sessionID && header.binding == s.binding
		})
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.retired || s.pending != nil {
			s.mu.Unlock()
			clear(payload)
			return
		}
		s.ordinal = ordinal
		s.pending = &minimalWorkFrame{header: header, payload: payload}
		s.mu.Unlock()
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

func (s *minimalControlWorkServer) serveRequests() {
	select {
	case <-s.ctx.Done():
		return
	case <-s.commit: // Post-send publication decision AND observer join.
	}
	for {
		s.mu.Lock()
		if s.retired || !s.serving.owned.minimalPreparation.workCurrent() {
			s.mu.Unlock()
			return
		}
		call := s.pending
		if call != nil {
			s.pending, s.active = nil, call
		}
		s.mu.Unlock()
		if call == nil {
			select {
			case <-s.ctx.Done():
				return
			case <-s.wake:
				continue
			}
		}
		if s.exchange(call) != nil {
			return
		}
	}
}

func (s *minimalControlWorkServer) exchange(call *minimalWorkFrame) error {
	defer clear(call.payload)
	response, err := s.work.RoundTrip(s.ctx, guestagent.TransportRequest{ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation: call.header.operation, Encoded: call.payload, MaxResponseBytes: call.header.maximum})
	defer clear(response.Encoded)
	if err != nil || s.ctx.Err() != nil {
		return errL8RuntimeOwnerInvalid
	}
	s.mu.Lock()
	if s.retired || s.active != call {
		s.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	s.writing = true
	s.mu.Unlock()
	header := call.header
	header.direction = minimalWorkResponse
	err = writeMinimalWorkFrame(s.conn, header, response.Encoded)
	s.mu.Lock()
	s.active, s.writing = nil, false
	s.mu.Unlock()
	return err
}
