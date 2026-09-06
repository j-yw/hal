//go:build linux

package firecrackerhost

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

var errMinimalControlTransport = errors.New("minimal control transport unavailable")
var minimalControlTransportGeneration atomic.Uint64

// This private, one-shot connector accepts retained authority, not reconstructed
// process coordinates. Availability never publishes readiness or cleanup proof.
type minimalControlTransport struct {
	manager                    *ProcessLifecycleManager
	handle                     firecracker.ProcessHandleMetadata
	runtimeID                  string
	claimed                    atomic.Bool
	checks                     vsockOwnerChecks
	dial                       func(context.Context, string, string) (net.Conn, error)
	handshakeTimeout, lifetime time.Duration
}

func newMinimalControlTransport(manager *ProcessLifecycleManager, handle firecracker.ProcessHandleMetadata, runtimeID string) (*minimalControlTransport, error) {
	if manager == nil || normalizeProcessHandleID(handle) != handle.ID || handle.ID == "" || handle.Source != processHandleSource || runtimeID != strings.TrimSpace(runtimeID) {
		return nil, errMinimalControlTransport
	}
	return &minimalControlTransport{manager: manager, handle: handle, runtimeID: runtimeID}, nil
}

type minimalControlStream struct {
	manager         *ProcessLifecycleManager
	process         liveProcessIdentity
	identity        vsockSocketIdentity
	checks          vsockOwnerChecks
	ctx             context.Context
	cancel          context.CancelFunc
	hardDeadline    time.Time
	reader          *bufio.Reader
	done, watchDone chan struct{}
	mu              sync.Mutex
	conn            *net.UnixConn
	closed          bool
	err             error
	generation      uint64
}

func minimalControlBound(value, limit time.Duration) time.Duration {
	if value <= 0 || value > limit {
		return limit
	}
	return value
}

func (c *minimalControlTransport) Open(ctx context.Context) (*minimalControlStream, error) {
	if c == nil || !c.claimed.CompareAndSwap(false, true) || c.manager == nil || ctx == nil || c.runtimeID != strings.TrimSpace(c.runtimeID) {
		return nil, errMinimalControlTransport
	}
	started := time.Now()
	process, err := c.manager.resolveLiveProcessIdentity(c.handle)
	if err != nil || process.handle != c.handle || process.owner == nil || !process.owner.active() || process.pid <= 0 || process.done == nil {
		return nil, errMinimalControlTransport
	}
	// Reuse canonical runtime/path validation without accepting a caller path.
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{RuntimeID: c.runtimeID, BaseStateDir: filepath.Dir(process.paths.StateDir)})
	if err != nil || paths.StateDir != process.paths.StateDir || paths.VsockSocketPath != process.paths.VsockSocketPath {
		return nil, errMinimalControlTransport
	}
	identity, err := statVsockSocketForOwner(process.paths.VsockSocketPath, process.owner, c.checks)
	if err != nil {
		return nil, errMinimalControlTransport
	}
	hard := started.Add(minimalControlBound(c.lifetime, session.MaxGuestCredentialSessionLifetime))
	lifetime, cancel := context.WithDeadline(ctx, hard)
	s := &minimalControlStream{manager: c.manager, process: process, identity: identity, checks: c.checks,
		ctx: lifetime, cancel: cancel, hardDeadline: hard, done: make(chan struct{}), watchDone: make(chan struct{})}
	go s.watch()
	fail := func() (*minimalControlStream, error) { _ = s.Close(); return nil, s.failure() }
	if !s.current() {
		return fail()
	}
	deadline := started.Add(minimalControlBound(c.handshakeTimeout, session.HandshakeDeadline))
	admission, stopAdmission := context.WithDeadline(lifetime, deadline)
	defer stopAdmission()
	dial := c.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	raw, err := dial(admission, "unix", process.paths.VsockSocketPath)
	if err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		s.finish(minimalControlContextError(admission))
		return fail()
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok || conn == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return fail()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return fail()
	}
	s.conn = conn
	s.mu.Unlock()
	if caller, ok := admission.Deadline(); ok {
		deadline = caller
	}
	if !s.current() || conn.SetDeadline(deadline) != nil {
		return fail()
	}
	s.reader = bufio.NewReaderSize(conn, maxVsockHandshakeBytes)
	if writeFull(conn, []byte("CONNECT 1025\n")) != nil {
		s.finish(minimalControlContextError(admission))
		return fail()
	}
	ack, err := s.reader.ReadSlice('\n')
	if err != nil || len(ack) > maxVsockHandshakeBytes || s.reader.Buffered() != 0 || !validVsockAck(string(ack)) {
		s.finish(minimalControlContextError(admission))
		return fail()
	}
	if admission.Err() != nil {
		s.finish(minimalControlContextError(admission))
		return fail()
	}
	if !s.current() || s.SetDeadline(time.Time{}) != nil {
		return fail()
	}
	if !s.current() {
		return fail()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fail()
	}
	// Final ownership observations may consume the remaining admission budget.
	// Recheck elapsed time too: the context timer callback can still be pending.
	// No potentially blocking observation follows this publication boundary.
	if admission.Err() != nil || !time.Now().Before(deadline) {
		s.mu.Unlock()
		s.finish(minimalControlContextError(admission))
		return fail()
	}
	s.generation = nextMinimalControlGeneration(&minimalControlTransportGeneration)
	valid := s.generation != 0
	s.mu.Unlock()
	if !valid {
		return fail()
	}
	return s, nil
}

func nextMinimalControlGeneration(counter *atomic.Uint64) uint64 {
	for {
		previous := counter.Load()
		if previous == ^uint64(0) {
			return 0
		}
		if counter.CompareAndSwap(previous, previous+1) {
			return previous + 1
		}
	}
}

func minimalControlContextError(ctx context.Context) error {
	if ctx.Err() == context.Canceled {
		return errors.Join(errMinimalControlTransport, context.Canceled)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return errors.Join(errMinimalControlTransport, context.DeadlineExceeded)
	}
	// The socket's deadline can fire just before the context timer goroutine.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return errors.Join(errMinimalControlTransport, context.DeadlineExceeded)
	}
	return errMinimalControlTransport
}

// current checks both retained record and filesystem identity; observing another
// valid socket or process is not enough. Calls own no lifetime/background work.
func (s *minimalControlStream) current() bool {
	if s.ctx.Err() != nil {
		s.finish(minimalControlContextError(s.ctx))
		return false
	}
	s.mu.Lock()
	closed, conn := s.closed, s.conn
	s.mu.Unlock()
	if closed {
		return false
	}
	p, err := s.manager.resolveLiveProcessIdentity(s.process.handle)
	if err != nil || p.handle != s.process.handle || p.pid != s.process.pid || p.done != s.process.done || p.paths != s.process.paths || p.owner == nil || !sameVsockProcessOwner(p.owner, s.process.owner) {
		s.finish(errMinimalControlTransport)
		return false
	}
	identity, err := statVsockSocketForOwner(p.paths.VsockSocketPath, p.owner, s.checks)
	if err != nil || identity != s.identity || (conn != nil && verifyVsockPeerForOwner(conn, p.pid, p.owner, s.checks) != nil) {
		s.finish(errMinimalControlTransport)
		return false
	}
	if s.ctx.Err() != nil {
		s.finish(minimalControlContextError(s.ctx))
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed
}

func (s *minimalControlStream) watch() {
	defer close(s.watchDone)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-s.ctx.Done():
			s.finish(minimalControlContextError(s.ctx))
			return
		case <-s.process.done:
			s.finish(errMinimalControlTransport)
			return
		case <-ticker.C:
			if !s.current() {
				return
			}
		}
	}
}

func (s *minimalControlStream) finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed, s.err, s.generation = true, err, 0
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.cancel()
	close(s.done)
}

func (s *minimalControlStream) failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return errMinimalControlTransport
}

func (s *minimalControlStream) Read(b []byte) (int, error) {
	if s == nil {
		return 0, errMinimalControlTransport
	}
	if !s.current() {
		return 0, s.failure()
	}
	n, err := s.reader.Read(b)
	if !s.current() {
		return 0, s.failure()
	}
	if err != nil {
		s.finish(errMinimalControlTransport)
		return n, s.failure()
	}
	return n, nil
}

func (s *minimalControlStream) Write(b []byte) (int, error) {
	if s == nil {
		return 0, errMinimalControlTransport
	}
	if !s.current() {
		return 0, s.failure()
	}
	n, err := s.conn.Write(b)
	if !s.current() {
		return 0, s.failure()
	}
	if err != nil {
		s.finish(errMinimalControlTransport)
		return n, s.failure()
	}
	return n, nil
}

func (s *minimalControlStream) SetDeadline(deadline time.Time) error {
	if s == nil {
		return errMinimalControlTransport
	}
	if !s.current() {
		return s.failure()
	}
	if deadline.IsZero() || s.hardDeadline.Before(deadline) {
		deadline = s.hardDeadline
	}
	if caller, ok := s.ctx.Deadline(); ok && caller.Before(deadline) {
		deadline = caller
	}
	if s.conn.SetDeadline(deadline) != nil {
		s.finish(errMinimalControlTransport)
		return s.failure()
	}
	return nil
}

func (s *minimalControlStream) Done() <-chan struct{} { return s.done }

func (s *minimalControlStream) Close() error {
	if s != nil {
		s.finish(errMinimalControlTransport)
		<-s.watchDone
	}
	return nil
}

// Correlation is transient and non-authoritative. Closed streams retire it.
func (s *minimalControlStream) Correlation() (firecracker.ProcessHandleMetadata, uint64) {
	if s == nil || !s.current() {
		return firecracker.ProcessHandleMetadata{}, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return firecracker.ProcessHandleMetadata{}, 0
	}
	return s.process.handle, s.generation
}
