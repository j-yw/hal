//go:build linux

package firecrackerhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func minimalTransportFixture(t *testing.T) (l5ProductionBridgeFixture, *minimalControlTransport) {
	t.Helper()
	f := newJailerVsockOwnerFixture(t)
	c, err := newMinimalControlTransport(f.bridge.lifecycle, f.handle, "fc-production-test")
	if err != nil {
		t.Fatal(err)
	}
	c.checks = f.bridge.ownerChecks
	return f, c
}

// Every server owns one ordinary Unix connection and joins it on cleanup. No
// fixture observation is evidence of a real Jailer UID or live VM.
func minimalTransportServer(t *testing.T, f l5ProductionBridgeFixture, serve func(context.Context, net.Conn)) net.Listener {
	t.Helper()
	l := l5ListenBridgeSocket(t, f.paths.VsockSocketPath)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		closed := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(closed) })
		defer func() {
			if !stop() {
				<-closed
			}
		}()
		serve(ctx, conn)
	}()
	t.Cleanup(func() { cancel(); _ = l.Close(); awaitMinimalTransportREDDone(t, done) })
	return l
}

func minimalTransportAck(t *testing.T, conn net.Conn, ack string) bool {
	t.Helper()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	} // a deliberately rejected connection may close
	if line != "CONNECT 1025\n" {
		t.Error("unexpected CONNECT transcript")
		return false
	}
	_, err = io.WriteString(conn, ack)
	return err == nil
}

func minimalTransportReject(t *testing.T, f l5ProductionBridgeFixture, c *minimalControlTransport, ctx context.Context) error {
	t.Helper()
	stream, err := c.Open(ctx)
	if stream != nil {
		_ = stream.Close()
		t.Fatal("rejected transport returned a usable stream")
	}
	if !errors.Is(err, errMinimalControlTransport) || strings.Contains(err.Error(), "sensitive-fixture") {
		t.Fatalf("unsanitized rejection: %v", err)
	}
	if f.bridge.session("fc-production-test") != nil {
		t.Fatal("transport published a legacy session")
	}
	if retry, retryErr := c.Open(context.Background()); retry != nil || retryErr == nil {
		if retry != nil {
			_ = retry.Close()
		}
		t.Fatal("failed connector was reusable")
	}
	return err
}

func TestMinimalHostTransportAdmissionRejectsMissingAuthority(t *testing.T) {
	for _, name := range []string{"legacy", "zero_uid", "missing_parent", "wrong_parent_uid", "missing_strict_flag", "removed", "forgotten", "no_paths", "wrong_paths", "exited", "zero_pid", "nil_done", "wrong_handle", "wrong_source", "spaced_handle", "wrong_runtime", "runtime_expression", "spaced_runtime", "empty_runtime", "nil_context", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalTransportFixture(t)
			l5ListenBridgeSocket(t, f.paths.VsockSocketPath)
			m := f.bridge.lifecycle
			m.mu.Lock()
			r := m.processes[f.handle.ID]
			switch name {
			case "legacy":
				r.hasStrictUID, r.strictRuntimeUID = false, 0
			case "zero_uid":
				r.strictRuntimeUID = 0
			case "missing_parent":
				r.hasStateIdentity = false
			case "wrong_parent_uid":
				r.stateIdentity.uid++
			case "missing_strict_flag":
				r.hasStrictUID = false
			case "removed":
				r.stateRemoved = true
			case "forgotten":
				delete(m.processes, f.handle.ID)
			case "no_paths":
				r.hasPaths = false
			case "wrong_paths":
				r.paths.VsockSocketPath += ".other"
			case "zero_pid":
				r.process = &l5IdentityProcess{pid: 0, done: make(chan struct{})}
			case "nil_done":
				r.process = &l5IdentityProcess{pid: os.Getpid()}
			case "wrong_handle":
				c.handle.ID += "-stale"
			case "wrong_source":
				c.handle.Source += "-stale"
			case "spaced_handle":
				c.handle.ID = " " + c.handle.ID
			case "wrong_runtime":
				c.runtimeID += "-other"
			case "runtime_expression":
				c.runtimeID = "../fc-production-test"
			case "spaced_runtime":
				c.runtimeID = " fc-production-test"
			case "empty_runtime":
				c.runtimeID = ""
			}
			m.mu.Unlock()
			if name == "exited" {
				f.process.stop()
			}
			ctx := context.Background()
			if name == "nil_context" {
				ctx = nil
			}
			if name == "canceled" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			var calls atomic.Int32
			c.dial = func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("sensitive-fixture dial")
			}
			minimalTransportReject(t, f, c, ctx)
			if calls.Load() != 0 {
				t.Fatal("invalid retained authority reached dial")
			}
		})
	}
}

func TestMinimalHostTransportConstructorRejectsNoncanonicalInput(t *testing.T) {
	f, _ := minimalTransportFixture(t)
	for _, name := range []string{"nil_manager", "empty_handle", "wrong_source", "spaced_handle", "spaced_runtime"} {
		t.Run(name, func(t *testing.T) {
			manager, handle, runtime := f.bridge.lifecycle, f.handle, "fc-production-test"
			switch name {
			case "nil_manager":
				manager = nil
			case "empty_handle":
				handle = firecracker.ProcessHandleMetadata{}
			case "wrong_source":
				handle.Source = "another"
			case "spaced_handle":
				handle.ID += " "
			case "spaced_runtime":
				runtime += " "
			}
			if c, err := newMinimalControlTransport(manager, handle, runtime); c != nil || err == nil {
				t.Fatal("constructor accepted invalid input")
			}
		})
	}
}

func TestMinimalHostTransportRejectsSocketAndPeerMismatch(t *testing.T) {
	for _, name := range []string{"socket_uid", "parent_uid", "socket_mode", "parent_mode", "socket_type", "parent_type", "parent_inode", "parent_device", "observe_error", "peer_uid", "peer_pid", "peer_error", "real_owner", "real_peer"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalTransportFixture(t)
			observe, peer := c.checks.observe, c.checks.peer
			c.checks.observe = func(path string) (vsockSocketObservation, error) {
				o, err := observe(path)
				switch name {
				case "socket_uid":
					o.uid++
				case "parent_uid":
					o.parentUID++
				case "socket_mode":
					o.socketMode |= 0o040
				case "parent_mode":
					o.parentMode |= 0o040
				case "socket_type":
					o.socketMode = 0o600
				case "parent_type":
					o.parentMode = os.ModeSymlink | 0o700
				case "parent_inode":
					o.identity.parentInode++
				case "parent_device":
					o.identity.parentDevice++
				case "observe_error":
					err = errors.New("sensitive-fixture observation")
				}
				return o, err
			}
			c.checks.peer = func(conn *net.UnixConn) (vsockPeerIdentity, error) {
				p, err := peer(conn)
				switch name {
				case "peer_uid":
					p.uid++
				case "peer_pid":
					p.pid++
				case "peer_error":
					err = errors.New("sensitive-fixture peer")
				}
				return p, err
			}
			if name == "real_owner" {
				c.checks.observe = nil
			}
			if name == "real_peer" {
				c.checks.peer = nil
			}
			minimalTransportServer(t, f, func(ctx context.Context, conn net.Conn) { minimalTransportAck(t, conn, "OK 1\n"); <-ctx.Done() })
			minimalTransportReject(t, f, c, context.Background())
		})
	}
}

func TestMinimalHostTransportRejectsInvalidACK(t *testing.T) {
	for _, ack := range []string{"", "OK 1", "OK 0\n", "OK 01\n", "OK +1\n", "OK 4294967295\n", "OK 4294967296\n", "OK 1\r\n", "OK 1\nOK 1\n", "OK 1\nextra", "NOT OK 1\n", strings.Repeat("x", 65) + "\n"} {
		t.Run(strings.ReplaceAll(ack, "\n", "_"), func(t *testing.T) {
			f, c := minimalTransportFixture(t)
			minimalTransportServer(t, f, func(_ context.Context, conn net.Conn) { minimalTransportAck(t, conn, ack) })
			before := minimalControlTransportGeneration.Load()
			minimalTransportReject(t, f, c, context.Background())
			if minimalControlTransportGeneration.Load() != before {
				t.Fatal("failed ACK allocated correlation")
			}
		})
	}
}

func TestMinimalHostTransportRejectsAndClosesInvalidDialResults(t *testing.T) {
	for _, name := range []string{"missing", "error", "non_unix", "connection_with_error"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalTransportFixture(t)
			peerClosed := make(chan struct{})
			if name == "connection_with_error" {
				minimalTransportServer(t, f, func(_ context.Context, conn net.Conn) {
					var b [1]byte
					if _, err := conn.Read(b[:]); err == nil {
						t.Error("failed dial result reached CONNECT")
					}
					close(peerClosed)
				})
			} else {
				l5ListenBridgeSocket(t, f.paths.VsockSocketPath)
			}
			var other net.Conn
			c.dial = func(ctx context.Context, network, path string) (net.Conn, error) {
				switch name {
				case "missing":
					return nil, nil
				case "error":
					return nil, errors.New("sensitive-fixture transport failure")
				case "non_unix":
					var raw net.Conn
					raw, other = net.Pipe()
					return raw, nil
				default:
					raw, err := (&net.Dialer{}).DialContext(ctx, network, path)
					if err != nil {
						return nil, err
					}
					return raw, errors.New("sensitive-fixture partial dial")
				}
			}
			minimalTransportReject(t, f, c, context.Background())
			if other != nil {
				defer other.Close()
				_ = other.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				if _, err := other.Read(b[:]); !errors.Is(err, io.EOF) {
					t.Fatal("non-Unix rejected connection was not closed")
				}
			}
			if name == "connection_with_error" {
				awaitMinimalTransportREDDone(t, peerClosed)
			}
		})
	}
}

func TestMinimalHostTransportRejectsChangesAcrossDialAndACK(t *testing.T) {
	for _, phase := range []string{"dial", "ack"} {
		for _, name := range []string{"record", "paths", "pid", "process_channel", "parent", "socket", "cancel"} {
			t.Run(phase+"_"+name, func(t *testing.T) {
				f, c := minimalTransportFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var listener net.Listener
				mutate := func() {
					m := f.bridge.lifecycle
					switch name {
					case "record":
						m.markStateRemoved(f.handle)
					case "paths":
						m.mu.Lock()
						m.processes[f.handle.ID].paths.APISocketPath += ".changed"
						m.mu.Unlock()
					case "pid", "process_channel":
						pid := os.Getpid()
						if name == "pid" {
							pid++
						}
						m.mu.Lock()
						m.processes[f.handle.ID].process = &l5IdentityProcess{pid: pid, done: make(chan struct{})}
						m.mu.Unlock()
					case "parent", "socket":
						listener.(*net.UnixListener).SetUnlinkOnClose(false)
						path := f.paths.VsockSocketPath
						if name == "parent" {
							path = f.paths.StateDir
						}
						if err := os.Rename(path, path+".retained"); err != nil {
							t.Error(err)
							return
						}
						if name == "parent" {
							if err := os.Mkdir(path, 0o700); err != nil {
								t.Error(err)
							}
						}
					case "cancel":
						cancel()
					}
				}
				// At ACK, mutation happens after real CONNECT was received but
				// before the successful ACK is emitted. Dial changes happen on an
				// actually connected socket, not an invented identity.
				listener = minimalTransportServer(t, f, func(serverCtx context.Context, conn net.Conn) {
					line, err := bufio.NewReader(conn).ReadString('\n')
					if err == nil && line == "CONNECT 1025\n" {
						if phase == "ack" {
							mutate()
						}
						_, _ = io.WriteString(conn, "OK 1\n")
					}
					<-serverCtx.Done()
				})
				if phase == "dial" {
					c.dial = func(ctx context.Context, network, path string) (net.Conn, error) {
						conn, err := (&net.Dialer{}).DialContext(ctx, network, path)
						if err == nil {
							mutate()
						}
						return conn, err
					}
				}
				minimalTransportReject(t, f, c, ctx)
			})
		}
	}
}

func TestMinimalHostTransportClosedStreamDoesNotReleaseProcessAuthority(t *testing.T) {
	f, c := minimalTransportFixture(t)
	minimalTransportServer(t, f, func(ctx context.Context, conn net.Conn) { minimalTransportAck(t, conn, "OK 1\n"); <-ctx.Done() })
	s, err := c.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if p, err := f.bridge.lifecycle.resolveLiveProcessIdentity(f.handle); err != nil || p.owner == nil || !p.owner.active() {
		t.Fatal("stream closure released process authority")
	}
	if _, err := os.Lstat(f.paths.VsockSocketPath); err != nil {
		t.Fatal("stream closure removed socket")
	}
	var one [1]byte
	if n, err := s.Read(one[:]); n != 0 || err == nil {
		t.Fatal("closed Read succeeded")
	}
	if n, err := s.Write(one[:]); n != 0 || err == nil {
		t.Fatal("closed Write succeeded")
	}
	if err := s.SetDeadline(time.Time{}); err == nil {
		t.Fatal("closed deadline changed")
	}
}

func TestMinimalHostTransportRechecksBeforeApplicationIO(t *testing.T) {
	for _, operation := range []string{"read", "write", "deadline", "correlation"} {
		t.Run(operation, func(t *testing.T) {
			f, c := minimalTransportFixture(t)
			minimalTransportServer(t, f, func(ctx context.Context, conn net.Conn) { minimalTransportAck(t, conn, "OK 1\n"); <-ctx.Done() })
			s, err := c.Open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			f.bridge.lifecycle.markStateRemoved(f.handle)
			var one [1]byte
			switch operation {
			case "read":
				n, err := s.Read(one[:])
				if n != 0 || err == nil {
					t.Fatal("stale read succeeded")
				}
			case "write":
				n, err := s.Write(one[:])
				if n != 0 || err == nil {
					t.Fatal("stale write succeeded")
				}
			case "deadline":
				if err := s.SetDeadline(time.Time{}); err == nil {
					t.Fatal("stale deadline succeeded")
				}
			case "correlation":
				h, n := s.Correlation()
				if h.ID != "" || n != 0 {
					t.Fatal("stale correlation succeeded")
				}
			}
			awaitMinimalTransportREDDone(t, s.Done())
		})
	}
}

func TestMinimalHostTransportAdmissionCancellationAndLoss(t *testing.T) {
	for _, phase := range []string{"dial", "ack"} {
		for _, cause := range []string{"cancel", "process", "record", "deadline"} {
			t.Run(phase+"_"+cause, func(t *testing.T) {
				f, c := minimalTransportFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				entered := make(chan struct{})
				if cause == "deadline" {
					c.handshakeTimeout = 100 * time.Millisecond
				}
				if phase == "dial" {
					l5ListenBridgeSocket(t, f.paths.VsockSocketPath)
					c.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
						close(entered)
						<-ctx.Done()
						return nil, ctx.Err()
					}
				} else {
					minimalTransportServer(t, f, func(ctx context.Context, conn net.Conn) {
						line, err := bufio.NewReader(conn).ReadString('\n')
						if err == nil && line == "CONNECT 1025\n" {
							close(entered)
						}
						<-ctx.Done()
					})
				}
				result := make(chan error, 1)
				go func() {
					s, err := c.Open(ctx)
					if s != nil {
						_ = s.Close()
						err = errors.New("unexpected usable stream")
					}
					result <- err
				}()
				awaitMinimalTransportREDDone(t, entered)
				switch cause {
				case "cancel":
					cancel()
				case "process":
					f.process.stop()
				case "record":
					f.bridge.lifecycle.markStateRemoved(f.handle)
				}
				select {
				case err := <-result:
					if !errors.Is(err, errMinimalControlTransport) {
						t.Fatalf("Open = %v", err)
					}
					if cause == "cancel" && !errors.Is(err, context.Canceled) {
						t.Fatal("lost cancellation classification")
					}
					if cause == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("lost deadline classification")
					}
				case <-time.After(time.Second):
					cancel()
					<-result
					t.Fatal("pending admission did not stop without watchdog")
				}
			})
		}
	}
}

func TestMinimalHostTransportUsesOneAdmissionDeadline(t *testing.T) {
	f, c := minimalTransportFixture(t)
	c.handshakeTimeout = 300 * time.Millisecond
	var dialDeadline time.Time
	c.dial = func(ctx context.Context, network, path string) (net.Conn, error) {
		dialDeadline, _ = ctx.Deadline()
		timer := time.NewTimer(200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, path)
	}
	minimalTransportServer(t, f, func(ctx context.Context, conn net.Conn) { _, _ = bufio.NewReader(conn).ReadString('\n'); <-ctx.Done() })
	err := minimalTransportReject(t, f, c, context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shared deadline did not fail closed")
	}
	if time.Now().After(dialDeadline.Add(150 * time.Millisecond)) {
		t.Fatal("ACK received a fresh timeout after delayed dial")
	}
}

func TestMinimalHostTransportRetainsCallerDeadlineAndHardExpiry(t *testing.T) {
	for _, name := range []string{"caller", "hard", "application"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalTransportFixture(t)
			ctx := context.Background()
			if name == "caller" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
				defer cancel()
			}
			if name == "hard" {
				c.lifetime = 150 * time.Millisecond
			}
			minimalTransportServer(t, f, func(ctx context.Context, conn net.Conn) { minimalTransportAck(t, conn, "OK 1\n"); <-ctx.Done() })
			s, err := c.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			deadline := time.Now().Add(time.Hour)
			if name == "application" {
				deadline = time.Now().Add(50 * time.Millisecond)
			}
			if err := s.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			pending := make(chan error, 1)
			go func() { var b [1]byte; _, err := s.Read(b[:]); pending <- err }()
			select {
			case err := <-pending:
				if err == nil {
					t.Fatal("expired read succeeded")
				}
			case <-time.After(time.Second):
				_ = s.Close()
				<-pending
				t.Fatal("deadline failed to bound read")
			}
			awaitMinimalTransportREDDone(t, s.Done())
			if handle, generation := s.Correlation(); handle.ID != "" || generation != 0 {
				t.Fatal("expired correlation remained available")
			}
		})
	}
}

func TestMinimalHostTransportOneShotAndFreshCorrelation(t *testing.T) {
	var previous uint64
	for attempt := 0; attempt < 2; attempt++ {
		f, c := minimalTransportFixture(t)
		minimalTransportServer(t, f, func(ctx context.Context, conn net.Conn) { minimalTransportAck(t, conn, "OK 1\n"); <-ctx.Done() })
		var group sync.WaitGroup
		results := make(chan *minimalControlStream, 10)
		for i := 0; i < 10; i++ {
			group.Add(1)
			go func() { defer group.Done(); s, _ := c.Open(context.Background()); results <- s }()
		}
		group.Wait()
		close(results)
		var admitted *minimalControlStream
		for s := range results {
			if s != nil {
				if admitted != nil {
					_ = s.Close()
					t.Fatal("multiple streams admitted")
				}
				admitted = s
			}
		}
		if admitted == nil {
			t.Fatal("no stream admitted")
		}
		handle, generation := admitted.Correlation()
		if handle != f.handle || generation <= previous {
			_ = admitted.Close()
			t.Fatal("correlation not fresh and process-bound")
		}
		previous = generation
		// Configuration copies belong to the admitted stream, not the opener.
		c.handle = firecracker.ProcessHandleMetadata{}
		c.runtimeID = "changed"
		c.checks = vsockOwnerChecks{}
		if got, n := admitted.Correlation(); got != handle || n != generation {
			t.Fatal("opener mutation changed stream binding")
		}
		_ = admitted.Close()
		awaitMinimalTransportREDDone(t, admitted.watchDone)
		if got, n := admitted.Correlation(); got.ID != "" || n != 0 {
			t.Fatal("closed stream retained correlation")
		}
		if f.bridge.session("fc-production-test") != nil {
			t.Fatal("transport availability became readiness")
		}
	}
	var counter atomic.Uint64
	counter.Store(^uint64(0) - 1)
	if nextMinimalControlGeneration(&counter) != ^uint64(0) || nextMinimalControlGeneration(&counter) != 0 || counter.Load() != ^uint64(0) {
		t.Fatal("generation counter wrapped")
	}
}
