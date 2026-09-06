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
)

// Real caller-owned directories/sockets, but a fake strict process record.
// In particular this fixture does not prove privileged Jailer admission.
func minimalStartupFixture(t *testing.T) (l5ProductionBridgeFixture, *minimalControlTransport) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("ordinary nonzero-UID socket fixture required")
	}
	f := newL5ProductionBridgeFixture(t, os.Getpid())
	parent, err := statPrivateFirecrackerStateDir(f.paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	f.handle = f.bridge.lifecycle.storeStrictJailerProcess(f.process, f.paths, parent, true, parent.uid)
	c, err := newMinimalControlTransport(f.bridge.lifecycle, f.handle, "fc-production-test")
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

type minimalStartupServer struct {
	connects atomic.Int32
	active   atomic.Int32
	done     chan struct{}
}

// The server can remain unbound until start is closed. Each sequential handler
// observes the complete real CONNECT. All fixture listeners/I/O are joined.
func serveMinimalStartup(t *testing.T, f l5ProductionBridgeFixture, start <-chan struct{}, handle func(int, net.Conn, *bufio.Reader)) *minimalStartupServer {
	t.Helper()
	s := &minimalStartupServer{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var listener net.Listener
	var active net.Conn
	go func() {
		defer close(s.done)
		select {
		case <-start:
		case <-ctx.Done():
			return
		}
		l, err := net.Listen("unix", f.paths.VsockSocketPath)
		if err != nil {
			t.Error("fixture listener failed", err)
			return
		}
		l.(*net.UnixListener).SetUnlinkOnClose(false)
		defer l.Close()
		if err := os.Chmod(f.paths.VsockSocketPath, 0o600); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		listener = l
		stopped := ctx.Err() != nil
		mu.Unlock()
		if stopped {
			return
		}
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active = conn
			stopped = ctx.Err() != nil
			mu.Unlock()
			if stopped {
				_ = conn.Close()
				return
			}
			s.active.Add(1)
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			reader := bufio.NewReader(conn)
			line, err := reader.ReadString('\n')
			if err == nil {
				if line != "CONNECT 1025\n" {
					t.Error("unexpected startup CONNECT transcript")
				} else {
					handle(int(s.connects.Add(1)), conn, reader)
				}
			}
			_ = conn.Close()
			s.active.Add(-1)
			mu.Lock()
			active = nil
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		cancel()
		mu.Lock()
		if active != nil {
			_ = active.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		mu.Unlock()
		awaitMinimalTransportREDDone(t, s.done)
	})
	return s
}

func minimalStartupReady(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	if _, err := io.WriteString(conn, "OK 1073741824\n"); err != nil {
		return
	}
	var payload [4]byte
	if _, err := io.ReadFull(reader, payload[:]); err != nil {
		return // rejection/cleanup may close before application bytes
	}
	if string(payload[:]) != "ping" {
		t.Error("startup altered application transcript")
		return
	}
	_, _ = conn.Write(payload[:])
	_, _ = reader.ReadByte() // product Close must release this peer
}

func minimalStartupBound(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("fixture socket did not become available")
}

func minimalStartupAssertStream(t *testing.T, f l5ProductionBridgeFixture, c *minimalControlTransport, stream *minimalControlStream, err error) {
	t.Helper()
	if err != nil || stream == nil {
		t.Fatalf("bounded startup never reached the available retained stream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if handle, generation := stream.Correlation(); handle != f.handle || generation == 0 {
		t.Fatal("startup did not retain the actual process/stream correlation")
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "ping" {
		t.Fatal("startup did not preserve the post-ACK byte transcript", err)
	}
	if f.bridge.session("fc-production-test") != nil {
		t.Fatal("startup published legacy readiness")
	}
	if extra, err := c.OpenWhenAvailable(context.Background(), time.Now().Add(time.Second)); extra != nil || err == nil {
		if extra != nil {
			_ = extra.Close()
		}
		t.Fatal("startup connector was reusable")
	}
	if extra, err := c.Open(context.Background()); extra != nil || err == nil {
		if extra != nil {
			_ = extra.Close()
		}
		t.Fatal("startup did not share the raw connector's one-shot claim")
	}
}

func TestMinimalControlStartupEventualAvailability(t *testing.T) {
	for _, name := range []string{"initial_socket_absent", "empty_pre_ack_closes", "already_available"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			start := make(chan struct{})
			var once sync.Once
			if name == "initial_socket_absent" {
				c.checks.observe = func(path string) (vsockSocketObservation, error) {
					observed, err := observeVsockSocketOwner(path)
					if os.IsNotExist(err) {
						once.Do(func() { close(start) })
					}
					return observed, err
				}
			} else {
				close(start)
			}
			before := minimalControlTransportGeneration.Load()
			s := serveMinimalStartup(t, f, start, func(attempt int, conn net.Conn, reader *bufio.Reader) {
				if minimalControlTransportGeneration.Load() != before {
					t.Error("generation allocated before valid ACK")
				}
				if name == "empty_pre_ack_closes" && attempt <= 2 {
					return // full CONNECT, zero ACK, real EOF
				}
				minimalStartupReady(t, conn, reader)
			})
			if name != "initial_socket_absent" {
				minimalStartupBound(t, f.paths.VsockSocketPath)
			}
			stream, err := c.OpenWhenAvailable(context.Background(), time.Now().Add(time.Second))
			minimalStartupAssertStream(t, f, c, stream, err)
			want := int32(1)
			if name == "empty_pre_ack_closes" {
				want = 3
			}
			if s.connects.Load() != want || s.active.Load() != 1 {
				t.Fatalf("CONNECT/active counts = %d/%d, want %d/1", s.connects.Load(), s.active.Load(), want)
			}
			_ = stream.Close()
			awaitMinimalTransportREDDone(t, stream.watchDone)
		})
	}
}

func TestMinimalControlStartupPreservesOriginalHardLifetime(t *testing.T) {
	f, c := minimalStartupFixture(t)
	c.lifetime = 450 * time.Millisecond
	start := make(chan struct{})
	close(start)
	s := serveMinimalStartup(t, f, start, func(attempt int, conn net.Conn, reader *bufio.Reader) {
		if attempt <= 2 {
			return
		}
		minimalStartupReady(t, conn, reader)
	})
	minimalStartupBound(t, f.paths.VsockSocketPath)
	before := time.Now()
	stream, err := c.OpenWhenAvailable(context.Background(), before.Add(time.Second))
	minimalStartupAssertStream(t, f, c, stream, err)
	if s.connects.Load() != 3 || stream.hardDeadline.After(before.Add(c.lifetime+25*time.Millisecond)) {
		t.Fatal("retry reset the original owner hard lifetime")
	}
	select {
	case <-stream.Done():
	case <-time.After(time.Until(before.Add(c.lifetime + 100*time.Millisecond))):
		_ = stream.Close() // watchdog is failure, never product cleanup evidence
		t.Fatal("original owner lifetime failed to revoke admitted stream")
	}
	_ = stream.Close()
	awaitMinimalTransportREDDone(t, stream.watchDone)
}

func TestMinimalControlStartupTerminalAfterObservedCONNECT(t *testing.T) {
	for _, name := range []string{"partial_ack", "malformed_ack", "extra_ack", "timeout", "canceled", "process_lost", "record_lost", "socket_disappeared", "socket_replaced", "parent_replaced"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := make(chan struct{})
			close(start)
			before := minimalControlTransportGeneration.Load()
			var replacement net.Listener
			var replacementMu sync.Mutex
			t.Cleanup(func() {
				replacementMu.Lock()
				defer replacementMu.Unlock()
				if replacement != nil {
					_ = replacement.Close()
				}
			})
			s := serveMinimalStartup(t, f, start, func(_ int, conn net.Conn, reader *bufio.Reader) {
				switch name {
				case "partial_ack":
					_, _ = io.WriteString(conn, "OK 1")
				case "malformed_ack":
					_, _ = io.WriteString(conn, "NOT OK 1\n")
				case "extra_ack":
					_, _ = io.WriteString(conn, "OK 1\nextra")
				case "timeout":
					_, _ = reader.ReadByte() // no ACK; product deadline must close
				case "canceled":
					cancel()
				case "process_lost":
					f.process.stop()
				case "record_lost":
					f.bridge.lifecycle.markStateRemoved(f.handle)
				case "socket_disappeared", "socket_replaced", "parent_replaced":
					path := f.paths.VsockSocketPath
					if name == "parent_replaced" {
						path = f.paths.StateDir
					}
					if err := os.Rename(path, path+".original"); err != nil {
						t.Error(err)
						return
					}
					if name == "parent_replaced" {
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Error(err)
							return
						}
					}
					if name != "socket_disappeared" {
						replacementMu.Lock()
						var err error
						replacement, err = net.Listen("unix", f.paths.VsockSocketPath)
						if err == nil {
							err = os.Chmod(f.paths.VsockSocketPath, 0o600)
						}
						replacementMu.Unlock()
						if err != nil {
							t.Error(err)
						}
					}
				}
			})
			minimalStartupBound(t, f.paths.VsockSocketPath)
			stream, err := c.OpenWhenAvailable(ctx, time.Now().Add(180*time.Millisecond))
			if stream != nil {
				_ = stream.Close()
				t.Fatal("terminal startup failure returned a stream")
			}
			if !errors.Is(err, errMinimalControlTransport) || strings.Contains(err.Error(), f.paths.StateDir) {
				t.Fatalf("invalid startup error: %v", err)
			}
			if s.connects.Load() != 1 {
				t.Fatalf("terminal failure must exercise exactly one real CONNECT, got %d", s.connects.Load())
			}
			if minimalControlTransportGeneration.Load() != before || f.bridge.session("fc-production-test") != nil {
				t.Fatal("failed startup published correlation or legacy readiness")
			}
			if name == "canceled" && !errors.Is(err, context.Canceled) || name == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("startup lost cancellation/deadline error identity", err)
			}
		})
	}
}

func TestMinimalControlStartupRetryDeadline(t *testing.T) {
	f, c := minimalStartupFixture(t)
	start := make(chan struct{})
	close(start)
	s := serveMinimalStartup(t, f, start, func(int, net.Conn, *bufio.Reader) {})
	minimalStartupBound(t, f.paths.VsockSocketPath)
	before := minimalControlTransportGeneration.Load()
	started := time.Now()
	stream, err := c.OpenWhenAvailable(context.Background(), started.Add(250*time.Millisecond))
	if stream != nil {
		_ = stream.Close()
		t.Fatal("endless unavailable guest returned a stream")
	}
	if !errors.Is(err, context.DeadlineExceeded) || s.connects.Load() < 2 || s.connects.Load() > 3 {
		t.Fatalf("bounded empty-ACK retries = %d, error %v; want 2..3 then deadline", s.connects.Load(), err)
	}
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond || elapsed > 600*time.Millisecond {
		t.Fatal("retry did not preserve absolute deadline or bounded delay", elapsed)
	}
	if minimalControlTransportGeneration.Load() != before {
		t.Fatal("unavailable attempts allocated generation")
	}
}

func TestMinimalControlStartupMissingSocketDoesNotHideAuthorityLoss(t *testing.T) {
	for _, name := range []string{"parent_mode", "parent_replaced", "parent_disappeared", "record_changed", "process_lost", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var observations atomic.Int32
			var mutation sync.Once
			c.checks.observe = func(path string) (vsockSocketObservation, error) {
				observed, err := observeVsockSocketOwner(path)
				if os.IsNotExist(err) {
					observations.Add(1)
					mutation.Do(func() {
						switch name {
						case "parent_mode":
							if err := os.Chmod(f.paths.StateDir, 0o750); err != nil {
								t.Error(err)
							}
						case "parent_replaced", "parent_disappeared":
							if err := os.Rename(f.paths.StateDir, f.paths.StateDir+".original"); err != nil {
								t.Error(err)
								return
							}
							if name == "parent_replaced" {
								if err := os.Mkdir(f.paths.StateDir, 0o700); err != nil {
									t.Error(err)
								}
							}
						case "record_changed":
							m := f.bridge.lifecycle
							m.mu.Lock()
							m.processes[f.handle.ID].strictRuntimeUID++
							m.mu.Unlock()
						case "process_lost":
							f.process.stop()
						case "canceled":
							cancel()
						}
					})
				}
				return observed, err
			}
			stream, err := c.OpenWhenAvailable(ctx, time.Now().Add(250*time.Millisecond))
			if stream != nil {
				_ = stream.Close()
				t.Fatal("missing socket hid invalid retained authority")
			}
			if !errors.Is(err, errMinimalControlTransport) || errors.Is(err, context.DeadlineExceeded) || observations.Load() == 0 {
				t.Fatalf("authority loss must be observed and terminal, observations=%d error=%v", observations.Load(), err)
			}
			if name == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("initial availability lost caller cancellation", err)
			}
		})
	}
}

// These controls establish the current real single-attempt behavior, not a
// success claim for the new stub. In particular an empty close is not an ACK.
func TestMinimalControlStartupExistingSingleAttemptControls(t *testing.T) {
	for _, ack := range []string{"", "OK 1", "NOT OK 1\n"} {
		t.Run(strings.ReplaceAll(ack, "\n", "_"), func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			start := make(chan struct{})
			close(start)
			s := serveMinimalStartup(t, f, start, func(_ int, conn net.Conn, _ *bufio.Reader) { _, _ = io.WriteString(conn, ack) })
			minimalStartupBound(t, f.paths.VsockSocketPath)
			before := minimalControlTransportGeneration.Load()
			stream, err := c.Open(context.Background())
			if stream != nil {
				_ = stream.Close()
				t.Fatal("single-attempt Open accepted missing/invalid ACK")
			}
			if !errors.Is(err, errMinimalControlTransport) || s.connects.Load() != 1 || minimalControlTransportGeneration.Load() != before {
				t.Fatalf("single-attempt gap control: connects=%d err=%v", s.connects.Load(), err)
			}
		})
	}
}
