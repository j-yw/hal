//go:build linux

package firecrackerhost

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestMinimalControlStartupResetBeforeACKThenSuccess(t *testing.T) {
	f, c := minimalStartupFixture(t)
	l := l5ListenBridgeSocket(t, f.paths.VsockSocketPath)
	done, peerClosed := make(chan struct{}), make(chan struct{})
	var connects atomic.Int32
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		var prefix [1]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil || prefix[0] != 'C' {
			t.Error("reset fixture did not receive CONNECT prefix", err)
		}
		connects.Add(1)
		// Leave the rest of the actual CONNECT unread. Linux closes this Unix
		// stream with ECONNRESET, as in the existing legacy bridge regression.
		_ = conn.Close()
		conn, err = l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		reader := bufio.NewReader(conn)
		if line, err := reader.ReadString('\n'); err != nil || line != "CONNECT 1025\n" {
			t.Error("retry did not send exact CONNECT", err)
			return
		}
		connects.Add(1)
		minimalStartupReady(t, conn, reader)
		close(peerClosed)
	}()
	t.Cleanup(func() { _ = l.Close(); awaitMinimalTransportREDDone(t, done) })
	stream, err := c.OpenWhenAvailable(context.Background(), time.Now().Add(time.Second))
	minimalStartupAssertStream(t, f, c, stream, err)
	if connects.Load() != 2 {
		t.Fatal("empty reset was not followed by exactly one successful attempt")
	}
	_ = stream.Close()
	awaitMinimalTransportREDDone(t, peerClosed)
}

func TestMinimalControlStartupAttemptLimitIsExact(t *testing.T) {
	f, c := minimalStartupFixture(t)
	c.startupPollInterval = time.Nanosecond // speed only, never enlarges the cap
	start := make(chan struct{})
	close(start)
	s := serveMinimalStartup(t, f, start, func(int, net.Conn, *bufio.Reader) {})
	minimalStartupBound(t, f.paths.VsockSocketPath)
	before := minimalControlTransportGeneration.Load()
	stream, err := c.OpenWhenAvailable(context.Background(), time.Now().Add(3*time.Second))
	if stream != nil {
		_ = stream.Close()
		t.Fatal("attempt exhaustion returned a stream")
	}
	if !errors.Is(err, errMinimalControlTransport) || errors.Is(err, context.DeadlineExceeded) || s.connects.Load() != 150 {
		t.Fatalf("attempt cap: CONNECT=%d error=%v; want exactly 150 and terminal exhaustion", s.connects.Load(), err)
	}
	if minimalControlTransportGeneration.Load() != before {
		t.Fatal("pre-ACK exhaustion allocated a generation")
	}
}

func TestMinimalControlStartupEffectiveDeadlines(t *testing.T) {
	for _, name := range []string{"fifteen_second_cap", "short_input", "owner_hard", "owner_context"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			ctx := context.Background()
			var cancel context.CancelFunc
			start := make(chan struct{})
			close(start)
			serveMinimalStartup(t, f, start, func(_ int, conn net.Conn, reader *bufio.Reader) { minimalStartupReady(t, conn, reader) })
			minimalStartupBound(t, f.paths.VsockSocketPath)
			before := time.Now()
			input, wantLatest := before.Add(time.Hour), before.Add(15*time.Second)
			switch name {
			case "short_input":
				input = before.Add(400 * time.Millisecond)
				wantLatest = input
			case "owner_hard":
				c.lifetime = 500 * time.Millisecond
				wantLatest = before.Add(c.lifetime)
			case "owner_context":
				wantLatest = before.Add(600 * time.Millisecond)
				ctx, cancel = context.WithDeadline(ctx, wantLatest)
				defer cancel()
			}
			stream, err := c.OpenWhenAvailable(ctx, input)
			minimalStartupAssertStream(t, f, c, stream, err)
			if stream.admissionDeadline.Before(wantLatest) || stream.admissionDeadline.After(wantLatest.Add(25*time.Millisecond)) {
				t.Fatalf("wrong effective admission bound: got %v want near %v", stream.admissionDeadline, wantLatest)
			}
			if stream.admissionDeadline.After(stream.hardDeadline) {
				t.Fatal("admission exceeds owner hard lifetime")
			}
			if name == "short_input" && !stream.hardDeadline.After(stream.admissionDeadline) {
				t.Fatal("short admission became the returned owner's lifetime")
			}
		})
	}
}

func TestMinimalControlStartupTerminalDialAndWriteErrors(t *testing.T) {
	for _, name := range []string{"eof", "reset", "refused", "permission", "connection_and_error", "write_closed"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			l := l5ListenBridgeSocket(t, f.paths.VsockSocketPath)
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := l.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var one [1]byte
				if n, _ := conn.Read(one[:]); n != 0 {
					t.Error("failed dial/write transmitted unexpected bytes")
				}
			}()
			t.Cleanup(func() { _ = l.Close(); awaitMinimalTransportREDDone(t, done) })
			var dials atomic.Int32
			c.dial = func(ctx context.Context, network, path string) (net.Conn, error) {
				dials.Add(1)
				switch name {
				case "eof":
					return nil, io.EOF
				case "reset":
					return nil, syscall.ECONNRESET
				case "refused":
					return nil, syscall.ECONNREFUSED
				case "permission":
					return nil, syscall.EACCES
				}
				conn, err := (&net.Dialer{}).DialContext(ctx, network, path)
				if err != nil {
					return nil, err
				}
				if name == "connection_and_error" {
					return conn, syscall.ECONNRESET
				}
				if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return conn, nil
			}
			before := minimalControlTransportGeneration.Load()
			stream, err := c.OpenWhenAvailable(context.Background(), time.Now().Add(time.Second))
			if stream != nil {
				_ = stream.Close()
				t.Fatal("terminal dial/write returned stream")
			}
			if !errors.Is(err, errMinimalControlTransport) || errors.Is(err, errMinimalControlPortPending) || dials.Load() != 1 || minimalControlTransportGeneration.Load() != before {
				t.Fatalf("wrong terminal dial/write behavior: calls=%d err=%v", dials.Load(), err)
			}
		})
	}
}

func TestMinimalControlStartupConcurrentOneShot(t *testing.T) {
	f, c := minimalStartupFixture(t)
	start := make(chan struct{})
	close(start)
	s := serveMinimalStartup(t, f, start, func(_ int, conn net.Conn, reader *bufio.Reader) { minimalStartupReady(t, conn, reader) })
	minimalStartupBound(t, f.paths.VsockSocketPath)
	results := make(chan *minimalControlStream, 12)
	var group sync.WaitGroup
	for range cap(results) {
		group.Add(1)
		go func() {
			defer group.Done()
			stream, _ := c.OpenWhenAvailable(context.Background(), time.Now().Add(time.Second))
			results <- stream
		}()
	}
	group.Wait()
	close(results)
	var winner *minimalControlStream
	for stream := range results {
		if stream != nil {
			if winner != nil {
				_ = stream.Close()
				t.Error("multiple startup winners")
			} else {
				winner = stream
			}
		}
	}
	minimalStartupAssertStream(t, f, c, winner, nil)
	if s.connects.Load() != 1 {
		t.Fatal("concurrent claim opened more than one connection")
	}
}

func TestMinimalControlStartupCancelsPendingDialAndWrite(t *testing.T) {
	for _, name := range []string{"dial", "write"} {
		t.Run(name, func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			l := l5ListenBridgeSocket(t, f.paths.VsockSocketPath)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, err := l.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				<-ctx.Done() // deliberately leave Unix send buffer full
			}()
			t.Cleanup(func() { cancel(); _ = l.Close(); awaitMinimalTransportREDDone(t, serverDone) })
			entered := make(chan struct{})
			c.dial = func(admission context.Context, network, path string) (net.Conn, error) {
				if name == "dial" {
					close(entered)
					<-admission.Done()
					return nil, admission.Err()
				}
				conn, err := (&net.Dialer{}).DialContext(admission, network, path)
				if err != nil {
					return nil, err
				}
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
				_, err = conn.Write(bytes.Repeat([]byte("x"), 4<<20))
				if timed, ok := err.(net.Error); !ok || !timed.Timeout() {
					t.Error("fixture did not fill Unix send buffer", err)
				}
				_ = conn.SetWriteDeadline(time.Time{})
				close(entered)
				return conn, nil
			}
			result := make(chan error, 1)
			operationDone := make(chan struct{})
			t.Cleanup(func() { cancel(); awaitMinimalTransportREDDone(t, operationDone) })
			go func() {
				defer close(operationDone)
				stream, err := c.OpenWhenAvailable(ctx, time.Now().Add(time.Second))
				if stream != nil {
					_ = stream.Close()
					t.Error("canceled startup returned stream")
				}
				result <- err
			}()
			awaitMinimalTransportREDDone(t, entered)
			select {
			case err := <-result:
				t.Fatal("startup I/O did not remain pending", err)
			case <-time.After(25 * time.Millisecond):
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("pending startup lost cancellation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled startup I/O did not join")
			}
		})
	}
}

func minimalStartupStackContains(suffix string) bool {
	var callers [24]uintptr
	frames := runtime.CallersFrames(callers[:runtime.Callers(2, callers[:])])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, suffix) {
			return true
		}
		if !more {
			return false
		}
	}
}

func TestMinimalControlStartupFinalACKDeadlineIsTerminal(t *testing.T) {
	for _, delayedTimer := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "caller_timer_not_fired"}[delayedTimer], func(t *testing.T) {
			f, c := minimalStartupFixture(t)
			deadline := time.Now().Add(120 * time.Millisecond)
			ctx := context.Context(context.Background())
			if delayedTimer {
				ctx = minimalTransportPendingDeadline{Context: ctx, deadline: deadline}
			}
			start := make(chan struct{})
			close(start)
			var acknowledged atomic.Bool
			var checks int
			crossed := false
			c.checks.observe = func(path string) (vsockSocketObservation, error) {
				if acknowledged.Load() && minimalStartupStackContains(".(*minimalControlTransport).openAttempt") && !minimalStartupStackContains(".(*minimalControlStream).watch") {
					checks++
					if checks == 3 {
						<-time.NewTimer(time.Until(deadline) + time.Millisecond).C
						crossed = true
					}
				}
				return observeVsockSocketOwner(path)
			}
			s := serveMinimalStartup(t, f, start, func(_ int, conn net.Conn, reader *bufio.Reader) {
				acknowledged.Store(true)
				_, _ = io.WriteString(conn, "OK 1\n")
				_, _ = reader.ReadByte()
			})
			minimalStartupBound(t, f.paths.VsockSocketPath)
			before := minimalControlTransportGeneration.Load()
			stream, err := c.OpenWhenAvailable(ctx, deadline)
			if stream != nil {
				_ = stream.Close()
			}
			if !crossed || stream != nil || !errors.Is(err, context.DeadlineExceeded) || s.connects.Load() != 1 || minimalControlTransportGeneration.Load() != before {
				t.Fatalf("late ACK publication: crossed=%v stream=%v CONNECT=%d error=%v", crossed, stream != nil, s.connects.Load(), err)
			}
			if delayedTimer && ctx.Err() != nil {
				t.Fatal("fixture did not retain a delayed caller cancellation")
			}
		})
	}
}

func TestMinimalControlStartupJoinsFailedWatcherBeforeRetry(t *testing.T) {
	f, c := minimalStartupFixture(t)
	start := make(chan struct{})
	close(start)
	firstCONNECT, closeFirst := make(chan struct{}), make(chan struct{})
	watchEntered, releaseWatch := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseWatch) }) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var watched atomic.Bool
	var dials atomic.Int32
	c.dial = func(ctx context.Context, network, path string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, path)
	}
	c.checks.observe = func(path string) (vsockSocketObservation, error) {
		if minimalStartupStackContains(".(*minimalControlStream).watch") && watched.CompareAndSwap(false, true) {
			close(watchEntered)
			<-releaseWatch
		}
		return observeVsockSocketOwner(path)
	}
	s := serveMinimalStartup(t, f, start, func(attempt int, conn net.Conn, reader *bufio.Reader) {
		if attempt == 1 {
			close(firstCONNECT)
			select {
			case <-closeFirst:
			case <-ctx.Done():
			}
			return
		}
		minimalStartupReady(t, conn, reader)
	})
	minimalStartupBound(t, f.paths.VsockSocketPath)
	type result struct {
		stream *minimalControlStream
		err    error
	}
	completed := make(chan result, 1)
	operationDone := make(chan struct{})
	t.Cleanup(func() { cancel(); release(); awaitMinimalTransportREDDone(t, operationDone) })
	go func() {
		defer close(operationDone)
		stream, err := c.OpenWhenAvailable(ctx, time.Now().Add(time.Second))
		completed <- result{stream, err}
	}()
	awaitMinimalTransportREDDone(t, firstCONNECT)
	awaitMinimalTransportREDDone(t, watchEntered)
	close(closeFirst)
	select {
	case <-completed:
		t.Fatal("startup returned while failed-attempt watcher remained blocked")
	case <-time.After(150 * time.Millisecond): // longer than normal retry delay
	}
	if dials.Load() != 1 {
		t.Fatal("next attempt began before the failed watcher joined")
	}
	release()
	select {
	case result := <-completed:
		minimalStartupAssertStream(t, f, c, result.stream, result.err)
		if s.connects.Load() != 2 {
			t.Fatal("joined failure was not followed by exactly one new stream")
		}
	case <-time.After(time.Second):
		t.Fatal("startup failed to resume after failed watcher joined")
	}
}

func TestMinimalControlStartupAbsoluteExpiredDeadlineBeforeDependencies(t *testing.T) {
	_, c := minimalStartupFixture(t)
	deadline := time.Now().Add(-time.Millisecond)
	ctx := minimalTransportPendingDeadline{Context: context.Background(), deadline: deadline}
	c.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("expired startup reached a dial")
		return nil, nil
	}
	stream, err := c.OpenWhenAvailable(ctx, deadline)
	if stream != nil || ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("absolute expired deadline was not independently rejected: %v", err)
	}
	if stream, err := c.OpenWhenAvailable(context.Background(), time.Now().Add(time.Second)); stream != nil || err == nil {
		t.Fatal("expired startup did not consume one-shot claim")
	}
}
