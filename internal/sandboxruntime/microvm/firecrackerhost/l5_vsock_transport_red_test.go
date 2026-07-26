package firecrackerhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestL5FirecrackerVsockTransportExactHandshakeAndFragmentedAck(t *testing.T) {
	socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("read CONNECT: %v", err)
			return
		}
		if line != "CONNECT 1024\n" {
			t.Errorf("CONNECT line = %q", line)
			return
		}
		for _, fragment := range []string{"O", "K ", "107", "374", "1824", "\n"} {
			if _, err := io.WriteString(conn, fragment); err != nil {
				t.Errorf("write ack: %v", err)
				return
			}
		}
		request, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if string(request) != `{"protocolVersion":"guest-agent-v1"}` {
			t.Errorf("request = %q", request)
			return
		}
		_, _ = io.WriteString(conn, `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready"}`)
	})

	transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath:       socketPath,
		guestPort:        L5GuestAgentPort,
		expectedPeerPID:  os.Getpid(),
		handshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
	}
	response, err := transport.RoundTrip(context.Background(), guestagent.TransportRequest{
		Operation:        guestagent.OperationReadiness,
		Encoded:          []byte(`{"protocolVersion":"guest-agent-v1"}`),
		MaxResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if !strings.Contains(string(response.Encoded), `"ready":true`) {
		t.Fatalf("response = %q, want ready", response.Encoded)
	}
}

func TestL5FirecrackerVsockTransportRejectsNoncanonicalAckAndPreAckData(t *testing.T) {
	for _, ack := range []string{
		"OK 0\n",
		"OK 4294967295\n",
		"OK 4294967296\n",
		"OK 01073741824\n",
		"OK +1073741824\n",
		"OK 1073741824 extra\n",
		"OK 1073741824\r\n",
		"OK 1073741824\nJUNK",
		`{"protocolVersion":"guest-agent-v1"}` + "\nOK 1073741824\n",
		strings.Repeat("A", 65) + "\n",
	} {
		t.Run(strings.ReplaceAll(ack[:min(len(ack), 12)], "\n", "_"), func(t *testing.T) {
			socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				_, _ = reader.ReadString('\n')
				_, _ = io.WriteString(conn, ack)
			})
			transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
				socketPath:       socketPath,
				guestPort:        L5GuestAgentPort,
				expectedPeerPID:  os.Getpid(),
				handshakeTimeout: time.Second,
			})
			if err != nil {
				t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
			}
			_, err = transport.RoundTrip(context.Background(), guestagent.TransportRequest{
				Operation: guestagent.OperationReadiness,
				Encoded:   []byte(`{}`),
			})
			if !l5ProtocolErrorCode(err, guestagent.ErrorCodeTransportFailure) {
				t.Fatalf("RoundTrip() error = %v, want transport_failure", err)
			}
		})
	}
}

func TestL5FirecrackerVsockTransportAckEOFAndTimeoutFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler func(net.Conn)
		timeout time.Duration
	}{
		{name: "eof", handler: func(conn net.Conn) {
			_, _ = bufio.NewReader(conn).ReadString('\n')
			_, _ = io.WriteString(conn, "OK 1073741824")
		}},
		{name: "timeout", handler: func(conn net.Conn) {
			_, _ = bufio.NewReader(conn).ReadString('\n')
			_, _ = io.Copy(io.Discard, conn)
		}, timeout: 10 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := l5StartFakeVsockBridge(t, tc.handler)
			transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
				socketPath:       socketPath,
				guestPort:        L5GuestAgentPort,
				expectedPeerPID:  os.Getpid(),
				handshakeTimeout: tc.timeout,
			})
			if err != nil {
				t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
			}
			_, err = transport.RoundTrip(context.Background(), guestagent.TransportRequest{
				Operation: guestagent.OperationReadiness,
				Encoded:   []byte(`{}`),
			})
			if !l5ProtocolErrorCode(err, guestagent.ErrorCodeTransportFailure) {
				t.Fatalf("RoundTrip() error = %v, want transport_failure", err)
			}
		})
	}
}

func TestL5FirecrackerVsockTransportRejectsOversizedResponse(t *testing.T) {
	socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "OK 1073741824\n")
		_, _ = io.ReadAll(reader)
		_, _ = conn.Write(make([]byte, 9))
	})
	transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath:      socketPath,
		guestPort:       L5GuestAgentPort,
		expectedPeerPID: os.Getpid(),
	})
	if err != nil {
		t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
	}
	_, err = transport.RoundTrip(context.Background(), guestagent.TransportRequest{
		Operation:        guestagent.OperationReadiness,
		Encoded:          []byte(`{}`),
		MaxResponseBytes: 8,
	})
	if !l5ProtocolErrorCode(err, guestagent.ErrorCodeOversizedResponse) {
		t.Fatalf("RoundTrip() error = %v, want oversized_response", err)
	}
}

func TestL5FirecrackerVsockTransportAcceptsMaximumAssignablePort(t *testing.T) {
	socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "OK 4294967294\n")
		_, _ = io.ReadAll(reader)
		_, _ = io.WriteString(conn, `{}`)
	})
	transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath:      socketPath,
		guestPort:       L5GuestAgentPort,
		expectedPeerPID: os.Getpid(),
	})
	if err != nil {
		t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
	}
	if _, err := transport.RoundTrip(context.Background(), guestagent.TransportRequest{
		Operation: guestagent.OperationReadiness,
		Encoded:   []byte(`{}`),
	}); err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
}

func TestL5FirecrackerVsockTransportCancellationClosesHandshake(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
		accepted <- conn
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = io.Copy(io.Discard, conn)
	})
	transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath:       socketPath,
		guestPort:        L5GuestAgentPort,
		expectedPeerPID:  os.Getpid(),
		handshakeTimeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(ctx, guestagent.TransportRequest{
			Operation: guestagent.OperationReadiness,
			Encoded:   []byte(`{}`),
		})
		done <- err
	}()
	<-accepted
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RoundTrip() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RoundTrip() did not return after cancellation")
	}
}

func TestL5FirecrackerVsockHandshakeDeadlineDoesNotCapValidOperation(t *testing.T) {
	socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "OK 1073741824\n")
		_, _ = io.ReadAll(reader)
		time.Sleep(75 * time.Millisecond)
		_, _ = io.WriteString(conn, `{}`)
	})
	transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath:       socketPath,
		guestPort:        L5GuestAgentPort,
		expectedPeerPID:  os.Getpid(),
		handshakeTimeout: 20 * time.Millisecond,
		operationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
	}
	if _, err := transport.RoundTrip(context.Background(), guestagent.TransportRequest{
		Operation: guestagent.OperationExec,
		Encoded:   []byte(`{}`),
	}); err != nil {
		t.Fatalf("RoundTrip() error = %v, operation should outlive handshake deadline", err)
	}
}

func TestL5FirecrackerVsockSessionCloseTerminatesActiveConnection(t *testing.T) {
	handshakeDone := make(chan struct{})
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "OK 1073741824\n")
		_, _ = io.ReadAll(reader)
		close(handshakeDone)
		<-releaseServer
	})
	transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath: socketPath, guestPort: L5GuestAgentPort, expectedPeerPID: os.Getpid(),
		operationTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(context.Background(), guestagent.TransportRequest{
			Operation: guestagent.OperationExec, Encoded: []byte(`{}`),
		})
		done <- err
	}()
	<-handshakeDone
	transport.Close()
	select {
	case err := <-done:
		if !l5ProtocolErrorCode(err, guestagent.ErrorCodeTransportFailure) {
			t.Fatalf("RoundTrip() error = %v, want transport failure after session close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session close did not terminate active connection")
	}
}

func TestL5FirecrackerVsockTransportRejectsUnsafeSocketMode(t *testing.T) {
	socketPath := l5StartFakeVsockBridge(t, func(net.Conn) {})
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}
	_, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath:      socketPath,
		guestPort:       L5GuestAgentPort,
		expectedPeerPID: os.Getpid(),
	})
	if err == nil {
		t.Fatal("newFirecrackerVsockTransport() error = nil, want unsafe mode rejection")
	}
	if strings.Contains(err.Error(), socketPath) || strings.Contains(err.Error(), filepath.Base(socketPath)) {
		t.Fatalf("error leaked socket path: %v", err)
	}
}

func TestL5FirecrackerVsockTransportRejectsWrongPeerProcess(t *testing.T) {
	socketPath := l5StartFakeVsockBridge(t, func(conn net.Conn) {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		data := make([]byte, 1)
		if n, _ := conn.Read(data); n != 0 {
			t.Errorf("bridge received %d request bytes despite wrong expected peer PID", n)
		}
	})
	transport, err := newFirecrackerVsockTransport(firecrackerVsockTransportOptions{
		socketPath:      socketPath,
		guestPort:       L5GuestAgentPort,
		expectedPeerPID: os.Getpid() + 1,
	})
	if err != nil {
		t.Fatalf("newFirecrackerVsockTransport() error = %v", err)
	}
	_, err = transport.RoundTrip(context.Background(), guestagent.TransportRequest{
		Operation: guestagent.OperationReadiness,
		Encoded:   []byte(`{}`),
	})
	if !l5ProtocolErrorCode(err, guestagent.ErrorCodeTransportFailure) {
		t.Fatalf("RoundTrip() error = %v, want transport_failure", err)
	}
}

func l5ProtocolErrorCode(err error, code guestagent.ErrorCode) bool {
	var protocolErr *guestagent.ProtocolError
	return errors.As(err, &protocolErr) && protocolErr.Code == code
}

func l5StartFakeVsockBridge(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hal-l5-vsock-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "bridge.sock")
	address, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		t.Fatalf("resolve unix: %v", err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		t.Fatalf("chmod socket: %v", err)
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("lstat socket: %v", err)
	}
	if err := validateVsockSocketOwnership(socketPath, info); err != nil {
		t.Fatalf("validate socket ownership: %v (dir mode=%#o socket mode=%#o euid=%d dir=%#v)", err, mustL5Mode(t, dir), info.Mode().Perm(), os.Geteuid(), mustL5Sys(t, dir))
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handle(conn)
	}()
	return socketPath
}

func mustL5Sys(t *testing.T, path string) any {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys()
}

func mustL5Mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
