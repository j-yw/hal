package firecrackerhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
)

func TestL5ProductionVsockSessionInvalidationDistinguishesCallerCancellation(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		errors.Join(errors.New("wrapped"), context.Canceled),
		errors.Join(errors.New("wrapped"), context.DeadlineExceeded),
	} {
		if shouldInvalidateProductionVsockSession(err) {
			t.Fatalf("shouldInvalidateProductionVsockSession(%v) = true, want false", err)
		}
	}
	if !shouldInvalidateProductionVsockSession(errors.New("transport failed")) {
		t.Fatal("shouldInvalidateProductionVsockSession(transport failure) = false, want true")
	}
}

func TestL5ProductionVsockBridgePeerMismatchIsFatalWithoutRetry(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid()+1)
	var accepts atomic.Int32
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepts.Add(1)
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = io.Copy(io.Discard, conn)
	}()

	started := time.Now()
	_, _, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-production-test", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err == nil {
		t.Fatal("ActivateSession() error = nil, want peer mismatch")
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("fatal peer mismatch retried until timeout: %v", elapsed)
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for accepts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if accepts.Load() != 1 {
		t.Fatalf("accepted connections = %d, want exactly one fatal attempt", accepts.Load())
	}
}

func TestL5ProductionVsockBridgeRetriesClosedPreAckGuestPort(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	var accepts atomic.Int32
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			reader := bufio.NewReader(conn)
			_, _ = reader.ReadString('\n')
			if attempt == 0 {
				_ = conn.Close()
				continue
			}
			_, _ = io.WriteString(conn, "OK 1073741824\n")
			_, _ = frame.Read(reader, 1024)
			_ = frame.Write(conn, []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready"}`), 1024)
			_ = conn.Close()
		}
	}()

	result, _, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-production-test", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err != nil {
		t.Fatalf("ActivateSession() error = %v, want retry after a closed pre-ack guest port", err)
	}
	if result.State != sandboxruntime.RuntimeGuestReadinessStateReady {
		t.Fatalf("readiness state = %q, want ready", result.State)
	}
	if got := accepts.Load(); got != 2 {
		t.Fatalf("accepted connections = %d, want one closed pre-ack attempt plus one ready attempt", got)
	}
}

func TestL5ProductionVsockBridgeRejectsMalformedAckWithoutRetry(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	var accepts atomic.Int32
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepts.Add(1)
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "NOT-AN-ACK\n")
	}()

	started := time.Now()
	_, _, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-production-test", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err == nil {
		t.Fatal("ActivateSession() error = nil, want malformed acknowledgement failure")
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("malformed acknowledgement retried until timeout: %v", elapsed)
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for accepts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("accepted connections = %d, want exactly one malformed-ack attempt", got)
	}
}

func TestL5ProductionVsockBridgeNaturalExitInvalidatesGeneration(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	go l5ServeReadyBridge(listener)

	result, generation, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-production-test", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err != nil {
		t.Fatalf("ActivateSession() error = %v", err)
	}
	if result.Transport != "vsock" || strings.Join(result.Labels, ",") != "ready,protocol_v1,runtime_bound,probe_ok" {
		t.Fatalf("readiness = %#v, want canonical vsock labels", result)
	}
	req := firecracker.ProductionVsockSessionRequest{Handle: fixture.handle, RuntimeID: "fc-production-test"}
	if !fixture.bridge.SessionActive(req, generation) {
		t.Fatal("new generation is not active")
	}
	forged := sandboxruntime.Target{
		ID: "fc-production-test",
		Runtime: sandboxruntime.RuntimeState{
			RuntimeID: "fc-production-test",
			Metadata: &sandboxruntime.RuntimeMetadata{ProcessLaunch: &sandboxruntime.RuntimeProcessLaunchMetadata{
				ProcessID: fixture.handle.ID, ProcessIDSource: "forged-source",
			}},
		},
	}
	if session := fixture.bridge.sessionForTarget(forged); session != nil {
		t.Fatal("forged process ID source selected a production vsock session")
	}
	if fixture.bridge.SessionActive(firecracker.ProductionVsockSessionRequest{
		Handle:    firecracker.ProcessHandleMetadata{ID: fixture.handle.ID, Source: "forged-source"},
		RuntimeID: "fc-production-test",
	}, generation) {
		t.Fatal("forged process ID source authorized the generation")
	}
	if !fixture.bridge.SessionActive(req, generation) {
		t.Fatal("forged process ID source invalidated the legitimate generation")
	}
	close(fixture.process.done)
	deadline := time.Now().Add(time.Second)
	for fixture.bridge.SessionActive(req, generation) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fixture.bridge.SessionActive(req, generation) {
		t.Fatal("natural process exit left the generation active")
	}
}

func TestL5ProductionVsockBridgeRejectsAndDoesNotRepairUnsafeSocketMode(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	if err := os.Chmod(fixture.paths.VsockSocketPath, 0o660); err != nil {
		t.Fatal(err)
	}
	_, _, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-production-test", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err == nil {
		t.Fatal("ActivateSession() error = nil, want unsafe socket rejection")
	}
	info, statErr := os.Lstat(fixture.paths.VsockSocketPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("unsafe socket mode was silently repaired to %#o", info.Mode().Perm())
	}
	_ = listener.Close()
}

func TestL5ProductionVsockBridgeRejectsCrossRuntimePathBinding(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	_, _, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-other-runtime", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err == nil {
		t.Fatal("ActivateSession() error = nil, want runtime/state binding rejection")
	}
}

type l5ProductionBridgeFixture struct {
	bridge  *ProductionVsockBridge
	process *l5IdentityProcess
	handle  firecracker.ProcessHandleMetadata
	paths   firecracker.PathPlan
}

func newL5ProductionBridgeFixture(t *testing.T, pid int) l5ProductionBridgeFixture {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "hal-l5-prod-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{
		RuntimeID: "fc-production-test", BaseStateDir: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	process := &l5IdentityProcess{pid: pid, done: make(chan struct{})}
	manager := NewProcessLifecycleManager(l5SingleProcessRunner{process: process})
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "firecracker",
		Args: []string{
			"--api-sock", paths.APISocketPath,
			"--config-file", paths.ConfigPath,
			"--log-path", paths.LogPath,
			"--metrics-path", paths.MetricsPath,
		},
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	return l5ProductionBridgeFixture{
		bridge: NewProductionVsockBridge(ProductionVsockBridgeOptions{
			Lifecycle: manager, Timeout: time.Second, PollInterval: time.Millisecond,
		}),
		process: process, handle: handle, paths: paths,
	}
}

type l5IdentityProcess struct {
	pid  int
	done chan struct{}
}

func (*l5IdentityProcess) Wait(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (*l5IdentityProcess) Signal(context.Context, ProcessSignal) error { return nil }
func (*l5IdentityProcess) Kill(context.Context) error                  { return nil }
func (process *l5IdentityProcess) HostPID() int                        { return process.pid }
func (process *l5IdentityProcess) Done() <-chan struct{}               { return process.done }

func l5ListenBridgeSocket(t *testing.T, path string) net.Listener {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func l5ServeReadyBridge(listener net.Listener) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n')
	_, _ = io.WriteString(conn, "OK 1073741824\n")
	_, _ = frame.Read(reader, 1024)
	_ = frame.Write(conn, []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready"}`), 1024)
}
