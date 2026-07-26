package firecrackerhost

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

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
		Handle: fixture.handle, RuntimeID: "fc-peer-mismatch", SocketPath: fixture.paths.VsockSocketPath,
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

func TestL5ProductionVsockBridgeNaturalExitInvalidatesGeneration(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	go l5ServeReadyBridge(listener)

	result, generation, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-natural-exit", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err != nil {
		t.Fatalf("ActivateSession() error = %v", err)
	}
	if result.Transport != "vsock" || strings.Join(result.Labels, ",") != "ready,protocol_v1,runtime_bound,probe_ok" {
		t.Fatalf("readiness = %#v, want canonical vsock labels", result)
	}
	req := firecracker.ProductionVsockSessionRequest{Handle: fixture.handle, RuntimeID: "fc-natural-exit"}
	if !fixture.bridge.SessionActive(req, generation) {
		t.Fatal("new generation is not active")
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
	_, _ = io.ReadAll(reader)
	_, _ = io.WriteString(conn, `{"protocolVersion":"guest-agent-v1","operation":"readiness","ready":true,"status":"ready"}`)
}
