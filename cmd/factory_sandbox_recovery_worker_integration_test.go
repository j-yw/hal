//go:build linux && worker_integration

package cmd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

// The real encoder/strict decoder carry the production recovery script. The
// handler records bytes only: no process, container, Git, or credentials.
func TestFactoryFinalizationRecoveryWorkerRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Unix sockets have a short pathname limit; do not inherit a long TMPDIR
	// or the full test name. MkdirTemp creates a private, task-owned directory.
	socketDir, err := os.MkdirTemp("/tmp", "hal-ff-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDir); err != nil {
			t.Errorf("remove worker fixture directory: %v", err)
		}
	})
	socketPath := filepath.Join(socketDir, "worker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan sandboxworker.ExecRequest, 1)
	server, err := sandboxworker.NewServer(sandboxworker.ServerOptions{SocketPath: socketPath, Handler: sandboxworker.RequestHandlerFunc(func(_ context.Context, req sandboxworker.Request) sandboxworker.Response {
		observed <- *req.Exec
		return sandboxworker.Response{OK: true, Operation: req.Operation, RequestID: req.RequestID, Exec: &sandboxworker.ExecResponse{
			Stdout: sandboxworker.ExecOutputPayload{LimitBytes: sandboxworker.MaxExecStdoutCaptureBytes},
			Stderr: sandboxworker.ExecOutputPayload{LimitBytes: sandboxworker.MaxExecStderrCaptureBytes},
		}}
	})})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("worker fixture shutdown: %v", err)
		}
	})
	client, err := sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := sandboxworker.NewClientDriver(sandboxworker.ClientDriverOptions{DriverID: sandboxruntime.DriverRootlessPodman, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	record := factory.RunRecord{RepoPath: "/workspace/repo", BaseBranch: "local-base"}
	target := workerRootlessCachedSandbox("recovery-wire")
	if err := generateFactorySandboxRuntimeRecoveryArtifacts(ctx, record, target, driver, nil); err != nil {
		t.Fatalf("actual recovery script worker round-trip: %v", err)
	}
	select {
	case req := <-observed:
		if !reflect.DeepEqual(req.Args, []string{"sh", "-c", factorySandboxRecoveryArtifactScript(record.RepoPath, record.BaseBranch)}) || req.Target.Runtime.RuntimeID != target.Runtime.RuntimeID || req.Env != nil {
			t.Fatal("worker changed recovery script bytes, exact target, or environment")
		}
	case <-ctx.Done():
		t.Fatal("worker did not dispatch recovery script")
	}
}
