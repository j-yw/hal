//go:build !windows

package sandboxworker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestL3WorkerServerRejectsUnsafeSocketParentsWithoutMutation(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) (string, func())
	}{
		{
			name: "broad parent",
			setup: func(t *testing.T) (string, func()) {
				parent := filepath.Join(resolvedWorkerTempDir(t), "shared")
				if err := os.Mkdir(parent, 0o755); err != nil {
					t.Fatalf("Mkdir(parent) error: %v", err)
				}
				return filepath.Join(parent, "worker.sock"), func() {
					info, err := os.Stat(parent)
					if err != nil {
						t.Fatalf("Stat(parent) error: %v", err)
					}
					if got := info.Mode().Perm(); got != 0o755 {
						t.Fatalf("parent mode = %#o, want unchanged 0755", got)
					}
				}
			},
		},
		{
			name: "symlinked parent",
			setup: func(t *testing.T) (string, func()) {
				base := resolvedWorkerTempDir(t)
				realParent := filepath.Join(base, "private")
				if err := os.Mkdir(realParent, 0o700); err != nil {
					t.Fatalf("Mkdir(real parent) error: %v", err)
				}
				linkedParent := filepath.Join(base, "linked")
				if err := os.Symlink(realParent, linkedParent); err != nil {
					t.Fatalf("Symlink(parent) error: %v", err)
				}
				return filepath.Join(linkedParent, "worker.sock"), func() {
					entries, err := os.ReadDir(realParent)
					if err != nil {
						t.Fatalf("ReadDir(real parent) error: %v", err)
					}
					if len(entries) != 0 {
						t.Fatalf("server wrote through socket-parent symlink: %#v", entries)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath, assertUnchanged := tt.setup(t)
			server, err := NewServer(ServerOptions{
				SocketPath: socketPath,
				Handler: RequestHandlerFunc(func(context.Context, Request) Response {
					t.Fatal("unsafe socket server dispatched a request")
					return Response{}
				}),
			})
			if err != nil {
				assertUnchanged()
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			err = server.ListenAndServe(ctx)
			if err == nil {
				t.Fatal("ListenAndServe() accepted an unsafe socket parent")
			}
			assertUnchanged()
		})
	}
}

func TestL3WorkerServerCreatesPrivateSocketAndRemovesOnlyItsOwnSocket(t *testing.T) {
	parent := filepath.Join(resolvedWorkerTempDir(t), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir(parent) error: %v", err)
	}
	socketPath := filepath.Join(parent, "worker.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(_ context.Context, req Request) Response {
			return Response{
				ProtocolVersion: ProtocolVersion,
				RequestID:       req.RequestID,
				Operation:       req.Operation,
				OK:              true,
			}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe(ctx)
	}()
	waitForWorkerSocket(t, socketPath, errCh)

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("Lstat(socket) error: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v, want Unix socket", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket permissions = %#o, want 0600", got)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe() shutdown error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe() did not stop")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket remains after shutdown: %v", err)
	}
}

func TestL3WorkerServerRejectsSocketParentReplacementDuringBind(t *testing.T) {
	base := resolvedWorkerTempDir(t)
	parent := filepath.Join(base, "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir(parent) error: %v", err)
	}
	socketPath := filepath.Join(parent, "worker.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			t.Fatal("server dispatched through a replaced socket parent")
			return Response{}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	originalListen := listenWorkerUnixSocket
	t.Cleanup(func() { listenWorkerUnixSocket = originalListen })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listenWorkerUnixSocket = func(ctx context.Context, path string) (net.Listener, error) {
		movedParent := parent + ".validated"
		if err := os.Rename(parent, movedParent); err != nil {
			return nil, err
		}
		if err := os.Mkdir(parent, 0o700); err != nil {
			return nil, err
		}
		listener, err := originalListen(ctx, path)
		cancel()
		return listener, err
	}

	err = server.ListenAndServe(ctx)
	if err == nil {
		t.Fatal("ListenAndServe() error = nil after socket parent replacement")
	}
	if strings.Contains(err.Error(), socketPath) || strings.Contains(err.Error(), base) {
		t.Fatalf("ListenAndServe() error exposed a socket path: %v", err)
	}
}

func TestL3WorkerServerDoesNotRemoveReplacementAtSocketPath(t *testing.T) {
	parent := filepath.Join(resolvedWorkerTempDir(t), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir(parent) error: %v", err)
	}
	socketPath := filepath.Join(parent, "worker.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    RequestHandlerFunc(func(context.Context, Request) Response { return Response{} }),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe(ctx)
	}()
	waitForWorkerSocket(t, socketPath, errCh)

	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("Remove(created socket) error: %v", err)
	}
	if err := os.WriteFile(socketPath, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("WriteFile(replacement) error: %v", err)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe() shutdown error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe() did not stop")
	}
	data, err := os.ReadFile(socketPath)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement was removed or changed: data=%q err=%v", data, err)
	}
}

func TestL3WorkerServerRejectsExistingNonSocketWithoutDeletingIt(t *testing.T) {
	parent := filepath.Join(resolvedWorkerTempDir(t), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir(parent) error: %v", err)
	}
	socketPath := filepath.Join(parent, "worker-token=preserve.sock")
	if err := os.WriteFile(socketPath, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("WriteFile(socket path) error: %v", err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    RequestHandlerFunc(func(context.Context, Request) Response { return Response{} }),
	})
	if err == nil {
		err = server.ListenAndServe(context.Background())
	}
	if err == nil {
		t.Fatal("worker server accepted an existing non-socket path")
	}
	if strings.Contains(err.Error(), socketPath) || strings.Contains(err.Error(), "worker-token") {
		t.Fatalf("worker server error exposed socket path: %v", err)
	}
	data, readErr := os.ReadFile(socketPath)
	if readErr != nil || string(data) != "preserve" {
		t.Fatalf("existing non-socket was mutated: data=%q err=%v", data, readErr)
	}
}
