//go:build linux

package firecrackerhost

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJailerVsockOwnerLinuxObservation(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	observed, err := observeVsockSocketOwner(fixture.paths.VsockSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	state, err := statPrivateFirecrackerStateDir(fixture.paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if observed.uid != uint32(os.Geteuid()) || observed.parentUID != state.uid ||
		observed.identity.parentDevice != state.device || observed.identity.parentInode != state.inode ||
		observed.identity.socketInode == 0 || observed.socketMode != os.ModeSocket|0o600 || observed.parentMode != os.ModeDir|0o700 {
		t.Fatalf("incomplete actual Linux observation: %#v", observed)
	}
	// Real pathname cases, all within the fixture-owned tree, without chown.
	link := filepath.Join(fixture.paths.StateDir, "socket-link")
	if err := os.Symlink(fixture.paths.VsockSocketPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := observeVsockSocketOwner(link); err == nil {
		t.Fatal("symlink socket observed as socket")
	}
	parentLink := fixture.paths.StateDir + "-link"
	if err := os.Symlink(fixture.paths.StateDir, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := observeVsockSocketOwner(filepath.Join(parentLink, filepath.Base(fixture.paths.VsockSocketPath))); err == nil {
		t.Fatal("symlink parent accepted")
	}
	regular := filepath.Join(fixture.paths.StateDir, "not-socket")
	file, err := os.OpenFile(regular, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := observeVsockSocketOwner(regular); err == nil {
		t.Fatal("regular file observed as socket")
	}
	if _, err := observeVsockSocketOwner(filepath.Join(fixture.paths.StateDir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing socket = %v", err)
	}
}

func TestJailerVsockOwnerProcessExitOrCancellationClosesAdmittedHandshake(t *testing.T) {
	for _, name := range []string{"exit", "cancel"} {
		t.Run(name, func(t *testing.T) {
			fixture := newJailerVsockOwnerFixture(t)
			listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
			admitted, peerClosed := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(peerClosed)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(conn)
				if _, err := reader.ReadString('\n'); err != nil {
					return
				}
				close(admitted)
				_, _ = reader.ReadByte() // Do not acknowledge: client must close.
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, _, err := fixture.bridge.ActivateSession(ctx, jailerVsockRequest(fixture))
				result <- err
			}()
			select {
			case <-admitted:
			case <-time.After(time.Second):
				t.Fatal("handshake not admitted")
			}
			if name == "exit" {
				fixture.process.stop()
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("revoked handshake succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("revoked handshake did not return")
			}
			select {
			case <-peerClosed:
			case <-time.After(time.Second):
				t.Fatal("revoked connection leaked")
			}
			if fixture.bridge.session("fc-production-test") != nil {
				t.Fatal("revoked handshake published readiness")
			}
		})
	}
}
