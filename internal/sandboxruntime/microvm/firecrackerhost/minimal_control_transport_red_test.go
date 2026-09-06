//go:build linux

package firecrackerhost

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type minimalHostTransportREDStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	Done() <-chan struct{}
}

// The original RED used the actual legacy connector without prior v1 readiness.
// Only this opener changes for GREEN; the real transcript/assertions stay intact.
func openMinimalHostTransportRED(ctx context.Context, fixture l5ProductionBridgeFixture) (minimalHostTransportREDStream, error) {
	connector, err := newMinimalControlTransport(fixture.bridge.lifecycle, fixture.handle, "fc-production-test")
	if err != nil {
		return nil, err
	}
	connector.checks = fixture.bridge.ownerChecks // private ordinary-UID fixture
	return connector.Open(ctx)
}

func TestMinimalHostTransportREDRetainedStreamWithoutV1(t *testing.T) {
	for _, scenario := range []string{"bytes_and_close", "cancel_read", "process_loss_read", "owner_loss_read", "socket_replaced_read", "record_uid_changed_read", "cancel_write", "owner_loss_write"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newJailerVsockOwnerFixture(t)
			listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
			serverCtx, stopServer := context.WithCancel(context.Background())
			serverDone := make(chan error, 1)
			writeObserved := make(chan struct{})
			writing := scenario == "cancel_write" || scenario == "owner_loss_write"
			var connects atomic.Int32
			go func() {
				serverDone <- serveMinimalHostTransportRED(serverCtx, listener, writing, writeObserved, &connects)
			}()
			t.Cleanup(func() {
				stopServer()
				_ = listener.Close()
				select {
				case <-serverDone:
				case <-time.After(2 * time.Second):
					t.Error("fixture transport handler did not join")
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fixture.bridge.session("fc-production-test") != nil {
				t.Fatal("fixture fabricated v1 readiness")
			}
			stream, err := openMinimalHostTransportRED(ctx, fixture)
			if err != nil || stream == nil {
				t.Fatalf("raw retained transport unavailable without v1 readiness: %v", err)
			}
			t.Cleanup(func() { _ = stream.Close() })
			if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var echoed [4]byte
			if _, err := io.ReadFull(stream, echoed[:]); err != nil || string(echoed[:]) != "ping" || connects.Load() != 1 {
				t.Fatal("opened stream did not complete real CONNECT1025/ACK/byte roundtrip", err)
			}
			if fixture.bridge.session("fc-production-test") != nil {
				t.Fatal("transport availability published legacy readiness")
			}
			if err := stream.SetDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if scenario == "bytes_and_close" {
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
				awaitMinimalTransportREDDone(t, stream.Done())
				if err := stream.Close(); err != nil {
					t.Fatal("second Close failed", err)
				}
				return
			}
			pending := make(chan error, 1)
			entered := make(chan struct{})
			ioDone := make(chan struct{})
			t.Cleanup(func() {
				_ = stream.Close()
				select {
				case <-ioDone:
				case <-time.After(time.Second):
					t.Error("fixture I/O goroutine did not join")
				}
			})
			go func() {
				defer close(ioDone)
				close(entered)
				if writing {
					_, err := stream.Write(bytes.Repeat([]byte("w"), 4<<20))
					pending <- err
				} else {
					var one [1]byte
					_, err := stream.Read(one[:])
					pending <- err
				}
			}()
			<-entered
			if writing {
				awaitMinimalTransportREDDone(t, writeObserved)
			}
			select {
			case err := <-pending:
				t.Fatalf("I/O was not pending before authority loss: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			switch scenario {
			case "cancel_read", "cancel_write":
				cancel()
			case "process_loss_read":
				fixture.process.stop()
			case "owner_loss_read", "owner_loss_write":
				fixture.bridge.lifecycle.markStateRemoved(fixture.handle)
			case "record_uid_changed_read":
				manager := fixture.bridge.lifecycle
				manager.mu.Lock()
				manager.processes[fixture.handle.ID].strictRuntimeUID++
				manager.mu.Unlock()
			case "socket_replaced_read":
				listener.(*net.UnixListener).SetUnlinkOnClose(false)
				if err := os.Rename(fixture.paths.VsockSocketPath, fixture.paths.VsockSocketPath+".retained"); err != nil {
					t.Fatal(err)
				}
				l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
			}
			select {
			case err := <-pending:
				if err == nil {
					t.Fatal("pending I/O succeeded after authority loss")
				}
			case <-time.After(time.Second):
				_ = stream.Close() // watchdog cleanup is a failure, never proof
				<-pending
				t.Fatal("product failed to cancel pending retained I/O")
			}
			awaitMinimalTransportREDDone(t, stream.Done())
			if fixture.bridge.session("fc-production-test") != nil {
				t.Fatal("loss created a legacy session")
			}
		})
	}
}

func awaitMinimalTransportREDDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("required observed transport event did not complete")
	}
}

func serveMinimalHostTransportRED(ctx context.Context, listener net.Listener, writing bool, writeObserved chan<- struct{}, connects *atomic.Int32) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || line != "CONNECT 1025\n" {
		return errors.New("unexpected fixture CONNECT")
	}
	connects.Add(1)
	if _, err := io.WriteString(conn, "OK 1073741824\n"); err != nil {
		return err
	}
	var payload [4]byte
	if _, err := io.ReadFull(reader, payload[:]); err != nil || string(payload[:]) != "ping" {
		return errors.New("unexpected fixture payload before minimal protocol")
	}
	if _, err := conn.Write(payload[:]); err != nil {
		return err
	}
	if writing {
		if _, err := reader.ReadByte(); err != nil {
			return err
		}
		close(writeObserved)
	}
	<-ctx.Done() // deliberately no more peer reads/writes while product I/O blocks
	return nil
}

func TestMinimalHostTransportLegacyStillRequiresV1Readiness(t *testing.T) {
	fixture := newJailerVsockOwnerFixture(t)
	l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	stream, err := (&productionL8V2ControlConnector{bridge: fixture.bridge}).OpenL8V2Control(context.Background(), jailerVsockTarget(fixture))
	if stream != nil || !errors.Is(err, ErrL8V2ControlUnavailable) || fixture.bridge.session("fc-production-test") != nil {
		if stream != nil {
			_ = stream.Close()
		}
		t.Fatalf("legacy admission changed: %v", err)
	}
}
