//go:build linux

package firecrackerhost

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestJailerVsockOwnerControlReconnect(t *testing.T) {
	for _, name := range []string{"active", "peer uid", "peer pid", "real peer uid", "closed", "exited", "stale handle", "canceled", "late cancellation", "late exit", "late socket replacement", "exit during ack"} {
		t.Run(name, func(t *testing.T) {
			fixture := newJailerVsockOwnerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var control atomic.Bool
			var observations atomic.Int32
			observe, peer := fixture.bridge.ownerChecks.observe, fixture.bridge.ownerChecks.peer
			fixture.bridge.ownerChecks.observe = func(path string) (vsockSocketObservation, error) {
				value, err := observe(path)
				if control.Load() && observations.Add(1) == 6 {
					switch name {
					case "late cancellation":
						cancel()
					case "late exit":
						fixture.process.stop()
					case "late socket replacement":
						value.identity.socketInode++
					}
				}
				return value, err
			}
			fixture.bridge.ownerChecks.peer = func(conn *net.UnixConn) (vsockPeerIdentity, error) {
				value, err := peer(conn)
				if control.Load() {
					switch name {
					case "peer uid":
						value.uid++
					case "peer pid":
						value.pid++
					case "real peer uid":
						return observeVsockPeerOwner(conn)
					}
				}
				return value, err
			}
			listener := jailerVsockServeReady(t, fixture)
			_, generation, err := fixture.bridge.ActivateSession(context.Background(), jailerVsockRequest(fixture))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { fixture.bridge.InvalidateSession(jailerVsockRequest(fixture), generation) })
			wire := fixture.bridge.session("fc-production-test").wire
			control.Store(true)
			target := jailerVsockTarget(fixture)
			switch name {
			case "closed":
				wire.Close()
			case "exited":
				fixture.process.stop()
			case "stale handle":
				target.Runtime.Metadata.ProcessLaunch.ProcessID += "stale"
			case "canceled":
				cancel()
			}
			serverDone := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			go func() {
				defer close(serverDone)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				if line != "CONNECT 1025\n" {
					t.Errorf("control connect = %q", line)
					return
				}
				if name == "exit during ack" {
					fixture.process.stop()
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				_, _ = io.WriteString(conn, "OK 1073741824\n")
				<-release
			}()
			t.Cleanup(func() { _ = listener.Close(); <-serverDone })
			connector := &productionL8V2ControlConnector{bridge: fixture.bridge}
			stream, err := connector.OpenL8V2Control(ctx, target)
			if name == "active" {
				if err != nil || stream == nil {
					t.Fatalf("OpenL8V2Control = %v", err)
				}
				wire.mu.Lock()
				active := len(wire.active)
				wire.mu.Unlock()
				if active != 1 {
					t.Fatalf("owned connections = %d", active)
				}
				fixture.process.stop()
				select {
				case <-stream.ProcessDone():
				case <-time.After(time.Second):
					t.Fatal("process exit did not revoke stream authority")
				}
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || stream != nil {
				if stream != nil {
					_ = stream.Close()
				}
				t.Fatalf("OpenL8V2Control = %v, want rejection", err)
			}
			wire.mu.Lock()
			active := len(wire.active)
			wire.mu.Unlock()
			if active != 0 {
				t.Fatalf("leaked connections = %d", active)
			}
		})
	}
}
