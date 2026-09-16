//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

func minimalSupervisorWorkObserve(t *testing.T, description string, observed func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !observed() {
		select {
		case <-deadline.C:
			t.Fatal("actual work prerequisite not reached:", description)
		case <-tick.C:
		}
	}
}

func TestMinimalSupervisorWorkBlockedWriterAndFullPendingLoss(t *testing.T) {
	for _, loss := range []string{"writer-eof", "pending-eof", "pending-extra-byte"} {
		t.Run(loss, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				backend, verifier, guestDone, rescue := f.guest(t, nil)
				defer rescue()
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				data := bytes.Repeat([]byte{31}, int(server.DefaultCopyBytes))
				backend.copyOut = func(ctx context.Context, _ server.CopyOutPlan) (server.CopyResult, error) {
					close(entered)
					select {
					case <-ctx.Done():
						return server.CopyResult{}, ctx.Err()
					case <-release:
						return server.CopyResult{Data: data, SizeBytes: int64(len(data)), Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(data))}, nil
					}
				}
				client, _ := minimalSupervisorWorkClient(t, f)
				serving := f.serving(t)
				serving.mu.Lock()
				pair := serving.server
				serving.mu.Unlock()
				if pair == nil {
					t.Fatal("original registered pair unavailable")
				}
				// The received candidate is not a post-send commit observation.
				// Join the actual commit before inspecting initialized pair I/O.
				minimalJointAwait(t, pair.commit, "original publication commit and observer join")
				if pair.conn.SetWriteBuffer(2048) != nil {
					t.Fatal("actual server socket write bound unavailable")
				}
				serverRaw, err := pair.conn.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				caller, cancel := context.WithCancel(context.Background())
				finished := make(chan struct{})
				var callErr error
				go func() {
					defer close(finished)
					_, callErr = client.CopyOut(caller, guestagent.CopyOutRequest{SourcePath: "/workspace/payload.bin",
						Payload: guestagent.PayloadMetadata{MaxBytes: server.DefaultCopyBytes, Encoding: guestagent.PayloadEncodingBase64}})
				}()
				locked := false
				defer func() {
					if locked {
						f.producer.mu.Unlock()
					}
					releaseOnce.Do(func() { close(release) })
					cancel()
					minimalJointAwait(t, finished, "explicit blocked writer caller rescue")
				}()
				minimalJointAwait(t, entered, "actual CopyOut backend entered")
				// The real sole response reader takes this original mutex after
				// its first byte. Hold it before allowing the actual large reply.
				f.producer.mu.Lock()
				locked = true
				header := f.producer.active.header
				releaseOnce.Do(func() { close(release) })
				minimalSupervisorWorkObserve(t, "response writer with queued kernel bytes", func() bool {
					pair.mu.Lock()
					writing := pair.writing && pair.active != nil
					pair.mu.Unlock()
					var queued int
					var queueErr error
					controlErr := serverRaw.Control(func(fd uintptr) { queued, queueErr = unix.IoctlGetInt(int(fd), unix.TIOCOUTQ) })
					return writing && controlErr == nil && queueErr == nil && queued > 0
				})
				select {
				case <-pair.worker:
					t.Fatal("response writer ended before backpressure loss")
				case <-time.After(25 * time.Millisecond):
				}
				if loss != "writer-eof" {
					header.ordinal++
					// This is an opaque protocol-level pending-frame negative,
					// not a second admitted Client operation or backend authority.
					if writeMinimalWorkFrame(f.producer.conn, header, []byte(`{}`)) != nil {
						t.Fatal("write one next frame during actual response backpressure")
					}
					minimalSupervisorWorkObserve(t, "one bounded pending frame beside blocked original writer", func() bool {
						pair.mu.Lock()
						defer pair.mu.Unlock()
						return pair.writing && pair.active != nil && pair.pending != nil && pair.ordinal == 2
					})
				}
				if backend.calls.Load() != 1 || verifier.calls.Load() != 2 {
					t.Fatal("pending peer frame executed beside original blocked writer")
				}
				if loss == "pending-extra-byte" {
					if n, err := f.producer.conn.Write([]byte{0}); n != 1 || err != nil {
						t.Fatal("write actual excess first byte", err)
					}
				} else {
					raw, err := f.producer.conn.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var shutdown error
					if raw.Control(func(fd uintptr) { shutdown = unix.Shutdown(int(fd), unix.SHUT_RDWR) }) != nil || shutdown != nil {
						t.Fatal("actual producer endpoint shutdown failed")
					}
				}
				minimalJointAwait(t, pair.reader, "full pending slot still observes EOF or excess byte")
				minimalJointAwait(t, pair.worker, "actual blocked response writer interrupted and joined")
				f.producer.mu.Unlock()
				locked = false
				minimalJointAwait(t, finished, "original bounded CopyOut call joined")
				minimalSupervisorWorkJoined(t, f)
				minimalJointAwait(t, guestDone, "original guest joined after writer loss")
				if callErr == nil || backend.calls.Load() != 1 || verifier.calls.Load() != 2 || f.owned.minimalPreparation.workCurrent() {
					t.Fatal("partial response survived writer loss, pending frame executed, or authority survived")
				}
			})
		})
	}
}
