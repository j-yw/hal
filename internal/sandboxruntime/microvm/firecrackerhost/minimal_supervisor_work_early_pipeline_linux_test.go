//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

func TestMinimalSupervisorWorkRejectsPeerPipeliningBeforeResponse(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		backend, verifier, guestDone, rescue := f.guest(t, nil)
		defer rescue()
		entered := make(chan struct{})
		backend.exec = func(ctx context.Context, _ server.ExecPlan) (server.ExecResult, error) {
			close(entered)
			<-ctx.Done()
			return server.ExecResult{}, ctx.Err()
		}
		client, _ := minimalSupervisorWorkClient(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		finished := make(chan struct{})
		var callErr error
		go func() {
			defer close(finished)
			_, callErr = client.Exec(ctx, minimalJointExecRequest())
		}()
		defer func() {
			cancel()
			minimalJointAwait(t, finished, "original caller joined after early-peer-input test")
		}()
		minimalJointAwait(t, entered, "actual first backend operation entered")
		serving := f.serving(t)
		serving.mu.Lock()
		pair := serving.server
		serving.mu.Unlock()
		if pair == nil {
			t.Fatal("original committed work pair missing")
		}
		minimalJointAwait(t, pair.commit, "original publication and observer join")
		pair.mu.Lock()
		if pair.active == nil || pair.pending != nil || pair.writing || pair.ordinal != 1 {
			pair.mu.Unlock()
			t.Fatal("first original operation was not active before response writing")
		}
		header := pair.active.header
		payload := bytes.Clone(pair.active.payload)
		pair.mu.Unlock()
		defer clear(payload)
		header.ordinal++
		var wire bytes.Buffer
		if err := writeMinimalWorkFrame(&wire, header, payload); err != nil {
			t.Fatal("encode a valid next peer frame from the original bound request", err)
		}
		defer clear(wire.Bytes())
		// This deliberately sends peer input, not a second admitted Client call.
		// Its real next ordinal and original request are otherwise valid. Only
		// the first operation's actual non-writing phase prohibits admission.
		if n, err := f.producer.conn.Write(wire.Bytes()); err != nil || n != wire.Len() {
			t.Fatal("actual next-frame write prerequisite", err)
		}
		minimalJointAwait(t, pair.reader, "early peer input retired the original reader")
		minimalJointAwait(t, pair.worker, "original blocked operation interrupted and joined")
		minimalJointAwait(t, finished, "original Client observed early-input loss")
		minimalSupervisorWorkJoined(t, f)
		minimalJointAwait(t, guestDone, "original guest joined after early input")
		pair.mu.Lock()
		ordinal, pending := pair.ordinal, pair.pending
		pair.mu.Unlock()
		if callErr == nil || backend.calls.Load() != 1 || verifier.calls.Load() != 2 || ordinal != 1 || pending != nil || f.owned.minimalPreparation.workCurrent() {
			t.Fatal("early peer request executed, advanced admission or retained authority")
		}
		fd, session := f.cleanup(t)
		defer unix.Close(fd)
		minimalSupervisorJointInspect(t, fd, session)
	})
}
