//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type minimalJailerPanickingContext struct{ context.Context }

func (*minimalJailerPanickingContext) Err() error { panic("secret-context-fixture-canary") }

type minimalJailerFixedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (ctx minimalJailerFixedDeadlineContext) Deadline() (time.Time, bool) { return ctx.deadline, true }

func TestMinimalJailerFinalizationInvalidCallerDoesNotClaimLegacyClient(t *testing.T) {
	for _, mode := range []string{"nil", "typed_nil", "panic", "canceled", "deadline", "copied_origin"} {
		t.Run(mode, func(t *testing.T) {
			f := newJailerRecoveryWireFixture(t)
			client := f.fresh(t)
			candidate := client
			var ctx context.Context = context.Background()
			switch mode {
			case "nil":
				ctx = nil
			case "typed_nil":
				var pointer *minimalJailerPanickingContext
				ctx = pointer
			case "panic":
				ctx = &minimalJailerPanickingContext{Context: ctx}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "deadline":
				ctx = minimalJailerFixedDeadlineContext{Context: ctx, deadline: time.Now().Add(-time.Second)}
			case "copied_origin":
				// Copy authority-bearing fields, never an in-use sync.Mutex.
				candidate = &jailerRecoveryClient{origin: client.origin, expected: client.expected, directory: client.directory}
			}
			completion, err := candidate.finalizeMinimalCleanup(ctx)
			if completion != nil || err == nil || err.Error() != errL8RuntimeOwnerInvalid.Error() || client.minimal != nil || client.legacyAdmitted {
				t.Fatal("invalid caller/origin claimed the route or leaked context detail")
			}
			if client.stopAndCommit(context.Background()) != nil {
				t.Fatal("invalid selected call changed the actual legacy transcript")
			}
			f.waitConnection()
		})
	}
}

func TestMinimalJailerFinalizationPartialConnectorFailureClosesReturnedFD(t *testing.T) {
	for _, mode := range []string{"partial_error", "nil_success"} {
		t.Run(mode, func(t *testing.T) {
			f, client, completion := minimalJailerFinalizedFixture(t)
			sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			socket := os.NewFile(uintptr(sockets[0]), "partial-connector-result")
			defer socket.Close()
			defer unix.Close(sockets[1])
			client.ops.connectMinimal = func(context.Context, *os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) {
				if mode == "nil_success" {
					return nil, nil
				}
				return socket, errors.New("secret-partial-connector-canary")
			}
			err = completion.commit(context.Background())
			if err == nil || err.Error() != errL8RuntimeOwnerInvalid.Error() || completion.state.active != nil || completion.state.acknowledged {
				t.Fatal("partial connector result became success or leaked detail")
			}
			_, statErr := socket.Stat()
			if (statErr == nil) != (mode == "nil_success") {
				t.Fatal("connector ownership did not track the actual returned partial file")
			}
			if _, err := unix.FcntlInt(uintptr(sockets[1]), unix.F_GETFD, 0); err != nil {
				t.Fatal("partial cleanup disposed the independent peer", err)
			}
			client.ops.connectMinimal = f.ops.connectMinimal
			if completion.commit(context.Background()) != nil {
				t.Fatal("bounded unavailable connector prevented explicit same-owner retry")
			}
			f.waitConnection()
		})
	}
}
