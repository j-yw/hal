package firecrackerhost

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMinimalCleanupPreflightRejectsEveryChangedRecordField(t *testing.T) {
	shape := reflect.TypeFor[firecrackerRuntimeOwnerRecordV1]()
	for index := 0; index < shape.NumField(); index++ {
		t.Run(shape.Field(index).Name, func(t *testing.T) {
			owner, store, request := minimalCleanupPreparedRequest(t, "finalize")
			transitions, snapshot := len(store.transitions), owner.cleanupSnapshot()
			var replacement firecrackerRuntimeOwnerRecordV1
			calls := 0
			_, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
				calls++
				owner.mu.Lock()
				defer owner.mu.Unlock()
				field := reflect.ValueOf(&store.record).Elem().Field(index)
				switch field.Kind() {
				case reflect.String:
					field.SetString(field.String() + "-changed")
				case reflect.Uint32, reflect.Uint64:
					field.SetUint(field.Uint() + 1)
				case reflect.Int64:
					field.SetInt(field.Int() + 1)
				default:
					t.Errorf("new record field kind needs explicit coverage: %s", field.Kind())
				}
				replacement = store.record
				return nil
			})
			if !errors.Is(err, errL8RuntimeOwnerInvalid) || calls != 1 || store.record != replacement ||
				len(store.transitions) != transitions || !snapshot.matches(owner) || store.retiredFinal {
				t.Fatalf("changed field admitted stale cleanup or was overwritten: err=%v barrier=%d", err, calls)
			}
		})
	}
}

func TestMinimalCleanupPreflightRejectsChangedSessionAndReplayLedger(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*l8RuntimeOwnerSupervisor)
	}{
		{"session", func(o *l8RuntimeOwnerSupervisor) { o.sessionGeneration = l8RuntimeOwnerTestToken(80) }},
		{"admitted", func(o *l8RuntimeOwnerSupervisor) { o.admittedSession = "" }},
		{"sequence", func(o *l8RuntimeOwnerSupervisor) { o.lastSequence++ }},
		{"opcode", func(o *l8RuntimeOwnerSupervisor) { o.lastOpcode++ }},
		{"has-last", func(o *l8RuntimeOwnerSupervisor) { o.hasLast = false }},
		{"reply-opcode", func(o *l8RuntimeOwnerSupervisor) { o.lastPacket.Opcode++ }},
		{"reply-sequence", func(o *l8RuntimeOwnerSupervisor) { o.lastPacket.Sequence++ }},
		{"reply-status", func(o *l8RuntimeOwnerSupervisor) { o.lastPacket.Status++ }},
		{"reply-body-in-place", func(o *l8RuntimeOwnerSupervisor) { o.lastPacket.Body[0] ^= 1 }},
		{"request-body-in-place", func(o *l8RuntimeOwnerSupervisor) { o.lastRequestBody[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner, store, request := minimalCleanupPreparedRequest(t, "finalize")
			before, transitions := store.record, len(store.transitions)
			var changed minimalCleanupControllerSnapshot
			calls := 0
			_, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
				calls++
				owner.mu.Lock()
				defer owner.mu.Unlock()
				test.mutate(owner)
				changed = owner.cleanupSnapshot()
				return nil
			})
			if !errors.Is(err, errL8RuntimeOwnerInvalid) || calls != 1 || store.record != before ||
				len(store.transitions) != transitions || !changed.matches(owner) || store.retiredFinal {
				t.Fatal("stale session/ledger dispatched or overwrote a successor")
			}
		})
	}
}

func TestMinimalCleanupPreflightConcurrentRequestAndReconnectWinOverStaleJoin(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "inspect", true: "lost-reconnect"}[reconnect], func(t *testing.T) {
			owner, store, request := minimalCleanupPreflightFixture(t)
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				_, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
					close(entered)
					<-release
					return nil
				})
				done <- err
			}()
			select {
			case <-entered:
			case err := <-done:
				close(release)
				t.Fatalf("did not reach valid selected barrier: %v", err)
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("barrier entry timeout")
			}
			// These are actual independent FSM calls while the first request is
			// parked outside owner.mu, not calls from its barrier callback.
			var concurrentErr error
			if reconnect {
				concurrentErr = owner.ControllerLost(context.Background())
				if concurrentErr == nil {
					body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{
						SupervisorGeneration: store.record.SupervisorGeneration, RuntimeGeneration: store.record.RuntimeGeneration,
						RecordRevision: store.record.Revision, ReconnectSecret: store.record.ReconnectSecret,
					})
					concurrentErr = err
					if err == nil {
						_, concurrentErr = owner.AdmitController(context.Background(), 1000, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}})
					}
				}
			} else {
				inspect := request
				inspect.Packet.Opcode = l8RuntimeOwnerOpcodeInspect
				_, concurrentErr = owner.HandleController(context.Background(), inspect)
			}
			before, transitions, snapshot := store.record, len(store.transitions), owner.cleanupSnapshot()
			close(release)
			select {
			case err := <-done:
				if concurrentErr != nil || !errors.Is(err, errL8RuntimeOwnerInvalid) || store.record != before ||
					len(store.transitions) != transitions || !snapshot.matches(owner) {
					t.Fatalf("stale cleanup replaced concurrent owner state: cleanup=%v other=%v", err, concurrentErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stale cleanup did not join")
			}
		})
	}
}

func TestMinimalCleanupPreflightConcurrentDuplicatesDispatchOnce(t *testing.T) {
	owner, store, request := minimalCleanupPreflightFixture(t)
	entered, release, results := make(chan struct{}, 2), make(chan struct{}), make(chan error, 2)
	for range 2 {
		go func() {
			_, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
				entered <- struct{}{}
				<-release
				return nil
			})
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("concurrent attempt failed to reach same-owner barrier")
		}
	}
	close(release)
	successes, failures := 0, 0
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				successes++
			} else if errors.Is(err, errL8RuntimeOwnerInvalid) {
				failures++
			} else {
				t.Errorf("unexpected duplicate result: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("duplicate attempt did not join")
		}
	}
	if successes != 1 || failures != 1 || store.record.State != "absent" || store.record.Revision != 5 || len(store.transitions) != 3 {
		t.Fatal("duplicate attempt dispatched twice or lost original cleanup")
	}
}

func TestMinimalCleanupPreflightBarrierAndStoreFailuresDoNotAdvance(t *testing.T) {
	for _, phase := range []string{"panic", "error", "first-load", "second-load"} {
		t.Run(phase, func(t *testing.T) {
			owner, store, request := minimalCleanupPreparedRequest(t, "commit")
			wrapped := &minimalCleanupLoadStore{l8RuntimeOwnerTestStore: store}
			wrapped.hook = func(load int) error {
				if phase == "first-load" && load == 1 || phase == "second-load" && load == 2 {
					return errors.New("private store failure")
				}
				return nil
			}
			owner.opts.Store = wrapped
			before, transitions, snapshot := store.record, len(store.transitions), owner.cleanupSnapshot()
			calls := 0
			_, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
				calls++
				if phase == "panic" {
					panic("private callback panic")
				}
				if phase == "error" {
					return errors.New("private callback failure")
				}
				return nil
			})
			want := 1
			if phase == "first-load" {
				want = 0
			}
			if err == nil || (err.Error() != errL8RuntimeOwnerInvalid.Error() && err.Error() != errL8RuntimeOwnerProtocol.Error()) ||
				calls != want || store.record != before || len(store.transitions) != transitions || !snapshot.matches(owner) || store.retiredFinal {
				t.Fatal("failed barrier/readback advanced or retired cleanup")
			}
		})
	}
}

func TestMinimalCleanupPreflightOwnsRequestAcrossBarrier(t *testing.T) {
	owner, store, request := minimalCleanupPreflightFixture(t)
	_, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
		request.Packet.Body[0] ^= 1
		return nil
	})
	if err != nil || store.record.State != "absent" || owner.lastRequestBody[0] == request.Packet.Body[0] {
		t.Fatal("caller mutation replaced the validated owned request bytes")
	}
}

func TestMinimalCleanupPreflightCanceledMutexWaiterCannotDispatch(t *testing.T) {
	for _, afterBarrier := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial-lock", true: "relock"}[afterBarrier], func(t *testing.T) {
			owner, store, request := minimalCleanupPreparedRequest(t, "finalize")
			before, events, transitions := store.record, len(store.events), len(store.transitions)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			if !afterBarrier {
				owner.mu.Lock()
			}
			go func() {
				_, err := owner.handleControllerWithCleanup(ctx, request, func() error {
					close(entered)
					<-release
					return nil
				})
				done <- err
			}()
			if afterBarrier {
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					close(release)
					t.Fatal("barrier did not enter before relock test")
				}
				owner.mu.Lock()
			}
			cancel()
			close(release)
			owner.mu.Unlock()
			select {
			case err := <-done:
				wantLoads := 0
				if afterBarrier {
					wantLoads = 1
				}
				if !errors.Is(err, errL8RuntimeOwnerInvalid) || store.record != before ||
					len(store.transitions) != transitions || len(store.events) != events+wantLoads {
					t.Fatal("canceled mutex waiter observed or advanced cleanup")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled mutex waiter did not join")
			}
		})
	}
}
