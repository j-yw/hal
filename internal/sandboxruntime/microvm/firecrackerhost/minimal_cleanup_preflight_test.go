package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func minimalCleanupFinalizePacket(t *testing.T, owner *l8RuntimeOwnerSupervisor, store *l8RuntimeOwnerTestStore, sequence uint64) l8RuntimeOwnerReceivedPacketV1 {
	t.Helper()
	body, err := encodeL8RuntimeOwnerFinalizeRequest(l8RuntimeOwnerFinalizeRequestV1{
		ControllerSessionGeneration: owner.sessionGeneration, AbsenceRevision: store.record.AbsenceRevision,
		ObservedAtUnixNano: store.record.AbsenceObservedAtUnixNano,
	})
	if err != nil {
		t.Fatal(err)
	}
	return minimalCleanupPacket(t, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeFinalize, Sequence: sequence, Body: body})
}

func minimalCleanupCommitPacket(t *testing.T, owner *l8RuntimeOwnerSupervisor, store *l8RuntimeOwnerTestStore, sequence uint64) l8RuntimeOwnerReceivedPacketV1 {
	t.Helper()
	body, err := encodeL8RuntimeOwnerCommitRequest(l8RuntimeOwnerCommitRequestV1{
		ControllerSessionGeneration: owner.sessionGeneration, CommitID: store.record.FinalizedCommitID,
		FinalizedRevision: store.record.FinalizeTargetRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	return minimalCleanupPacket(t, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: sequence, Body: body})
}

func minimalCleanupPreparedRequest(t *testing.T, phase string) (*l8RuntimeOwnerSupervisor, *l8RuntimeOwnerTestStore, l8RuntimeOwnerReceivedPacketV1) {
	t.Helper()
	owner, store, request := minimalCleanupPreflightFixture(t)
	owner.opts.CloseNamespaces = func() error { return nil }
	if phase == "stop" {
		return owner, store, request
	}
	if _, err := owner.HandleController(context.Background(), request); err != nil {
		t.Fatal("actual StopReap setup failed")
	}
	request = minimalCleanupFinalizePacket(t, owner, store, 2)
	if phase == "finalize" {
		return owner, store, request
	}
	if _, err := owner.HandleController(context.Background(), request); err != nil {
		t.Fatal("actual Finalize setup failed")
	}
	return owner, store, minimalCleanupCommitPacket(t, owner, store, 3)
}

func TestMinimalCleanupPreflightMatchesLegacyTransitionsAndReplay(t *testing.T) {
	for _, phase := range []string{"stop", "finalize", "commit"} {
		t.Run(phase, func(t *testing.T) {
			legacy, legacyStore, legacyRequest := minimalCleanupPreparedRequest(t, phase)
			owner, store, request := minimalCleanupPreparedRequest(t, phase)
			before := store.record
			legacyStore.events, store.events = nil, nil
			legacyCommits, commits, barrierCalls, closeCalls := 0, 0, 0, 0
			legacy.opts.commitID = func(key []byte, digest [32]byte, revision uint64) (string, error) {
				legacyCommits++
				return l8RuntimeOwnerCommitID(key, digest, revision)
			}
			owner.opts.commitID = func(key []byte, digest [32]byte, revision uint64) (string, error) {
				commits++
				return l8RuntimeOwnerCommitID(key, digest, revision)
			}
			owner.opts.CloseNamespaces = func() error {
				closeCalls++
				if barrierCalls != 1 {
					t.Error("namespace close preceded selected shutdown")
				}
				return nil
			}
			want, wantErr := legacy.HandleController(context.Background(), legacyRequest)
			got, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
				barrierCalls++
				if !owner.mu.TryLock() {
					t.Error("barrier held owner mutex")
					return errL8RuntimeOwnerInvalid
				}
				defer owner.mu.Unlock()
				if store.record != before || store.retiredFinal {
					t.Error("cleanup mutation preceded barrier")
				}
				return nil
			})
			if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) || store.record != legacyStore.record ||
				!reflect.DeepEqual(store.transitions, legacyStore.transitions) || store.retiredFinal != legacyStore.retiredFinal ||
				commits != legacyCommits || barrierCalls != 1 {
				t.Fatalf("selected/default divergence: selected=%v legacy=%v commits=%d/%d barrier=%d", err, wantErr, commits, legacyCommits, barrierCalls)
			}
			if len(store.events) != len(legacyStore.events)+1 || store.events[0] != "load" || !reflect.DeepEqual(store.events[1:], legacyStore.events) {
				t.Fatalf("selected must add only its one revalidation Load: selected=%v legacy=%v", store.events, legacyStore.events)
			}
			if phase == "finalize" && (commits != 1 || closeCalls != 1) {
				t.Fatal("Finalize recomputed its commit or closed namespaces twice")
			}
			prior, eventCount, commitCount := store.record, len(store.events), commits
			replay, err := owner.handleControllerWithCleanup(context.Background(), request, func() error { t.Error("cached replay entered barrier"); return nil })
			if err != nil || replay.Exit || len(replay.Files) != 0 || replay.Packet.Opcode != got.Packet.Opcode ||
				replay.Packet.Sequence != got.Packet.Sequence || !bytes.Equal(replay.Packet.Body, got.Packet.Body) ||
				store.record != prior || len(store.events) != eventCount || commits != commitCount {
				t.Fatal("cached replay changed existing packet/Exit/observation semantics")
			}
		})
	}
}

func TestMinimalCleanupPreflightRejectsBeforeShutdown(t *testing.T) {
	for _, test := range []struct {
		name, phase string
		mutate      func(*l8RuntimeOwnerSupervisor, *l8RuntimeOwnerTestStore, *l8RuntimeOwnerReceivedPacketV1)
	}{
		{"session", "stop", func(_ *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, r *l8RuntimeOwnerReceivedPacketV1) {
			r.Packet.Body[0] ^= 1
		}},
		{"sequence", "stop", func(_ *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, r *l8RuntimeOwnerReceivedPacketV1) {
			r.Packet.Sequence++
		}},
		{"status", "stop", func(_ *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, r *l8RuntimeOwnerReceivedPacketV1) {
			r.Packet.Status = l8RuntimeOwnerStatusRejected
		}},
		{"rights", "stop", func(_ *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, r *l8RuntimeOwnerReceivedPacketV1) {
			r.Files = append(r.Files, nil)
		}},
		{"oversize", "stop", func(_ *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, r *l8RuntimeOwnerReceivedPacketV1) {
			r.Packet.Body = make([]byte, 513)
		}},
		{"unclaimed", "stop", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.ControllerState = "unclaimed"
		}},
		{"wrong-state", "stop", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.State = "finalized"
		}},
		{"missing-containment", "stop", func(o *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			o.opts.ContainChild = nil
		}},
		{"wrong-latch", "stop", func(o *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			o.admittedSession = l8RuntimeOwnerTestToken(101)
		}},
		{"stale-absence", "finalize", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.AbsenceRevision++
		}},
		{"stale-time", "finalize", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.AbsenceObservedAtUnixNano++
		}},
		{"invalid-seed", "finalize", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.SeedCorrelationDigest = "invalid"
		}},
		{"overflow", "finalize", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.Revision = ^uint64(0)
		}},
		{"bad-finalizing-target", "finalize", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.State, s.record.FinalizeTargetRevision, s.record.FinalizedCommitID = "finalizing", 0, l8RuntimeOwnerTestToken(55)
		}},
		{"bad-finalized-hmac", "finalize", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.State, s.record.FinalizeTargetRevision, s.record.FinalizedCommitID = "finalized", s.record.Revision, l8RuntimeOwnerTestToken(55)
		}},
		{"commit-function-error", "finalize", func(o *l8RuntimeOwnerSupervisor, _ *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			o.opts.commitID = func([]byte, [32]byte, uint64) (string, error) { return "", errors.New("private canary") }
		}},
		{"wrong-commit", "commit", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.FinalizedCommitID = l8RuntimeOwnerTestToken(44)
		}},
		{"wrong-commit-target", "commit", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.FinalizeTargetRevision++
		}},
		{"not-finalized", "commit", func(_ *l8RuntimeOwnerSupervisor, s *l8RuntimeOwnerTestStore, _ *l8RuntimeOwnerReceivedPacketV1) {
			s.record.State = "absent"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner, store, request := minimalCleanupPreparedRequest(t, test.phase)
			test.mutate(owner, store, &request)
			before, transitions, snapshot := store.record, len(store.transitions), owner.cleanupSnapshot()
			calls := 0
			_, err := owner.handleControllerWithCleanup(context.Background(), request, func() error { calls++; return nil })
			if err == nil || strings.Contains(err.Error(), "private canary") || calls != 0 || store.record != before ||
				len(store.transitions) != transitions || store.retiredFinal || store.retiredZero || !snapshot.matches(owner) {
				t.Fatalf("invalid request performed selected effects: err=%v barrier=%d", err, calls)
			}
		})
	}
}

func TestMinimalCleanupPreflightRequiresActualAdmissionAndPreservesLegacyAdoption(t *testing.T) {
	for _, inferred := range []bool{false, true} {
		t.Run(map[bool]string{false: "unestablished", true: "legacy-inferred"}[inferred], func(t *testing.T) {
			original, store, request := minimalCleanupPreflightFixture(t)
			// A new FSM over controlled legacy fixture metadata has never admitted
			// a controller, even if its default handler adopts a request session.
			owner, err := newL8RuntimeOwnerSupervisor(original.opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { clear(owner.opts.CommitKey) })
			if inferred {
				inspect := request
				inspect.Packet.Opcode = l8RuntimeOwnerOpcodeInspect
				if _, err := owner.HandleController(context.Background(), inspect); err != nil || owner.sessionGeneration == "" {
					t.Fatal("legacy implicit session adoption prerequisite changed")
				}
				request.Packet.Sequence++
			}
			before, events, snapshot := store.record, len(store.events), owner.cleanupSnapshot()
			calls := 0
			if _, err := owner.handleControllerWithCleanup(context.Background(), request, func() error { calls++; return nil }); err == nil ||
				calls != 0 || store.record != before || len(store.events) != events || !snapshot.matches(owner) {
				t.Fatal("non-admitted session authorized selected shutdown")
			}
			if _, err := owner.handleControllerWithCleanup(context.Background(), request, nil); err != nil || store.record.State != "absent" {
				t.Fatal("nil barrier changed legacy implicit-adoption cleanup")
			}
		})
	}
}

func TestMinimalCleanupPreflightFinalizeFailureKeepsOriginalCheckpoints(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "close-error", true: "missing-close"}[missing], func(t *testing.T) {
			owner, store, request := minimalCleanupPreparedRequest(t, "finalize")
			before := store.record
			closeCalls, commits, barriers := 0, 0, 0
			owner.opts.CloseNamespaces = func() error { closeCalls++; return errors.New("private close canary") }
			if missing {
				owner.opts.CloseNamespaces = nil
			}
			owner.opts.commitID = func(key []byte, digest [32]byte, revision uint64) (string, error) {
				commits++
				return l8RuntimeOwnerCommitID(key, digest, revision)
			}
			barrier := func() error { barriers++; return nil }
			if _, err := owner.handleControllerWithCleanup(context.Background(), request, barrier); !errors.Is(err, errL8RuntimeOwnerInvalid) ||
				store.record.State != "finalizing" || store.record.Revision != before.Revision+1 || commits != 1 || barriers != 1 || owner.lastSequence != 1 {
				t.Fatal("namespace close failure lost its original durable finalizing checkpoint")
			}
			if closeCalls != map[bool]int{false: 1, true: 0}[missing] {
				t.Fatal("close call count changed")
			}
			owner.opts.CloseNamespaces = func() error { closeCalls++; return nil }
			result, err := owner.handleControllerWithCleanup(context.Background(), request, barrier)
			if err != nil || store.record.State != "finalized" || commits != 2 || barriers != 2 {
				t.Fatal("same-owner finalizing retry failed")
			}
			request.Packet.Sequence++ // Fresh finalized Finalize, not cached replay.
			again, err := owner.handleControllerWithCleanup(context.Background(), request, barrier)
			if err != nil || !bytes.Equal(again.Packet.Body, result.Packet.Body) || commits != 3 || barriers != 3 ||
				closeCalls != map[bool]int{false: 2, true: 1}[missing] {
				t.Fatal("fresh finalized Finalize changed its ack or closed namespaces again")
			}
		})
	}
}

type minimalCleanupLoadStore struct {
	*l8RuntimeOwnerTestStore
	loads int
	hook  func(int) error
}

func (store *minimalCleanupLoadStore) Load(ctx context.Context) (firecrackerRuntimeOwnerRecordV1, error) {
	store.loads++
	if store.hook != nil {
		if err := store.hook(store.loads); err != nil {
			return firecrackerRuntimeOwnerRecordV1{}, err
		}
	}
	return store.l8RuntimeOwnerTestStore.Load(ctx)
}

type minimalCleanupDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (ctx *minimalCleanupDeadlineContext) Deadline() (time.Time, bool) { return ctx.deadline, true }

func TestMinimalCleanupPreflightCancellationAtEveryReadBoundary(t *testing.T) {
	for _, phase := range []string{"entry", "first-load", "barrier", "second-load"} {
		for _, deadlineOnly := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "-cancel", true: "-deadline"}[deadlineOnly], func(t *testing.T) {
				owner, store, request := minimalCleanupPreparedRequest(t, "finalize")
				base, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx := &minimalCleanupDeadlineContext{Context: base, deadline: time.Now().Add(time.Minute)}
				expire := func() {
					if deadlineOnly {
						ctx.deadline = time.Now().Add(-time.Second) // Err remains nil.
					} else {
						cancel()
					}
				}
				wrapped := &minimalCleanupLoadStore{l8RuntimeOwnerTestStore: store}
				wrapped.hook = func(load int) error {
					if phase == "first-load" && load == 1 || phase == "second-load" && load == 2 {
						expire()
					}
					return nil
				}
				owner.opts.Store = wrapped
				before, transitions, snapshot := store.record, len(store.transitions), owner.cleanupSnapshot()
				if phase == "entry" {
					expire()
				}
				barriers := 0
				_, err := owner.handleControllerWithCleanup(ctx, request, func() error {
					barriers++
					if phase == "barrier" {
						expire()
					}
					return nil
				})
				want := map[string]int{"entry": 0, "first-load": 0, "barrier": 1, "second-load": 1}[phase]
				if !errors.Is(err, errL8RuntimeOwnerInvalid) || barriers != want || store.record != before ||
					len(store.transitions) != transitions || !snapshot.matches(owner) {
					t.Fatalf("expired caller advanced cleanup: err=%v barriers=%d want=%d", err, barriers, want)
				}
			})
		}
	}
}

func TestMinimalCleanupPreflightRetainedStopStatesAndSessionReset(t *testing.T) {
	for _, state := range []string{"stopping", "uncertain", "absent"} {
		t.Run(state, func(t *testing.T) {
			owner, store, request := minimalCleanupPreflightFixture(t)
			store.record.State = state // Existing fake recovery-state fixture.
			calls, barriers := 0, 0
			observe := func() (l8RuntimeOwnerAbsenceObservation, error) {
				calls++
				if barriers != 1 {
					t.Error("observation preceded selected shutdown")
				}
				return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: time.Unix(900, 0)}, nil
			}
			owner.opts.ContainChild, owner.opts.ReinspectAbsence = observe, observe
			if _, err := owner.handleControllerWithCleanup(context.Background(), request, func() error { barriers++; return nil }); err != nil || calls != 1 || store.record.State != "absent" {
				t.Fatal("valid retained StopReap state failed")
			}
		})
	}
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "controller-lost"}[lost], func(t *testing.T) {
			owner, store, request := minimalCleanupPreflightFixture(t)
			barrier := func() error { t.Error("non-cleanup request entered shutdown"); return nil }
			if lost {
				if err := owner.ControllerLost(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else {
				request.Packet.Opcode = l8RuntimeOwnerOpcodeClose
				if _, err := owner.handleControllerWithCleanup(context.Background(), request, barrier); err != nil {
					t.Fatal(err)
				}
				before := len(store.events)
				if _, err := owner.handleControllerWithCleanup(context.Background(), request, barrier); err != nil || len(store.events) != before {
					t.Fatal("cached Close replay lost its no-Load semantics after session reset")
				}
			}
			if owner.admittedSession != "" || owner.sessionGeneration != "" || store.record.ControllerState != "unclaimed" {
				t.Fatal("successful owner reset retained selected admission provenance")
			}
		})
	}
}

func TestMinimalCleanupPreflightRejectsWithoutConsumingCallerRights(t *testing.T) {
	owner, _, request := minimalCleanupPreflightFixture(t)
	file, err := os.CreateTemp(t.TempDir(), "received-right")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	request.Files = []*os.File{file}
	if _, err := owner.handleControllerWithCleanup(context.Background(), request, func() error { t.Error("rights reached barrier"); return nil }); err == nil {
		t.Fatal("unexpected rights accepted")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("rejection consumed the caller-owned descriptor")
	}
}
