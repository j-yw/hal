//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"
)

// This deliberately composes existing fake boundaries. It is passing evidence
// about the reusable supervisor FSM, NOT a production Jailer subprocess or
// selected minimal-config implementation. Legacy seed/token fixtures exercise
// only that existing FSM; they must never become a pre-credential launch seed.
func TestJailerRecoveryExistingSupervisorKeepsCoordinatorAcrossReconnect(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		name := "terminal"
		if failCleanup {
			name = "cleanup_failure_then_reconnect"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			events := []string{}
			root := &coordinatorFakeRoot{events: &events}
			coordinator := coordinatorForStateTest(&events, root, &coordinatorFakeLifecycle{events: &events})
			authority, identityStore := newFakeJailerIdentityAuthority()
			coordinator.deps.identity = authority
			identityStore.hook = func(operation string) {
				if operation == "sync" {
					record, err := readJailerIdentityRecord(identityStore.snapshot(), authority.slot)
					if err != nil {
						t.Fatal(err)
					}
					if record.State == "idle" {
						events = append(events, "identity-idle")
					}
				}
			}
			defer func() { _ = coordinator.generationIdentityForTest().close() }()
			request := validStrictJailerCoordinatorRequest(t)
			seed := l8RuntimeOwnerTestSeed()
			seed.RuntimeID = request.runtimeID
			record := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
			store := &l8RuntimeOwnerTestStore{}
			var session strictJailerSession
			var retainedGeneration *strictJailerCoordinatorGeneration
			var terminal bool
			var namespaceCloses int
			nextToken := byte(10)
			owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
				Store: store, GenesisRecord: l8RuntimeOwnerTestGenesis(record), ExpectedUID: 1000,
				CommitKey: make([]byte, 32),
				RandomToken: func() (string, error) {
					nextToken++
					return l8RuntimeOwnerTestToken(nextToken), nil
				},
				StartChild: func() (l8RuntimeOwnerStartedChild, error) {
					var err error
					session, err = coordinator.start(ctx, request)
					if err != nil {
						return l8RuntimeOwnerStartedChild{}, err
					}
					retainedGeneration = coordinator.generation
					return l8RuntimeOwnerStartedChild{
						Observation: l8RuntimeOwnerProcessObservation{PID: record.FirecrackerPID, StartTime: record.FirecrackerStartTime},
						Release:     func() error { return nil },
						Abort:       func() error { return coordinator.stop(ctx, session) },
					}, nil
				},
				ContainChild: func() (l8RuntimeOwnerAbsenceObservation, error) {
					var err error
					if coordinator.generation.state == strictJailerCoordinatorActive {
						err = coordinator.stop(ctx, session)
					} else {
						err = coordinator.retryCleanup(ctx, session)
					}
					if err != nil {
						return l8RuntimeOwnerAbsenceObservation{}, err
					}
					terminal = true
					return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: seed.IssuedAt.Add(time.Minute)}, nil
				},
				CloseNamespaces: func() error {
					if !terminal || coordinator.generation != nil {
						return errors.New("fixture cleanup is not terminal")
					}
					namespaceCloses++
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			// The FSM checks only descriptor count; no descriptors, namespace
			// operations, processes, or runtime commands are created here.
			_, err = owner.HandleBootstrap(ctx, 1000, l8RuntimeOwnerReceivedPacketV1{
				Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: encodeL8RuntimeOwnerNamespaceCorrelation(l8RuntimeOwnerNamespaceCorrelationV1{})},
				Files:  []*os.File{nil, nil},
			})
			if err != nil || retainedGeneration == nil {
				t.Fatal("fake bootstrap", err)
			}
			first := jailerRecoveryAdmitFakeController(t, owner, store)
			beforeLoss := slices.Clone(events)
			if err := owner.ControllerLost(ctx); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(events, beforeLoss) || coordinator.generation != retainedGeneration {
				t.Fatal("daemon-client loss discarded or cleaned the retained owner")
			}
			busy, err := readJailerIdentityRecord(identityStore.snapshot(), authority.slot)
			if err != nil || busy.State != "busy" || retainedGeneration.identity.verify(ctx) != nil || retainedGeneration.staging.verifyOwnedRoot() != nil || retainedGeneration.cgroup.verifyForLaunch() != nil {
				t.Fatal("client loss revoked exact retained leases", err)
			}
			second := jailerRecoveryAdmitFakeController(t, owner, store)
			oldBody, _ := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: first})
			if _, err := owner.HandleController(ctx, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 1, Body: oldBody}}); err == nil {
				t.Fatal("stale daemon session controlled reconnected owner")
			}
			if failCleanup {
				root.removeErrors = []error{errors.New("fixture removal failure"), nil}
				if _, err := jailerRecoveryFakeStop(owner, second); err == nil || store.record.State != "uncertain" || coordinator.generation != retainedGeneration {
					t.Fatal("failed cleanup published absence or lost ownership", err)
				}
				if _, err := owner.finalize(ctx, store.record, l8RuntimeOwnerFinalizeRequestV1{}); err == nil || namespaceCloses != 0 {
					t.Fatal("uncertain cleanup finalized")
				}
				if _, err := authority.reserve(ctx, request.runtimeID, request.config.SHA256, authority.slot.uid, authority.slot.gid); err == nil {
					t.Fatal("failed cleanup reused identity")
				}
				if err := owner.ControllerLost(ctx); err != nil {
					t.Fatal(err)
				}
				second = jailerRecoveryAdmitFakeController(t, owner, store)
			}
			stopped, err := jailerRecoveryFakeStop(owner, second)
			if err != nil || store.record.State != "absent" || !terminal || coordinator.generation != nil {
				t.Fatal("reconnected owner did not finish exact cleanup", err)
			}
			beforeReplay := slices.Clone(events)
			if replay, err := jailerRecoveryFakeStop(owner, second); err != nil || !slices.Equal(replay.Packet.Body, stopped.Packet.Body) || !slices.Equal(events, beforeReplay) {
				t.Fatal("stop replay repeated resource cleanup", err)
			}
			finalizeBody, _ := encodeL8RuntimeOwnerFinalizeRequest(l8RuntimeOwnerFinalizeRequestV1{ControllerSessionGeneration: second, AbsenceRevision: store.record.AbsenceRevision, ObservedAtUnixNano: store.record.AbsenceObservedAtUnixNano})
			finalized, err := owner.HandleController(ctx, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeFinalize, Sequence: 2, Body: finalizeBody}})
			if err != nil {
				t.Fatal(err)
			}
			ack, err := decodeL8RuntimeOwnerFinalizeAck(finalized.Packet.Body)
			if err != nil || namespaceCloses != 1 {
				t.Fatal("missing terminal receipt", err)
			}
			if err := owner.ControllerLost(ctx); err != nil {
				t.Fatal(err)
			}
			third := jailerRecoveryAdmitFakeController(t, owner, store)
			commitBody, _ := encodeL8RuntimeOwnerCommitRequest(l8RuntimeOwnerCommitRequestV1{ControllerSessionGeneration: third, CommitID: ack.CommitID, FinalizedRevision: ack.FinalizedRevision})
			committed, err := owner.HandleController(ctx, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: 1, Body: commitBody}})
			if err != nil || !committed.Exit || !store.retiredFinal || namespaceCloses != 1 {
				t.Fatal("commit after second reconnect", err)
			}
			idle, err := readJailerIdentityRecord(identityStore.snapshot(), authority.slot)
			rootIndex, forgetIndex, idleIndex := slices.Index(events, "release"), slices.Index(events, "forget"), slices.Index(events, "identity-idle")
			if err != nil || idle.State != "idle" || identityStore.owner != nil || rootIndex < 0 || forgetIndex < rootIndex || idleIndex < forgetIndex {
				t.Fatal("terminal identity release lost cleanup ordering", err)
			}
			for _, once := range []string{"start", "forget", "identity-idle"} {
				count := 0
				for _, event := range events {
					if event == once {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("%s count=%d events=%v", once, count, events)
				}
			}
			successor, err := authority.reserve(ctx, request.runtimeID, request.config.SHA256, authority.slot.uid, authority.slot.gid)
			if err != nil {
				t.Fatal("terminal identity was not reusable", err)
			}
			defer successor.close()
			beforeStale := slices.Clone(events)
			if _, err := jailerRecoveryFakeStop(owner, third); err == nil || !slices.Equal(events, beforeStale) || successor.verify(ctx) != nil {
				t.Fatal("old terminal owner affected successor")
			}
		})
	}
}

func jailerRecoveryAdmitFakeController(t *testing.T, owner *l8RuntimeOwnerSupervisor, store *l8RuntimeOwnerTestStore) string {
	t.Helper()
	record := store.record
	body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret})
	if err != nil {
		t.Fatal(err)
	}
	result, err := owner.AdmitController(context.Background(), 1000, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := decodeL8RuntimeOwnerHandshakeAck(result.Packet.Body)
	if err != nil {
		t.Fatal(err)
	}
	return ack.ControllerSessionGeneration
}

func jailerRecoveryFakeStop(owner *l8RuntimeOwnerSupervisor, session string) (l8RuntimeOwnerControlResult, error) {
	body, err := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: session})
	if err != nil {
		return l8RuntimeOwnerControlResult{}, err
	}
	return owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 1, Body: body}})
}
