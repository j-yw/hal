package firecrackerhost

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type l8RuntimeOwnerTestStore struct {
	record       firecrackerRuntimeOwnerRecordV1
	events       []string
	transitions  []firecrackerRuntimeOwnerRecordV1
	retiredZero  bool
	retiredFinal bool
}

func (store *l8RuntimeOwnerTestStore) Load(context.Context) (firecrackerRuntimeOwnerRecordV1, error) {
	store.events = append(store.events, "load")
	return store.record, nil
}
func (store *l8RuntimeOwnerTestStore) CreateGenesis(_ context.Context, next firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	store.events = append(store.events, "genesis")
	store.record = next
	return next, nil
}
func (store *l8RuntimeOwnerTestStore) Transition(_ context.Context, expected uint64, next firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	store.events = append(store.events, "transition")
	if store.record.Revision != expected || next.Revision != expected+1 {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	store.record = next
	store.transitions = append(store.transitions, next)
	return next, nil
}
func (store *l8RuntimeOwnerTestStore) RetireStartingZero(_ context.Context, expected uint64) error {
	store.events = append(store.events, "retire_zero")
	if expected != 0 || store.record.State != "starting" || store.record.Revision != 0 {
		return errL8RuntimeOwnerInvalid
	}
	store.retiredZero = true
	return nil
}
func (store *l8RuntimeOwnerTestStore) RetireFinalized(_ context.Context, expected uint64, commitID string) error {
	store.events = append(store.events, "retire_final")
	if store.record.State != "finalized" || store.record.Revision != expected || store.record.FinalizedCommitID != commitID {
		return errL8RuntimeOwnerInvalid
	}
	store.retiredFinal = true
	return nil
}

func TestL8RuntimeOwnerAdmissionPreservesLifecycleAndRotatesOneUseSecret(t *testing.T) {
	for _, state := range []string{"running", "stopping", "absent", "uncertain", "finalizing", "finalized"} {
		t.Run(state, func(t *testing.T) {
			record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
			record.State, record.ControllerState, record.Revision = state, "unclaimed", 7
			if state == "absent" || state == "uncertain" || state == "finalizing" || state == "finalized" {
				record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "direct_wait", 6, time.Unix(600, 0).UnixNano()
			}
			if state == "finalizing" || state == "finalized" {
				record.FinalizedCommitID = l8RuntimeOwnerTestToken(8)
				if state == "finalizing" {
					record.FinalizeTargetRevision = 8
				} else {
					record.FinalizeTargetRevision = 7
				}
			}
			store := &l8RuntimeOwnerTestStore{record: record}
			owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: store, ExpectedUID: 1000, RandomToken: func() (string, error) { return l8RuntimeOwnerTestToken(9), nil }, CommitKey: make([]byte, 32)})
			if err != nil {
				t.Fatal(err)
			}
			body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret})
			if err != nil {
				t.Fatal(err)
			}
			result, err := owner.AdmitController(context.Background(), 1000, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}})
			if err != nil || result.Packet.Status != l8RuntimeOwnerStatusOK {
				t.Fatalf("admit = %#v, %v", result, err)
			}
			if store.record.State != state || store.record.ControllerState != "controlled" || store.record.Revision != 8 || store.record.ReconnectSecret == record.ReconnectSecret || store.record.AbsenceRevision != record.AbsenceRevision {
				t.Fatalf("admitted record = %#v", store.record)
			}
			if err := owner.ControllerLost(context.Background()); err != nil {
				t.Fatal(err)
			}
			if store.record.State != state || store.record.ControllerState != "unclaimed" || store.record.AbsenceRevision != record.AbsenceRevision {
				t.Fatalf("lost record = %#v", store.record)
			}
		})
	}
}

func TestL8RuntimeOwnerFinalizeRetriesBothDurablePhasesAndPreservesReceiptAcrossReconnect(t *testing.T) {
	record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "absent", "controlled", 12
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "direct_wait", 12, time.Unix(12, 0).UnixNano()
	store := &l8RuntimeOwnerTestStore{record: record}
	closeCalls := 0
	closeFails := true
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store: store, ExpectedUID: 1000, CommitKey: make([]byte, 32),
		CloseNamespaces: func() error {
			closeCalls++
			if closeFails {
				closeFails = false
				return errors.New("private close uncertainty")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := l8RuntimeOwnerFinalizeRequestV1{
		ControllerSessionGeneration: l8RuntimeOwnerTestToken(1),
		AbsenceRevision:             record.AbsenceRevision,
		ObservedAtUnixNano:          record.AbsenceObservedAtUnixNano,
	}
	if _, err := owner.finalize(context.Background(), record, request); !errors.Is(err, errL8RuntimeOwnerInvalid) || store.record.State != "finalizing" {
		t.Fatalf("first finalize = %#v, %v", store.record, err)
	}
	ack, err := owner.finalize(context.Background(), store.record, request)
	if err != nil || store.record.State != "finalized" || store.record.Revision != ack.FinalizedRevision || closeCalls != 2 {
		t.Fatalf("retry finalize = %#v, %#v, calls %d, %v", store.record, ack, closeCalls, err)
	}
	transitions := len(store.transitions)
	replayed, err := owner.finalize(context.Background(), store.record, request)
	if err != nil || replayed != ack || len(store.transitions) != transitions || closeCalls != 2 {
		t.Fatalf("finalized replay = %#v, transitions %d, calls %d, %v", replayed, len(store.transitions), closeCalls, err)
	}

	store.record.ControllerState = "unclaimed"
	store.record.Revision++
	owner.opts.RandomToken = func() (string, error) { return l8RuntimeOwnerTestToken(byte(20 + store.record.Revision)), nil }
	body, _ := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{
		SupervisorGeneration: store.record.SupervisorGeneration,
		RuntimeGeneration:    store.record.RuntimeGeneration,
		RecordRevision:       store.record.Revision,
		ReconnectSecret:      store.record.ReconnectSecret,
	})
	admitted, err := owner.AdmitController(context.Background(), 1000, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}})
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := decodeL8RuntimeOwnerHandshakeAck(admitted.Packet.Body)
	if err != nil {
		t.Fatal(err)
	}
	commitBody, _ := encodeL8RuntimeOwnerCommitRequest(l8RuntimeOwnerCommitRequestV1{
		ControllerSessionGeneration: handshake.ControllerSessionGeneration,
		CommitID:                    ack.CommitID,
		FinalizedRevision:           ack.FinalizedRevision,
	})
	committed, err := owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: 1, Body: commitBody}})
	if err != nil || !committed.Exit || !store.retiredFinal {
		t.Fatalf("commit after reconnect = %#v, %v", committed, err)
	}
}

func TestL8RuntimeOwnerReplayRequiresByteIdenticalRequest(t *testing.T) {
	record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "absent", "controlled", 5
	store := &l8RuntimeOwnerTestStore{record: record}
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: store, ExpectedUID: 1000, CommitKey: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	owner.sessionGeneration = l8RuntimeOwnerTestToken(1)
	body, _ := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: owner.sessionGeneration})
	request := l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Sequence: 1, Body: body}}
	if _, err := owner.HandleController(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	mutated := request
	mutated.Packet.Body = append([]byte(nil), body...)
	mutated.Packet.Body[0] ^= 1
	if _, err := owner.HandleController(context.Background(), mutated); !errors.Is(err, errL8RuntimeOwnerProtocol) {
		t.Fatalf("mutated replay = %v", err)
	}
}

func TestL8RuntimeOwnerAdmissionRejectsPeerSecretRevisionAndReplayWithoutMutation(t *testing.T) {
	record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "running", "unclaimed", 2
	for _, scenario := range []struct {
		name   string
		uid    uint32
		mutate func(*l8RuntimeOwnerHandshakeV1)
	}{
		{name: "wrong uid", uid: 1001},
		{name: "wrong secret", uid: 1000, mutate: func(value *l8RuntimeOwnerHandshakeV1) { value.ReconnectSecret = l8RuntimeOwnerTestToken(31) }},
		{name: "wrong revision", uid: 1000, mutate: func(value *l8RuntimeOwnerHandshakeV1) { value.RecordRevision++ }},
		{name: "wrong generation", uid: 1000, mutate: func(value *l8RuntimeOwnerHandshakeV1) { value.SupervisorGeneration = l8RuntimeOwnerTestToken(30) }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			store := &l8RuntimeOwnerTestStore{record: record}
			owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: store, ExpectedUID: 1000, RandomToken: func() (string, error) { return l8RuntimeOwnerTestToken(9), nil }, CommitKey: make([]byte, 32)})
			if err != nil {
				t.Fatal(err)
			}
			handshake := l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret}
			if scenario.mutate != nil {
				scenario.mutate(&handshake)
			}
			body, _ := encodeL8RuntimeOwnerHandshake(handshake)
			if _, err := owner.AdmitController(context.Background(), scenario.uid, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}}); !errors.Is(err, errL8RuntimeOwnerProtocol) || err.Error() != errL8RuntimeOwnerProtocol.Error() {
				t.Fatalf("admit = %v", err)
			}
			if store.record != record || len(store.transitions) != 0 {
				t.Fatalf("record mutated = %#v", store.record)
			}
		})
	}
}

func TestL8RuntimeOwnerAbortStartIsCausalAtRevisionZeroAndContainedAtRevisionOne(t *testing.T) {
	for _, revision := range []uint64{0, 1} {
		t.Run(string(rune('0'+revision)), func(t *testing.T) {
			record := l8RuntimeOwnerTestGenesis(l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef"))
			record.Revision = revision
			if revision == 1 {
				record.FirecrackerPID, record.FirecrackerStartTime = 5001, 7001
			}
			store := &l8RuntimeOwnerTestStore{record: record}
			var events []string
			owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: store, ExpectedUID: 1000, AbortStartingZero: func() error { events = append(events, "prove_no_fork_close_assets"); return nil }, ContainChild: func() (l8RuntimeOwnerAbsenceObservation, error) {
				events = append(events, "contain")
				return l8RuntimeOwnerAbsenceObservation{Kind: 1, Revision: 3, ObservedAt: time.Unix(1, 0)}, nil
			}, CommitKey: make([]byte, 32)})
			if err != nil {
				t.Fatal(err)
			}
			result, err := owner.AbortStart(context.Background(), 1000, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeAbortStart, Sequence: 1}})
			if err != nil || !result.Exit {
				t.Fatalf("abort = %#v, %v", result, err)
			}
			if revision == 0 && (!store.retiredZero || !reflect.DeepEqual(events, []string{"prove_no_fork_close_assets"})) {
				t.Fatalf("rev0 = %v %#v", events, store)
			}
			if revision == 1 && (!reflect.DeepEqual(events, []string{"contain"}) || store.record.State != "absent" || store.record.Revision != 3) {
				t.Fatalf("rev1 = %v %#v", events, store.record)
			}
		})
	}
}

func TestL8RuntimeOwnerStopReinspectsAndPersistsFreshAbsenceAcrossReconnect(t *testing.T) {
	record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "absent", "controlled", 9
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "replacement_proc", 9, time.Unix(9, 0).UnixNano()
	store := &l8RuntimeOwnerTestStore{record: record}
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: store, ExpectedUID: 1000, ReinspectAbsence: func() (l8RuntimeOwnerAbsenceObservation, error) {
		return l8RuntimeOwnerAbsenceObservation{Kind: 2, Revision: 10, ObservedAt: time.Unix(10, 0)}, nil
	}, CommitKey: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(1)})
	first, err := owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 1, Body: body}})
	if err != nil || first.Packet.Status != 0 || store.record.AbsenceRevision != 10 || store.record.AbsenceObservedAtUnixNano != time.Unix(10, 0).UnixNano() {
		t.Fatalf("first inspect = %#v %#v %v", first, store.record, err)
	}
	second, err := owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 2, Body: body}})
	if err != nil || second.Packet.Sequence != 2 || store.record.AbsenceRevision != 11 {
		t.Fatalf("second inspect = %#v %#v %v", second, store.record, err)
	}
}

func TestL8RuntimeOwnerReplayReissuesFreshNamespaceDuplicatesAndClosePreservesOriginals(t *testing.T) {
	record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "absent", "unclaimed", 5
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "direct_wait", 5, time.Unix(5, 0).UnixNano()
	store := &l8RuntimeOwnerTestStore{record: record}
	tokenIndex := byte(20)
	duplicateCall := 0
	closedOriginals := 0
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store: store, ExpectedUID: 1000, CommitKey: make([]byte, 32),
		RandomToken: func() (string, error) { tokenIndex++; return l8RuntimeOwnerTestToken(tokenIndex), nil },
		DuplicateNamespaces: func() ([]int, error) {
			duplicateCall++
			return []int{100 + duplicateCall*2, 101 + duplicateCall*2}, nil
		},
		CloseNamespaces: func() error { closedOriginals++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	handshakeBody, _ := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration, RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret})
	admitted, err := owner.AdmitController(context.Background(), 1000, l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: handshakeBody}})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := decodeL8RuntimeOwnerHandshakeAck(admitted.Packet.Body)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, _ := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: ack.ControllerSessionGeneration})
	inspect := l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Sequence: 1, Body: requestBody}}
	first, err := owner.HandleController(context.Background(), inspect)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := owner.HandleController(context.Background(), inspect)
	if err != nil || !reflect.DeepEqual(duplicate.Packet, first.Packet) {
		t.Fatalf("inspect replay = %#v / %#v, %v", first, duplicate, err)
	}
	acquire := l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeAcquireNamespaces, Sequence: 2, Body: requestBody}}
	rightsOne, err := owner.HandleController(context.Background(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	rightsTwo, err := owner.HandleController(context.Background(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rightsOne.Packet, rightsTwo.Packet) || reflect.DeepEqual(rightsOne.Files, rightsTwo.Files) || duplicateCall != 2 || closedOriginals != 0 {
		t.Fatalf("namespace replay = %#v / %#v calls %d closed %d", rightsOne, rightsTwo, duplicateCall, closedOriginals)
	}
	if _, err := owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Sequence: 4, Body: requestBody}}); !errors.Is(err, errL8RuntimeOwnerProtocol) {
		t.Fatalf("skipped sequence = %v", err)
	}
	closed, err := owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeClose, Sequence: 3, Body: requestBody}})
	if err != nil || closed.Exit || closedOriginals != 0 || store.record.State != "absent" || store.record.ControllerState != "unclaimed" {
		t.Fatalf("close = %#v record %#v originals %d err %v", closed, store.record, closedOriginals, err)
	}
}

func TestL8RuntimeOwnerFinalizeIsCrashSafeAndCommitRetiresOnlyFinalized(t *testing.T) {
	record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "absent", "controlled", 12
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "direct_wait", 12, time.Unix(12, 0).UnixNano()
	store := &l8RuntimeOwnerTestStore{record: record}
	var events []string
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{Store: store, ExpectedUID: 1000, CloseNamespaces: func() error { events = append(events, "close_namespace_originals"); return nil }, CommitKey: []byte("01234567890123456789012345678901")})
	if err != nil {
		t.Fatal(err)
	}
	requestBody, _ := encodeL8RuntimeOwnerFinalizeRequest(l8RuntimeOwnerFinalizeRequestV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(1), AbsenceRevision: 12, ObservedAtUnixNano: time.Unix(12, 0).UnixNano()})
	result, err := owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeFinalize, Sequence: 1, Body: requestBody}})
	if err != nil || store.record.State != "finalized" || len(store.transitions) != 2 || store.transitions[0].State != "finalizing" || store.transitions[1].State != "finalized" || !reflect.DeepEqual(events, []string{"close_namespace_originals"}) {
		t.Fatalf("finalize = %#v %#v %v events %v", result, store.transitions, err, events)
	}
	ack, err := decodeL8RuntimeOwnerFinalizeAck(result.Packet.Body)
	if err != nil {
		t.Fatal(err)
	}
	commitBody, _ := encodeL8RuntimeOwnerCommitRequest(l8RuntimeOwnerCommitRequestV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(1), CommitID: ack.CommitID, FinalizedRevision: ack.FinalizedRevision})
	committed, err := owner.HandleController(context.Background(), l8RuntimeOwnerReceivedPacketV1{Packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: 2, Body: commitBody}})
	if err != nil || !committed.Exit || !store.retiredFinal {
		t.Fatalf("commit = %#v %v retired %t", committed, err, store.retiredFinal)
	}
}
