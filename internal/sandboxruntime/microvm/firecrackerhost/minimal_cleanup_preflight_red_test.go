package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Actual packet codecs, AdmitController and the existing FSM over its ordinary
// fake store. The UID argument and containment observation are injected fixture
// facts, not a live peer, process, namespace or selected runtime constructor.
func minimalCleanupPreflightFixture(t *testing.T) (*l8RuntimeOwnerSupervisor, *l8RuntimeOwnerTestStore, l8RuntimeOwnerReceivedPacketV1) {
	t.Helper()
	record := l8RuntimeOwnerTestRecord(t, l8RuntimeOwnerTestSeed(), "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "running", "unclaimed", 2
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "", 0, 0
	store := &l8RuntimeOwnerTestStore{record: record}
	token := byte(8)
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store: store, ExpectedUID: 1000, CommitKey: make([]byte, 32),
		RandomToken: func() (string, error) { token++; return l8RuntimeOwnerTestToken(token), nil },
		ContainChild: func() (l8RuntimeOwnerAbsenceObservation, error) {
			return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: time.Unix(900, 0)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(owner.opts.CommitKey) })
	body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{
		SupervisorGeneration: record.SupervisorGeneration, RuntimeGeneration: record.RuntimeGeneration,
		RecordRevision: record.Revision, ReconnectSecret: record.ReconnectSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := owner.AdmitController(context.Background(), 1000, minimalCleanupPacket(t, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}))
	if err != nil || admitted.Packet.Status != l8RuntimeOwnerStatusOK {
		t.Fatal("actual controller admission prerequisite failed")
	}
	ack, err := decodeL8RuntimeOwnerHandshakeAck(admitted.Packet.Body)
	if err != nil || ack.ControllerSessionGeneration == "" || ack.RecordRevision != 3 ||
		store.record.ControllerState != "controlled" || store.record.ReconnectSecret == record.ReconnectSecret {
		t.Fatal("actual admission did not establish and durably claim the session")
	}
	body, err = encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: ack.ControllerSessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	return owner, store, minimalCleanupPacket(t, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 1, Body: body})
}

func minimalCleanupPacket(t *testing.T, packet l8RuntimeOwnerPacketV1) l8RuntimeOwnerReceivedPacketV1 {
	t.Helper()
	wire, err := encodeL8RuntimeOwnerPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeL8RuntimeOwnerPacket(wire)
	if err != nil || validateL8RuntimeOwnerPacketRole(decoded, false, 0) != nil {
		t.Fatal("canonical zero-rights request prerequisite failed")
	}
	return l8RuntimeOwnerReceivedPacketV1{Packet: decoded}
}

func TestMinimalCleanupPreflightShutdownPrecedesContainment(t *testing.T) {
	owner, store, request := minimalCleanupPreflightFixture(t)
	barrierCalls, containCalls := 0, 0
	joined := false
	contain := owner.opts.ContainChild
	owner.opts.ContainChild = func() (l8RuntimeOwnerAbsenceObservation, error) {
		containCalls++
		if !joined {
			t.Error("actual authenticated StopReap entered containment before selected shutdown joined")
		}
		return contain()
	}
	result, err := owner.handleControllerWithCleanup(context.Background(), request, func() error {
		barrierCalls++
		if !owner.mu.TryLock() {
			t.Error("selected shutdown barrier holds the FSM owner mutex")
			return errL8RuntimeOwnerInvalid
		}
		owner.mu.Unlock()
		joined = true
		return nil
	})
	if err != nil || result.Packet.Status != l8RuntimeOwnerStatusOK || containCalls != 1 || store.record.State != "absent" || store.record.Revision != 5 {
		t.Fatalf("actual StopReap prerequisite failed: error=%v containment=%d state=%s revision=%d", err, containCalls, store.record.State, store.record.Revision)
	}
	if barrierCalls != 1 || !joined {
		t.Fatalf("actual StopReap completed without its selected shutdown barrier: calls=%d joined=%v", barrierCalls, joined)
	}
}

func TestMinimalCleanupPreflightBlockedShutdownLeavesFSMUnlocked(t *testing.T) {
	owner, store, request := minimalCleanupPreflightFixture(t)
	before, transitions := store.record, len(store.transitions)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var result l8RuntimeOwnerControlResult
	var callErr error
	go func() {
		result, callErr = owner.handleControllerWithCleanup(ctx, request, func() error {
			close(entered)
			<-release
			return nil
		})
		close(done)
	}()
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("fixture cleanup did not join the controller request")
		}
	}()
	select {
	case <-entered:
	case <-done:
		t.Fatalf("actual authenticated StopReap returned before entering the blocked shutdown barrier: error=%v state=%s", callErr, store.record.State)
	case <-ctx.Done():
		t.Fatal("request did not reach its selected shutdown barrier")
	}
	if !owner.mu.TryLock() {
		t.Fatal("blocked selected shutdown holds the FSM owner mutex")
	}
	unchanged := store.record == before && len(store.transitions) == transitions && !store.retiredZero && !store.retiredFinal && !owner.hasLast
	owner.mu.Unlock()
	if !unchanged {
		t.Fatal("blocked selected shutdown advanced durable cleanup or replay state")
	}
	unblock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("request did not complete after shutdown joined")
	}
	if callErr != nil || result.Packet.Status != l8RuntimeOwnerStatusOK || store.record.State != "absent" {
		t.Fatalf("post-barrier StopReap failed: %v", callErr)
	}
}

func TestMinimalCleanupPreflightLegacyAndReplayControls(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		owner, store, request := minimalCleanupPreflightFixture(t)
		result, err := owner.HandleController(context.Background(), request)
		if err != nil || result.Packet.Status != l8RuntimeOwnerStatusOK || store.record.State != "absent" || store.record.Revision != 5 {
			t.Fatal("legacy admitted cleanup changed")
		}
	})
	t.Run("wrong-session", func(t *testing.T) {
		owner, store, request := minimalCleanupPreflightFixture(t)
		before, events := store.record, len(store.events)
		body, err := encodeL8RuntimeOwnerControllerRequest(l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(99)})
		if err != nil {
			t.Fatal(err)
		}
		request.Packet.Body = body
		calls := 0
		_, err = owner.handleControllerWithCleanup(context.Background(), request, func() error { calls++; return nil })
		if !errors.Is(err, errL8RuntimeOwnerProtocol) || calls != 0 || store.record != before || len(store.events) != events || owner.hasLast {
			t.Fatal("wrong-session request changed cleanup, replay or store observations")
		}
	})
	t.Run("cached-replay", func(t *testing.T) {
		owner, store, request := minimalCleanupPreflightFixture(t)
		first, err := owner.HandleController(context.Background(), request)
		if err != nil {
			t.Fatal("actual cleanup prerequisite failed")
		}
		before, events := store.record, len(store.events)
		calls := 0
		replay, err := owner.handleControllerWithCleanup(context.Background(), request, func() error { calls++; return nil })
		if err != nil || calls != 0 || store.record != before || len(store.events) != events ||
			replay.Packet.Opcode != first.Packet.Opcode || replay.Packet.Sequence != first.Packet.Sequence ||
			replay.Packet.Status != first.Packet.Status || !bytes.Equal(replay.Packet.Body, first.Packet.Body) {
			t.Fatal("cached replay changed its packet or performed new cleanup/store observations")
		}
	})
}
