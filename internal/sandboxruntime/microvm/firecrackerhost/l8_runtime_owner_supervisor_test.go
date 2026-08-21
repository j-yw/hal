package firecrackerhost

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestL8RuntimeOwnerProtocolExactRoundTripsAndRejectsMutations(t *testing.T) {
	handshake := l8RuntimeOwnerHandshakeV1{
		SupervisorGeneration: l8RuntimeOwnerTestToken(1),
		RuntimeGeneration:    "runtime-generation-1",
		RecordRevision:       9,
		ReconnectSecret:      l8RuntimeOwnerTestToken(2),
	}
	body, err := encodeL8RuntimeOwnerHandshake(handshake)
	if err != nil {
		t.Fatal(err)
	}
	packet := l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}
	wire, err := encodeL8RuntimeOwnerPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != l8RuntimeOwnerPacketHeaderSize+len(body) || string(wire[:8]) != l8RuntimeOwnerProtocolMagic || binary.BigEndian.Uint16(wire[8:10]) != l8RuntimeOwnerProtocolVersion {
		t.Fatalf("wire header = %x", wire)
	}
	decodedPacket, err := decodeL8RuntimeOwnerPacket(wire)
	if err != nil || !reflect.DeepEqual(decodedPacket, packet) {
		t.Fatalf("decoded packet = %#v, %v", decodedPacket, err)
	}
	decodedHandshake, err := decodeL8RuntimeOwnerHandshake(decodedPacket.Body)
	if err != nil || decodedHandshake != handshake {
		t.Fatalf("decoded handshake = %#v, %v", decodedHandshake, err)
	}

	mutations := map[string]func([]byte) []byte{
		"magic":              func(value []byte) []byte { value[0] ^= 1; return value },
		"version":            func(value []byte) []byte { binary.BigEndian.PutUint16(value[8:10], 2); return value },
		"opcode":             func(value []byte) []byte { binary.BigEndian.PutUint16(value[10:12], 99); return value },
		"request status":     func(value []byte) []byte { binary.BigEndian.PutUint16(value[12:14], 1); return value },
		"body length":        func(value []byte) []byte { binary.BigEndian.PutUint16(value[14:16], uint16(len(body)+1)); return value },
		"handshake sequence": func(value []byte) []byte { binary.BigEndian.PutUint64(value[16:24], 1); return value },
		"trailing":           func(value []byte) []byte { return append(value, 0) },
		"truncated":          func(value []byte) []byte { return value[:len(value)-1] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), wire...)
			if _, err := decodeL8RuntimeOwnerPacket(mutate(candidate)); !errors.Is(err, errL8RuntimeOwnerProtocol) {
				t.Fatalf("mutation error = %v", err)
			}
		})
	}
	if _, err := decodeL8RuntimeOwnerPacket(make([]byte, l8RuntimeOwnerPacketLimit+1)); !errors.Is(err, errL8RuntimeOwnerProtocol) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestL8RuntimeOwnerProtocolExactBodies(t *testing.T) {
	ack := l8RuntimeOwnerHandshakeAckV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(3), RecordRevision: 11}
	ackBody, err := encodeL8RuntimeOwnerHandshakeAck(ack)
	if err != nil || len(ackBody) != 51 {
		t.Fatalf("ack body length = %d, %v", len(ackBody), err)
	}
	if got, err := decodeL8RuntimeOwnerHandshakeAck(ackBody); err != nil || got != ack {
		t.Fatalf("ack = %#v, %v", got, err)
	}
	response := l8RuntimeOwnerResponseV1{State: 5, AbsenceKind: 1, RecordRevision: 12, ObservedAtUnixNano: 123456789}
	responseBody, err := encodeL8RuntimeOwnerResponse(response)
	if err != nil || len(responseBody) != 24 {
		t.Fatalf("response body length = %d, %v", len(responseBody), err)
	}
	if got, err := decodeL8RuntimeOwnerResponse(responseBody); err != nil || got != response {
		t.Fatalf("response = %#v, %v", got, err)
	}
	reserved := append([]byte(nil), responseBody...)
	reserved[2] = 1
	if _, err := decodeL8RuntimeOwnerResponse(reserved); !errors.Is(err, errL8RuntimeOwnerProtocol) {
		t.Fatalf("nonzero reserved response = %v", err)
	}
	for _, malformed := range [][]byte{
		ackBody[:len(ackBody)-1], append(append([]byte(nil), ackBody...), 0),
		responseBody[:len(responseBody)-1], append(append([]byte(nil), responseBody...), 0),
	} {
		if len(malformed) < 40 {
			if _, err := decodeL8RuntimeOwnerResponse(malformed); !errors.Is(err, errL8RuntimeOwnerProtocol) {
				t.Errorf("response mutation = %v", err)
			}
		} else if _, err := decodeL8RuntimeOwnerHandshakeAck(malformed); !errors.Is(err, errL8RuntimeOwnerProtocol) {
			t.Errorf("ack mutation = %v", err)
		}
	}
}

func TestL8RuntimeOwnerTypedBodiesAndRoleMatrixAreExact(t *testing.T) {
	controller := l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(1)}
	finalize := l8RuntimeOwnerFinalizeRequestV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(2), AbsenceRevision: 17, ObservedAtUnixNano: 123}
	ack := l8RuntimeOwnerFinalizeAckV1{CommitID: l8RuntimeOwnerTestToken(3), FinalizedRevision: 19}
	commit := l8RuntimeOwnerCommitRequestV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(4), CommitID: l8RuntimeOwnerTestToken(5), FinalizedRevision: 19}
	for _, scenario := range []struct {
		name   string
		want   int
		encode func() ([]byte, error)
		decode func([]byte) error
	}{
		{name: "controller", want: 43, encode: func() ([]byte, error) { return encodeL8RuntimeOwnerControllerRequest(controller) }, decode: func(body []byte) error {
			got, err := decodeL8RuntimeOwnerControllerRequest(body)
			if got != controller {
				return errL8RuntimeOwnerProtocol
			}
			return err
		}},
		{name: "finalize", want: 59, encode: func() ([]byte, error) { return encodeL8RuntimeOwnerFinalizeRequest(finalize) }, decode: func(body []byte) error {
			got, err := decodeL8RuntimeOwnerFinalizeRequest(body)
			if got != finalize {
				return errL8RuntimeOwnerProtocol
			}
			return err
		}},
		{name: "finalize ack", want: 51, encode: func() ([]byte, error) { return encodeL8RuntimeOwnerFinalizeAck(ack) }, decode: func(body []byte) error {
			got, err := decodeL8RuntimeOwnerFinalizeAck(body)
			if got != ack {
				return errL8RuntimeOwnerProtocol
			}
			return err
		}},
		{name: "commit", want: 94, encode: func() ([]byte, error) { return encodeL8RuntimeOwnerCommitRequest(commit) }, decode: func(body []byte) error {
			got, err := decodeL8RuntimeOwnerCommitRequest(body)
			if got != commit {
				return errL8RuntimeOwnerProtocol
			}
			return err
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			body, err := scenario.encode()
			if err != nil || len(body) != scenario.want {
				t.Fatalf("encoded = %d, %v", len(body), err)
			}
			if err := scenario.decode(body); err != nil {
				t.Fatalf("decode = %v", err)
			}
			for _, bad := range [][]byte{body[:len(body)-1], append(append([]byte(nil), body...), 0)} {
				if err := scenario.decode(bad); !errors.Is(err, errL8RuntimeOwnerProtocol) {
					t.Fatalf("mutation = %v", err)
				}
			}
		})
	}

	type roleCase struct {
		name     string
		packet   l8RuntimeOwnerPacketV1
		response bool
		rights   int
		ok       bool
	}
	controllerBody, _ := encodeL8RuntimeOwnerControllerRequest(controller)
	finalizeBody, _ := encodeL8RuntimeOwnerFinalizeRequest(finalize)
	commitBody, _ := encodeL8RuntimeOwnerCommitRequest(commit)
	responseBody, _ := encodeL8RuntimeOwnerResponse(l8RuntimeOwnerResponseV1{State: 4, AbsenceKind: 1, RecordRevision: 17, ObservedAtUnixNano: 123})
	for _, scenario := range []roleCase{
		{name: "reject", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeReject, Status: l8RuntimeOwnerStatusRejected}, response: true, ok: true},
		{name: "bootstrap", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapStart, Body: make([]byte, 32)}, rights: 2, ok: true},
		{name: "published", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeBootstrapPublished, Body: make([]byte, 8)}, response: true, ok: true},
		{name: "child armed", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildArmed}, ok: true},
		{name: "child release", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease}, response: true, ok: true},
		{name: "handshake", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: make([]byte, 97)}, ok: true},
		{name: "handshake response", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Status: l8RuntimeOwnerStatusOK, Body: make([]byte, 51)}, response: true, ok: true},
		{name: "abort", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeAbortStart, Sequence: 1, Body: controllerBody}, ok: true},
		{name: "inspect", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Sequence: 1, Body: controllerBody}, ok: true},
		{name: "stop", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeStopReap, Sequence: 1, Body: controllerBody}, ok: true},
		{name: "acquire", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeAcquireNamespaces, Sequence: 1, Body: controllerBody}, ok: true},
		{name: "close", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeClose, Sequence: 1, Body: controllerBody}, ok: true},
		{name: "inspect response", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Status: l8RuntimeOwnerStatusOK, Sequence: 1, Body: responseBody}, response: true, ok: true},
		{name: "invalid state response", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Status: l8RuntimeOwnerStatusInvalidState, Sequence: 1}, response: true, ok: true},
		{name: "uncertain response", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Status: l8RuntimeOwnerStatusUncertain, Sequence: 1}, response: true, ok: true},
		{name: "unsupported response", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Status: l8RuntimeOwnerStatusUnsupported, Sequence: 1}, response: true, ok: true},
		{name: "acquire response", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeAcquireNamespaces, Status: l8RuntimeOwnerStatusOK, Sequence: 1, Body: responseBody}, response: true, rights: 2, ok: true},
		{name: "finalize", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeFinalize, Sequence: 1, Body: finalizeBody}, ok: true},
		{name: "commit", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeCommit, Sequence: 1, Body: commitBody}, ok: true},
		{name: "wrong rights", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Sequence: 1, Body: controllerBody}, rights: 1},
		{name: "request status", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Status: 1, Sequence: 1, Body: controllerBody}},
		{name: "error response body", packet: l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Status: l8RuntimeOwnerStatusUncertain, Sequence: 1, Body: []byte{1}}, response: true},
		{name: "unknown opcode", packet: l8RuntimeOwnerPacketV1{Opcode: 99, Sequence: 1}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			err := validateL8RuntimeOwnerPacketRole(scenario.packet, scenario.response, scenario.rights)
			if scenario.ok && err != nil {
				t.Fatal(err)
			}
			if !scenario.ok && !errors.Is(err, errL8RuntimeOwnerProtocol) {
				t.Fatalf("role = %v", err)
			}
		})
	}
}

func TestL8RuntimeOwnerLockedTransitionReconcilesEveryCommitOutcome(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	prior := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	prior.State, prior.ControllerState, prior.Revision = "running", "unclaimed", 2
	intended := prior
	intended.ControllerState, intended.Revision, intended.ReconnectSecret = "controlled", 3, l8RuntimeOwnerTestToken(7)
	for _, scenario := range []struct {
		name              string
		writeErr, syncErr error
		reread            firecrackerRuntimeOwnerRecordV1
		present           bool
		readErr           error
		want              bool
	}{
		{name: "durable", reread: intended, present: true, want: true},
		{name: "rename uncertain intended", writeErr: errors.New("commit uncertain"), reread: intended, present: true, want: true},
		{name: "directory uncertain intended", syncErr: errors.New("commit uncertain"), reread: intended, present: true, want: true},
		{name: "prior retained", writeErr: errors.New("commit uncertain"), reread: prior, present: true},
		{name: "missing", writeErr: errors.New("commit uncertain")},
		{name: "read error", writeErr: errors.New("commit uncertain"), readErr: errors.New("private read")},
		{name: "third", writeErr: errors.New("commit uncertain"), reread: func() firecrackerRuntimeOwnerRecordV1 {
			v := intended
			v.ReconnectSecret = l8RuntimeOwnerTestToken(8)
			return v
		}(), present: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var events []string
			reads := 0
			ops := l8RuntimeOwnerTransactionOps{
				Lock:   func(context.Context) error { events = append(events, "lock"); return nil },
				Unlock: func() error { events = append(events, "unlock"); return nil },
				Read: func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
					events = append(events, "read")
					reads++
					if reads == 1 {
						return prior, true, nil
					}
					return scenario.reread, scenario.present, scenario.readErr
				},
				WriteAndRename: func(firecrackerRuntimeOwnerRecordV1) error {
					events = append(events, "rename")
					return scenario.writeErr
				},
				SyncDirectory: func() error { events = append(events, "fsync"); return scenario.syncErr },
			}
			got, err := transitionL8RuntimeOwnerRecordLocked(context.Background(), ops, prior.Revision, intended)
			if scenario.want {
				if err != nil || got != intended {
					t.Fatalf("transition = %#v, %v", got, err)
				}
			} else if !errors.Is(err, errL8RuntimeOwnerInvalid) {
				t.Fatalf("transition = %#v, %v", got, err)
			}
			if len(events) == 0 || events[0] != "lock" || events[len(events)-1] != "unlock" {
				t.Fatalf("lock events = %v", events)
			}
		})
	}
}

func TestL8RuntimeOwnerTransitionGraphRejectsResurrection(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	base := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record := func(state, controller string, revision uint64) firecrackerRuntimeOwnerRecordV1 {
		value := base
		value.State, value.ControllerState, value.Revision = state, controller, revision
		value.FinalizedCommitID, value.FinalizeTargetRevision = "", 0
		if state != "absent" && state != "finalizing" && state != "finalized" && state != "uncertain" {
			value.AbsenceKind, value.AbsenceRevision, value.AbsenceObservedAtUnixNano = "", 0, 0
		}
		if state == "absent" || state == "uncertain" {
			value.AbsenceRevision = revision
		}
		if state == "finalizing" {
			value.AbsenceRevision = revision - 1
			value.FinalizedCommitID, value.FinalizeTargetRevision = l8RuntimeOwnerTestToken(9), revision+1
		}
		if state == "finalized" {
			value.AbsenceRevision = revision - 2
			value.FinalizedCommitID, value.FinalizeTargetRevision = l8RuntimeOwnerTestToken(9), revision
		}
		if state == "starting" && revision == 0 {
			value.FirecrackerPID, value.FirecrackerStartTime = 0, 0
		}
		return value
	}
	genesis := record("starting", "none", 0)
	revisionOne := record("starting", "none", 1)
	if !validL8RuntimeOwnerTransition(genesis, revisionOne) {
		t.Fatal("revision-zero starting did not advance to revision-one starting")
	}
	if !validL8RuntimeOwnerTransition(revisionOne, record("running", "unclaimed", 2)) ||
		!validL8RuntimeOwnerTransition(revisionOne, record("stopping", "none", 2)) ||
		validL8RuntimeOwnerTransition(revisionOne, record("absent", "none", 2)) {
		t.Fatal("revision-one publication/abort ordering is not exact")
	}
	allowed := [][4]string{
		{"running", "unclaimed", "running", "controlled"}, {"running", "controlled", "running", "unclaimed"},
		{"stopping", "unclaimed", "stopping", "controlled"}, {"absent", "unclaimed", "absent", "controlled"},
		{"uncertain", "unclaimed", "uncertain", "controlled"}, {"finalizing", "unclaimed", "finalizing", "controlled"},
		{"finalized", "unclaimed", "finalized", "controlled"}, {"running", "controlled", "stopping", "controlled"},
		{"running", "controlled", "uncertain", "controlled"}, {"stopping", "controlled", "absent", "controlled"},
		{"stopping", "controlled", "uncertain", "controlled"}, {"uncertain", "controlled", "absent", "controlled"},
		{"absent", "controlled", "absent", "controlled"}, {"absent", "controlled", "finalizing", "controlled"},
		{"finalizing", "controlled", "finalized", "controlled"},
	}
	for _, transition := range allowed {
		if !validL8RuntimeOwnerTransition(record(transition[0], transition[1], 4), record(transition[2], transition[3], 5)) {
			t.Errorf("allowed transition %s/%s -> %s/%s rejected", transition[0], transition[1], transition[2], transition[3])
		}
	}
	for _, transition := range [][2]string{
		{"absent", "running"}, {"finalized", "absent"}, {"uncertain", "stopping"},
		{"stopping", "running"}, {"running", "starting"}, {"absent", "finalized"},
	} {
		if validL8RuntimeOwnerTransition(record(transition[0], "controlled", 4), record(transition[1], "controlled", 5)) {
			t.Errorf("resurrection %s -> %s accepted", transition[0], transition[1])
		}
	}
	if validL8RuntimeOwnerTransition(record("starting", "none", 1), record("starting", "none", 2)) ||
		validL8RuntimeOwnerTransition(record("starting", "none", 0), record("running", "unclaimed", 1)) ||
		validL8RuntimeOwnerTransition(record("running", "unclaimed", 2), record("running", "controlled", 4)) {
		t.Fatal("noncanonical starting or revision jump accepted")
	}
}

func TestL8RuntimeOwnerCommitUncertainAcceptsOnlyPriorOrIntended(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	prior := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	prior.State, prior.ControllerState, prior.Revision = "running", "unclaimed", 2
	intended := prior
	intended.ControllerState, intended.Revision, intended.ReconnectSecret = "controlled", 3, l8RuntimeOwnerTestToken(4)
	if got, committed, err := reconcileL8RuntimeOwnerCommitUncertain(prior, intended, prior); err != nil || committed || got != prior {
		t.Fatalf("prior reconciliation = %#v, %t, %v", got, committed, err)
	}
	if got, committed, err := reconcileL8RuntimeOwnerCommitUncertain(prior, intended, intended); err != nil || !committed || got != intended {
		t.Fatalf("intended reconciliation = %#v, %t, %v", got, committed, err)
	}
	third := intended
	third.ReconnectSecret = l8RuntimeOwnerTestToken(5)
	if _, _, err := reconcileL8RuntimeOwnerCommitUncertain(prior, intended, third); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("third-value reconciliation = %v", err)
	}
}

func TestL8RuntimeOwnerContainmentUsesOneIndependentBudgetAndNeverSkipsWait(t *testing.T) {
	for _, scenario := range []struct {
		name            string
		terminatePanic  bool
		terminateErr    bool
		firstWaitReaped bool
		killPanic       bool
		killErr         bool
		finalReaped     bool
		wantAbsent      bool
	}{
		{name: "term exit", firstWaitReaped: true, wantAbsent: true},
		{name: "term error still kill wait", terminateErr: true, finalReaped: true, wantAbsent: true},
		{name: "term panic still kill wait", terminatePanic: true, finalReaped: true, wantAbsent: true},
		{name: "kill error still wait", killErr: true, finalReaped: true, wantAbsent: true},
		{name: "kill panic still wait", killPanic: true, finalReaped: true, wantAbsent: true},
		{name: "unreaped uncertain"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var events []string
			waitCalls := 0
			var waitDeadlines []time.Time
			started := time.Now()
			ops := l8RuntimeOwnerContainmentOps{
				RecordStopping: func() (uint64, error) { events = append(events, "record_stopping"); return 3, nil },
				Terminate: func() error {
					events = append(events, "term")
					if scenario.terminatePanic {
						panic("private term panic")
					}
					if scenario.terminateErr {
						return errors.New("private term error")
					}
					return nil
				},
				Wait: func(ctx context.Context) (bool, error) {
					events = append(events, "wait")
					deadline, ok := ctx.Deadline()
					if !ok {
						t.Error("wait context has no deadline")
					}
					waitDeadlines = append(waitDeadlines, deadline)
					waitCalls++
					if waitCalls == 1 {
						return scenario.firstWaitReaped, nil
					}
					return scenario.finalReaped, nil
				},
				Kill: func() error {
					events = append(events, "kill")
					if scenario.killPanic {
						panic("private kill panic")
					}
					if scenario.killErr {
						return errors.New("private kill error")
					}
					return nil
				},
				RecordAbsent: func(observation l8RuntimeOwnerAbsenceObservation) (uint64, error) {
					events = append(events, "record_absent")
					return 4, nil
				},
				RecordUncertain: func() (uint64, error) { events = append(events, "record_uncertain"); return 4, nil },
				Now:             func() time.Time { return time.Unix(100, 0) },
			}
			observation, err := containL8RuntimeOwnerChild(ops)
			if scenario.wantAbsent {
				if err != nil || observation.Kind != 1 || observation.Revision != 4 || !observation.ObservedAt.Equal(time.Unix(100, 0)) || events[len(events)-1] != "record_absent" {
					t.Fatalf("containment = %#v, %v, events %v", observation, err, events)
				}
			} else if !errors.Is(err, errL8RuntimeOwnerInvalid) || observation != (l8RuntimeOwnerAbsenceObservation{}) || len(events) == 0 || events[len(events)-1] != "record_uncertain" {
				t.Fatalf("uncertain containment = %#v, %v, events %v", observation, err, events)
			}
			if !scenario.firstWaitReaped && !reflect.DeepEqual(events[1:4], []string{"term", "wait", "kill"}) {
				t.Fatalf("containment order = %v", events)
			}
			if len(waitDeadlines) != 0 {
				first := waitDeadlines[0].Sub(started)
				if first < 4*time.Second || first > 5*time.Second+100*time.Millisecond {
					t.Fatalf("first wait budget = %v", first)
				}
			}
			if len(waitDeadlines) == 2 {
				final := waitDeadlines[1].Sub(started)
				if final < 29*time.Second || final > 31*time.Second || !waitDeadlines[1].After(waitDeadlines[0]) {
					t.Fatalf("shared final deadline = %v after first %v", final, waitDeadlines[0].Sub(started))
				}
			}
		})
	}
}

func TestL8RuntimeOwnerContainmentStoreFailuresNeverPublishAbsence(t *testing.T) {
	for _, scenario := range []struct {
		name                 string
		stoppingFailure      string
		absentFailure        string
		wantContainmentCalls bool
	}{
		{name: "stopping error", stoppingFailure: "error"},
		{name: "stopping panic", stoppingFailure: "panic"},
		{name: "absent error", absentFailure: "error", wantContainmentCalls: true},
		{name: "absent panic", absentFailure: "panic", wantContainmentCalls: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var events []string
			ops := l8RuntimeOwnerContainmentOps{
				RecordStopping: func() (uint64, error) {
					events = append(events, "record_stopping")
					if scenario.stoppingFailure == "panic" {
						panic("private stopping panic")
					}
					if scenario.stoppingFailure == "error" {
						return 0, errors.New("private stopping error")
					}
					return 3, nil
				},
				Terminate: func() error { events = append(events, "term"); return nil },
				Wait:      func(context.Context) (bool, error) { events = append(events, "wait"); return true, nil },
				Kill:      func() error { events = append(events, "kill"); return nil },
				RecordAbsent: func(l8RuntimeOwnerAbsenceObservation) (uint64, error) {
					events = append(events, "record_absent")
					if scenario.absentFailure == "panic" {
						panic("private absent panic")
					}
					if scenario.absentFailure == "error" {
						return 0, errors.New("private absent error")
					}
					return 4, nil
				},
				RecordUncertain: func() (uint64, error) { events = append(events, "record_uncertain"); return 4, nil },
				Now:             func() time.Time { return time.Unix(200, 0) },
			}
			observation, err := containL8RuntimeOwnerChild(ops)
			if observation != (l8RuntimeOwnerAbsenceObservation{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) || err.Error() != errL8RuntimeOwnerInvalid.Error() {
				t.Fatalf("failure result = %#v, %v", observation, err)
			}
			if containsString(events, "record_absent") != scenario.wantContainmentCalls || len(events) == 0 || events[len(events)-1] != "record_uncertain" {
				t.Fatalf("failure events = %v", events)
			}
			if !scenario.wantContainmentCalls && (containsString(events, "term") || containsString(events, "wait") || containsString(events, "kill")) {
				t.Fatalf("signalled before stopping durability: %v", events)
			}
		})
	}
}

func TestL8RuntimeOwnerContainmentRejectsNilPanicWaitAndRetriesUncertain(t *testing.T) {
	base := l8RuntimeOwnerContainmentOps{
		RecordStopping:  func() (uint64, error) { return 3, nil },
		Terminate:       func() error { return nil },
		Wait:            func(context.Context) (bool, error) { return true, nil },
		Kill:            func() error { return nil },
		RecordAbsent:    func(l8RuntimeOwnerAbsenceObservation) (uint64, error) { return 4, nil },
		RecordUncertain: func() (uint64, error) { return 4, nil },
		Now:             func() time.Time { return time.Unix(1, 0) },
	}
	for _, scenario := range []struct {
		name   string
		mutate func(*l8RuntimeOwnerContainmentOps)
	}{
		{name: "nil stopping", mutate: func(value *l8RuntimeOwnerContainmentOps) { value.RecordStopping = nil }},
		{name: "nil wait", mutate: func(value *l8RuntimeOwnerContainmentOps) { value.Wait = nil }},
		{name: "wait error", mutate: func(value *l8RuntimeOwnerContainmentOps) {
			value.Wait = func(context.Context) (bool, error) { return false, errors.New("private wait path") }
		}},
		{name: "wait panic", mutate: func(value *l8RuntimeOwnerContainmentOps) {
			value.Wait = func(context.Context) (bool, error) { panic("private wait panic") }
		}},
		{name: "uncertain panic", mutate: func(value *l8RuntimeOwnerContainmentOps) {
			value.Wait = func(context.Context) (bool, error) { return false, nil }
			value.RecordUncertain = func() (uint64, error) { panic("private uncertain panic") }
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			value := base
			scenario.mutate(&value)
			observation, err := containL8RuntimeOwnerChild(value)
			if observation != (l8RuntimeOwnerAbsenceObservation{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) || err.Error() != errL8RuntimeOwnerInvalid.Error() {
				t.Fatalf("containment = %#v, %v", observation, err)
			}
		})
	}

	controller := &l8RuntimeOwnerContainmentController{}
	attempts := 0
	ops := base
	ops.RecordStopping = func() (uint64, error) {
		attempts++
		if attempts == 1 {
			return 0, errors.New("private transient")
		}
		return 3, nil
	}
	if _, err := controller.Stop(ops); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("first attempt = %v", err)
	}
	if observation, err := controller.Stop(ops); err != nil || observation.Revision != 4 || attempts != 2 {
		t.Fatalf("retry = %#v, %v attempts %d", observation, err, attempts)
	}
	if _, err := controller.Stop(ops); err != nil || attempts != 2 {
		t.Fatalf("cached success = %v attempts %d", err, attempts)
	}
}

func TestL8RuntimeOwnerContainmentSerializesConcurrentStop(t *testing.T) {
	controller := &l8RuntimeOwnerContainmentController{}
	entered := make(chan struct{})
	release := make(chan struct{})
	var muEvents []string
	var eventMu = make(chan struct{}, 1)
	eventMu <- struct{}{}
	add := func(event string) {
		<-eventMu
		muEvents = append(muEvents, event)
		eventMu <- struct{}{}
	}
	ops := l8RuntimeOwnerContainmentOps{
		RecordStopping:  func() (uint64, error) { add("record_stopping"); close(entered); <-release; return 3, nil },
		Terminate:       func() error { add("term"); return nil },
		Wait:            func(context.Context) (bool, error) { add("wait"); return true, nil },
		Kill:            func() error { add("kill"); return nil },
		RecordAbsent:    func(l8RuntimeOwnerAbsenceObservation) (uint64, error) { add("record_absent"); return 4, nil },
		RecordUncertain: func() (uint64, error) { add("record_uncertain"); return 4, nil },
		Now:             func() time.Time { return time.Unix(300, 0) },
	}
	results := make(chan l8RuntimeOwnerAbsenceObservation, 2)
	for index := 0; index < 2; index++ {
		go func() { observation, _ := controller.Stop(ops); results <- observation }()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("containment never admitted a single owner")
	}
	close(release)
	first, second := <-results, <-results
	if first != second || first.Kind != 1 {
		t.Fatalf("concurrent observations = %#v / %#v", first, second)
	}
	<-eventMu
	events := append([]string(nil), muEvents...)
	eventMu <- struct{}{}
	if got := countString(events, "record_stopping"); got != 1 || countString(events, "term") != 1 || countString(events, "wait") != 1 || countString(events, "record_absent") != 1 {
		t.Fatalf("concurrent containment events = %v", events)
	}
}

func TestL8RuntimeOwnerReplacementRequiresExactSameBootAndDoubleProcAbsence(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	bootID := "01234567-89ab-cdef-0123-456789abcdef"
	record := l8RuntimeOwnerTestRecord(t, seed, bootID)
	record.State, record.ControllerState, record.Revision = "running", "unclaimed", 2
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "", 0, 0
	exactChild := l8RuntimeOwnerProcessObservation{
		PID: record.FirecrackerPID, ParentPID: 1, StartTime: record.FirecrackerStartTime,
		state: 'S', pidfd: 11, pidfdOwned: true,
	}
	for _, scenario := range []struct {
		name             string
		currentBoot      string
		supervisorExists bool
		child            l8RuntimeOwnerProcessObservation
		childExists      bool
		absences         []bool
		wantSignal       bool
		wantAbsent       bool
	}{
		{name: "exact child killed then absent", currentBoot: bootID, child: exactChild, childExists: true, absences: []bool{true, true}, wantSignal: true, wantAbsent: true},
		{name: "already absent twice", currentBoot: bootID, absences: []bool{true, true}, wantAbsent: true},
		{name: "old boot", currentBoot: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{name: "live supervisor", currentBoot: bootID, supervisorExists: true},
		{name: "PID reused", currentBoot: bootID, child: func() l8RuntimeOwnerProcessObservation { value := exactChild; value.StartTime++; return value }(), childExists: true},
		{name: "unexpected reparent", currentBoot: bootID, child: func() l8RuntimeOwnerProcessObservation { value := exactChild; value.ParentPID = 2; return value }(), childExists: true},
		{name: "zombie", currentBoot: bootID, child: func() l8RuntimeOwnerProcessObservation { value := exactChild; value.state = 'Z'; return value }(), childExists: true},
		{name: "only one absence", currentBoot: bootID, absences: []bool{true, false}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var events []string
			absenceIndex := 0
			ops := l8RuntimeOwnerReplacementOps{
				CurrentBootID: func() (string, error) { events = append(events, "boot"); return scenario.currentBoot, nil },
				InspectSupervisor: func(uint32) (l8RuntimeOwnerProcessObservation, bool, error) {
					events = append(events, "inspect_supervisor")
					if scenario.supervisorExists {
						return l8RuntimeOwnerProcessObservation{PID: record.SupervisorPID, StartTime: record.SupervisorStartTime, state: 'S', pidfd: 10, pidfdOwned: true}, true, nil
					}
					return l8RuntimeOwnerProcessObservation{}, false, nil
				},
				InspectChild: func(uint32) (l8RuntimeOwnerProcessObservation, bool, error) {
					events = append(events, "inspect_child")
					return scenario.child, scenario.childExists, nil
				},
				SignalKill: func(l8RuntimeOwnerProcessObservation) error { events = append(events, "pidfd_kill"); return nil },
				WaitTerminal: func(context.Context, l8RuntimeOwnerProcessObservation) error {
					events = append(events, "pidfd_terminal")
					return nil
				},
				ProcessAbsent: func(uint32) (bool, error) {
					events = append(events, "proc_absence")
					if absenceIndex >= len(scenario.absences) {
						return false, nil
					}
					value := scenario.absences[absenceIndex]
					absenceIndex++
					return value, nil
				},
				AcquisitionBarrier: func() error { events = append(events, "acquisition_barrier"); return nil },
				RecordAbsent: func(l8RuntimeOwnerAbsenceObservation) (uint64, error) {
					events = append(events, "record_absent")
					return 5, nil
				},
				RecordUncertain: func() (uint64, error) { events = append(events, "record_uncertain"); return 5, nil },
				Now:             func() time.Time { return time.Unix(400, 0) },
			}
			observation, err := containL8RuntimeOwnerReplacement(record, ops)
			if containsString(events, "pidfd_kill") != scenario.wantSignal {
				t.Fatalf("replacement signal events = %v", events)
			}
			if scenario.wantAbsent {
				if err != nil || observation.Kind != 2 || countString(events, "proc_absence") != 2 || !containsString(events, "acquisition_barrier") {
					t.Fatalf("replacement absence = %#v, %v, events %v", observation, err, events)
				}
			} else if observation != (l8RuntimeOwnerAbsenceObservation{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) || containsString(events, "record_absent") {
				t.Fatalf("uncertain replacement = %#v, %v, events %v", observation, err, events)
			}
			if scenario.currentBoot != bootID && (containsString(events, "inspect_supervisor") || containsString(events, "inspect_child") || containsString(events, "pidfd_kill")) {
				t.Fatalf("old boot reached process authority: %v", events)
			}
		})
	}
}

func containsString(values []string, target string) bool { return countString(values, target) != 0 }

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}
