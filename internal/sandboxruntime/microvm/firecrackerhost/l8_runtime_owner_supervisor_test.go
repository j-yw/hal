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

func TestL8RuntimeOwnerTransitionGraphRejectsResurrection(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	base := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record := func(state string, revision uint64) firecrackerRuntimeOwnerRecordV1 {
		value := base
		value.State, value.Revision = state, revision
		value.FinalizedCommitID = ""
		if state == "finalized" {
			value.FinalizedCommitID = l8RuntimeOwnerTestToken(9)
		}
		if state == "starting" && revision == 0 {
			value.FirecrackerPID, value.FirecrackerStartTime = 0, 0
		}
		return value
	}
	genesis := record("starting", 0)
	revisionOne := record("starting", 1)
	if !validL8RuntimeOwnerTransition(genesis, revisionOne) {
		t.Fatal("revision-zero starting did not advance to revision-one starting")
	}
	for _, state := range []string{"unclaimed", "stopping", "absent", "uncertain"} {
		if !validL8RuntimeOwnerTransition(revisionOne, record(state, 2)) {
			t.Errorf("revision-one starting -> %s rejected", state)
		}
	}
	allowed := [][2]string{
		{"unclaimed", "controlled"}, {"unclaimed", "stopping"}, {"unclaimed", "absent"}, {"unclaimed", "uncertain"},
		{"controlled", "unclaimed"}, {"controlled", "stopping"}, {"controlled", "absent"}, {"controlled", "uncertain"},
		{"stopping", "absent"}, {"stopping", "uncertain"}, {"absent", "finalized"},
	}
	for _, transition := range allowed {
		fromRevision := uint64(2)
		if !validL8RuntimeOwnerTransition(record(transition[0], fromRevision), record(transition[1], fromRevision+1)) {
			t.Errorf("allowed transition %s -> %s rejected", transition[0], transition[1])
		}
	}
	for _, transition := range [][2]string{
		{"absent", "controlled"}, {"absent", "unclaimed"}, {"finalized", "absent"}, {"uncertain", "stopping"},
		{"stopping", "controlled"}, {"controlled", "starting"},
	} {
		if validL8RuntimeOwnerTransition(record(transition[0], 4), record(transition[1], 5)) {
			t.Errorf("resurrection %s -> %s accepted", transition[0], transition[1])
		}
	}
	if validL8RuntimeOwnerTransition(record("starting", 1), record("starting", 2)) ||
		validL8RuntimeOwnerTransition(record("starting", 0), record("unclaimed", 1)) ||
		validL8RuntimeOwnerTransition(record("unclaimed", 2), record("controlled", 4)) {
		t.Fatal("noncanonical starting or revision jump accepted")
	}
}

func TestL8RuntimeOwnerCommitUncertainAcceptsOnlyPriorOrIntended(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	prior := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	prior.State, prior.Revision = "unclaimed", 2
	intended := prior
	intended.State, intended.Revision, intended.ReconnectSecret = "controlled", 3, l8RuntimeOwnerTestToken(4)
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
				RecordStopping: func() error { events = append(events, "record_stopping"); return nil },
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
				RecordAbsent: func(observation l8RuntimeOwnerAbsenceObservation) error {
					events = append(events, "record_absent")
					return nil
				},
				RecordUncertain: func() error { events = append(events, "record_uncertain"); return nil },
				Now:             func() time.Time { return time.Unix(100, 0) },
			}
			observation, err := containL8RuntimeOwnerChild(ops)
			if scenario.wantAbsent {
				if err != nil || observation.Kind != 1 || !observation.ObservedAt.Equal(time.Unix(100, 0)) || events[len(events)-1] != "record_absent" {
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
				if first < 4*time.Second || first > 6*time.Second {
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
				RecordStopping: func() error {
					events = append(events, "record_stopping")
					if scenario.stoppingFailure == "panic" {
						panic("private stopping panic")
					}
					if scenario.stoppingFailure == "error" {
						return errors.New("private stopping error")
					}
					return nil
				},
				Terminate: func() error { events = append(events, "term"); return nil },
				Wait:      func(context.Context) (bool, error) { events = append(events, "wait"); return true, nil },
				Kill:      func() error { events = append(events, "kill"); return nil },
				RecordAbsent: func(l8RuntimeOwnerAbsenceObservation) error {
					events = append(events, "record_absent")
					if scenario.absentFailure == "panic" {
						panic("private absent panic")
					}
					if scenario.absentFailure == "error" {
						return errors.New("private absent error")
					}
					return nil
				},
				RecordUncertain: func() error { events = append(events, "record_uncertain"); return nil },
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
		RecordStopping:  func() error { add("record_stopping"); close(entered); <-release; return nil },
		Terminate:       func() error { add("term"); return nil },
		Wait:            func(context.Context) (bool, error) { add("wait"); return true, nil },
		Kill:            func() error { add("kill"); return nil },
		RecordAbsent:    func(l8RuntimeOwnerAbsenceObservation) error { add("record_absent"); return nil },
		RecordUncertain: func() error { add("record_uncertain"); return nil },
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
	record.State, record.Revision = "unclaimed", 2
	exactChild := l8RuntimeOwnerProcessObservation{
		PID: record.FirecrackerPID, ParentPID: record.SupervisorPID, StartTime: record.FirecrackerStartTime,
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
				RecordAbsent:       func(l8RuntimeOwnerAbsenceObservation) error { events = append(events, "record_absent"); return nil },
				RecordUncertain:    func() error { events = append(events, "record_uncertain"); return nil },
				Now:                func() time.Time { return time.Unix(400, 0) },
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
