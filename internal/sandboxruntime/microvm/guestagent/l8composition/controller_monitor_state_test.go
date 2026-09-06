package l8composition

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestControllerMonitorStateHardHorizonObservationAndOnePrepare(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)

	request := byteRange16(0x10)
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1_900, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "http", Mode: credentialprotocol.DeliveryModeHTTPProxy}}}
	wire, err := EncodeControllerMonitorPrepareBeginPacket(0, request, fixture.jobIdentity, begin)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_800)
	if err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("begin = %v, %v", decision, err)
	}
	if got := state.Snapshot(); got.Phase != ControllerMonitorPhasePreparing || !got.PrepareConsumed || !got.RequestOutstanding {
		t.Fatalf("snapshot = %#v", got)
	}

	manifest, _ := credentialprotocol.ComputeHelperManifestSHA256(begin.Bindings)
	commit := credentialprotocol.HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifest}
	wire, err = EncodeControllerMonitorPrepareCommitPacket(1, request, fixture.jobIdentity, commit)
	if err != nil {
		t.Fatal(err)
	}
	if decision, err = state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("commit = %v, %v", decision, err)
	}

	transaction := controllerMonitorEmptyPrepareTransactionDigest(t, request, fixture.jobIdentity, begin, manifest)
	post, _ := ControllerMonitorPreparePostinspectionSHA256(fixture.jobIdentity, 1, fixture.ready.MonitorGeneration, fixture.ready.MountGeneration, manifest, transaction, 0, 0)
	response, err := NewControllerMonitorPrepareAcceptedResponse(1, ControllerMonitorPrepareResult{MountGeneration: fixture.ready.MountGeneration, ManifestSHA256: manifest, PrepareTransactionSHA256: transaction, PreparePostinspectionSHA256: post})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ = EncodeControllerMonitorResponsePacket(1, request, fixture.jobIdentity, response)
	if decision, err = state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("response = %v, %v", decision, err)
	}
	if got := state.Snapshot(); got.Phase != ControllerMonitorPhasePrepared || got.RequestOutstanding {
		t.Fatalf("snapshot = %#v", got)
	}

	second, _ := EncodeControllerMonitorPrepareBeginPacket(2, byteRange16(0x20), fixture.jobIdentity, begin)
	if decision, err = state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), second, 1_800); !errors.Is(err, ErrControllerMonitorTransition) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("second prepare = %v, %v", decision, err)
	}
}

func TestControllerMonitorStateRejectsUnusedObservationAndOutOfWindowExpiry(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	ready := mustControllerMonitorReadyPacket(t, fixture)
	if decision, err := state.Accept(fixture.readyMetadata, ready, 1); !errors.Is(err, ErrControllerMonitorTrustedObservation) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("unused observation = %v, %v", decision, err)
	}

	state = mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 2_001, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "http", Mode: credentialprotocol.DeliveryModeHTTPProxy}}}
	wire, _ := EncodeControllerMonitorPrepareBeginPacket(0, byteRange16(0x30), fixture.jobIdentity, begin)
	decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_800)
	if !errors.Is(err, ErrControllerMonitorExpiryWindow) || decision != ControllerMonitorTransitionSendOperationDenied {
		t.Fatalf("expiry = %v, %v", decision, err)
	}
	got := state.Snapshot()
	if got.Phase != ControllerMonitorPhaseReadyTransferred || !got.PrepareConsumed || !got.RequestOutstanding {
		t.Fatalf("snapshot = %#v", got)
	}
}

func TestControllerMonitorStateClosedObservationQueueAndSendFailure(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	observation, err := NewControllerMonitorExpiredObservation(byteRange16(0x40))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := state.Observe(observation)
	if err != nil || decision != ControllerMonitorTransitionPendingEventSendable {
		t.Fatalf("observe = %v, %v", decision, err)
	}
	pending, ok := state.PendingEvent()
	if !ok || pending.Body.EventCode != ControllerMonitorEventExpired || pending.Body.EventID != controllerMonitorEventID(pending.RequestID) {
		t.Fatalf("pending = %#v, %t", pending, ok)
	}
	if state.Snapshot().Phase != ControllerMonitorPhaseRevokeRequired {
		t.Fatalf("phase = %#v", state.Snapshot())
	}
	if _, err := state.Observe(observation); !errors.Is(err, ErrControllerMonitorPendingEvent) {
		t.Fatalf("second observation = %v", err)
	}
	if state.Decision() != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("decision = %v", state.Decision())
	}

	state = mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	state.SendFailed()
	if state.Decision() != ControllerMonitorTransitionStopVMRequired {
		t.Fatal("send failure was not terminal")
	}
	if _, err := state.Observe(observation); !errors.Is(err, ErrControllerMonitorTerminal) {
		t.Fatalf("post-terminal observe = %v", err)
	}
}

func TestControllerMonitorStateExpiryDuringPrepareIsRepresentedOrQueuedExactlyOnce(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1_900, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "http", Mode: credentialprotocol.DeliveryModeHTTPProxy}}}

	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	request := byteRange16(0x42)
	wire, _ := EncodeControllerMonitorPrepareBeginPacket(0, request, fixture.jobIdentity, begin)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_800); err != nil {
		t.Fatal(err)
	}
	expired, _ := NewControllerMonitorExpiredObservation(byteRange16(0x52))
	if decision, err := state.Observe(expired); err != nil || decision != ControllerMonitorTransitionSendOperationDenied {
		t.Fatalf("pre-commit expiry = %v, %v", decision, err)
	}
	if got := state.Snapshot(); got.Phase != ControllerMonitorPhaseReadyTransferred || got.PendingEvent || !got.RequestOutstanding {
		t.Fatalf("represented expiry snapshot = %#v", got)
	}
	denied, _ := NewControllerMonitorRejectedResponse(ControllerMonitorPacketTypePrepareCommit, 1, ControllerMonitorFailureOperationDenied)
	wire, _ = EncodeControllerMonitorResponsePacket(1, request, fixture.jobIdentity, denied)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("represented expiry response = %v, %v", decision, err)
	}

	state = mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	request = byteRange16(0x62)
	wire, _ = EncodeControllerMonitorPrepareBeginPacket(0, request, fixture.jobIdentity, begin)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_800); err != nil {
		t.Fatal(err)
	}
	manifest, _ := credentialprotocol.ComputeHelperManifestSHA256(begin.Bindings)
	wire, _ = EncodeControllerMonitorPrepareCommitPacket(1, request, fixture.jobIdentity, credentialprotocol.HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifest})
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil {
		t.Fatal(err)
	}
	expired, _ = NewControllerMonitorExpiredObservation(byteRange16(0x72))
	if decision, err := state.Observe(expired); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("post-commit expiry = %v, %v", decision, err)
	}
	if got := state.Snapshot(); got.Phase != ControllerMonitorPhaseRevokeRequired || !got.PendingEvent || !got.RequestOutstanding {
		t.Fatalf("queued expiry snapshot = %#v", got)
	}
	transaction := controllerMonitorEmptyPrepareTransactionDigest(t, request, fixture.jobIdentity, begin, manifest)
	post, _ := ControllerMonitorPreparePostinspectionSHA256(fixture.jobIdentity, 1, fixture.ready.MonitorGeneration, fixture.ready.MountGeneration, manifest, transaction, 0, 0)
	accepted, _ := NewControllerMonitorPrepareAcceptedResponse(1, ControllerMonitorPrepareResult{MountGeneration: fixture.ready.MountGeneration, ManifestSHA256: manifest, PrepareTransactionSHA256: transaction, PreparePostinspectionSHA256: post})
	wire, _ = EncodeControllerMonitorResponsePacket(1, request, fixture.jobIdentity, accepted)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionSendOutstandingResultBeforePendingEvent {
		t.Fatalf("response before event = %v, %v", decision, err)
	}
	pending, ok := state.PendingEvent()
	if !ok {
		t.Fatal("independent expiry event was not retained")
	}
	wire, _ = EncodeControllerMonitorEventPacket(2, pending.RequestID, fixture.jobIdentity, pending.Body)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("queued expiry event = %v, %v", decision, err)
	}
}

func TestControllerMonitorStateConcurrentTerminalLatch(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	observation, _ := NewControllerMonitorMountDriftObservation(byteRange16(0x50))
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if index%2 == 0 {
				state.SendFailed()
			} else {
				_, _ = state.Observe(observation)
			}
			_ = state.Snapshot()
			_ = state.Decision()
		}()
	}
	group.Wait()
	if state.Decision() != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("decision = %v", state.Decision())
	}
}

func TestControllerMonitorStateRevokeRetriesBilateralCloseAndExpectedEOF(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)

	revoke1 := byteRange16(0x60)
	wire, _ := EncodeControllerMonitorRevokePacket(0, revoke1, fixture.jobIdentity, credentialprotocol.HelperRevokeBody{Revision: 1, Reason: credentialprotocol.RevokeReasonRequested})
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("revoke = %v, %v", decision, err)
	}
	retry, _ := NewControllerMonitorCleanupRetryResponse(1, ControllerMonitorFailureCleanupIncomplete)
	wire, _ = EncodeControllerMonitorResponsePacket(1, revoke1, fixture.jobIdentity, retry)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("retry = %v, %v", decision, err)
	}

	revoke2 := byteRange16(0x70)
	body := credentialprotocol.HelperRevokeBody{Revision: 1, Reason: credentialprotocol.RevokeReasonRequested}
	wire, _ = EncodeControllerMonitorRevokePacket(1, revoke2, fixture.jobIdentity, body)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil {
		t.Fatal(err)
	}
	cleanupDigest, _ := ControllerMonitorCleanupSHA256(fixture.jobIdentity, 1, body.Reason, fixture.ready.MonitorGeneration, fixture.ready.MountGeneration, "", true, true, true)
	complete, _ := NewControllerMonitorCleanupCompleteResponse(1, ControllerMonitorRevokeResult{CleanupSHA256: cleanupDigest, EntriesAbsent: true, SocketAbsent: true, MountAbsent: true})
	wire, _ = EncodeControllerMonitorResponsePacket(2, revoke2, fixture.jobIdentity, complete)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("complete = %v, %v", decision, err)
	}

	closeBody := ControllerMonitorCloseNotifyBody{Reason: credentialprotocol.CloseReasonNormal}
	wire, _ = EncodeControllerMonitorCloseNotifyPacket(3, fixture.jobIdentity, closeBody)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionSendNormalClose {
		t.Fatalf("monitor close = %v, %v", decision, err)
	}
	wire, _ = EncodeControllerMonitorCloseNotifyPacket(2, fixture.jobIdentity, closeBody)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil || decision != ControllerMonitorTransitionClosedClean {
		t.Fatalf("controller close = %v, %v", decision, err)
	}
	if state.Lost() != ControllerMonitorTransitionClosedClean {
		t.Fatal("expected EOF was not clean")
	}
}

func TestControllerMonitorStatePIDBoundsAliasesAndImmutableHorizon(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	expected := ControllerMonitorExpected{MonitorCredential: fixture.monitorCredential, ControllerCredential: fixture.controllerCredential, AgentPID: fixture.agentPID, JobIdentityDigest: fixture.jobIdentity, MonitorReady: fixture.ready, AuthenticatedSessionHardExpiryUnixNano: 2_000}
	for name, mutate := range map[string]func(*ControllerMonitorExpected){
		"monitor high":    func(value *ControllerMonitorExpected) { value.MonitorCredential.PID = 1 << 31 },
		"controller pid1": func(value *ControllerMonitorExpected) { value.ControllerCredential.PID = 1 },
		"agent alias":     func(value *ControllerMonitorExpected) { value.AgentPID = value.MonitorCredential.PID },
		"zero horizon":    func(value *ControllerMonitorExpected) { value.AuthenticatedSessionHardExpiryUnixNano = 0 },
	} {
		candidate := expected
		mutate(&candidate)
		if _, err := NewControllerMonitorState(candidate); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	state, err := NewControllerMonitorState(expected)
	if err != nil {
		t.Fatal(err)
	}
	expected.AuthenticatedSessionHardExpiryUnixNano = 9_000
	acceptControllerMonitorReady(t, state, fixture)
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 2_001, Bindings: []credentialprotocol.HelperBindingManifestRecord{{BindingID: "http", Mode: credentialprotocol.DeliveryModeHTTPProxy}}}
	wire, _ := EncodeControllerMonitorPrepareBeginPacket(0, byteRange16(0x20), fixture.jobIdentity, begin)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_900); !errors.Is(err, ErrControllerMonitorExpiryWindow) || decision != ControllerMonitorTransitionSendOperationDenied {
		t.Fatalf("mutated caller horizon changed state: %v, %v", decision, err)
	}
}

func TestControllerMonitorStateEventSendCommitsOnce(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	observation, _ := NewControllerMonitorExpiredObservation(byteRange16(0x11))
	if decision, err := state.Observe(observation); err != nil || decision != ControllerMonitorTransitionPendingEventSendable {
		t.Fatalf("observe = %v, %v", decision, err)
	}
	pending, ok := state.PendingEvent()
	if !ok {
		t.Fatal("missing pending event")
	}
	wire, err := EncodeControllerMonitorEventPacket(1, pending.RequestID, fixture.jobIdentity, pending.Body)
	if err != nil {
		t.Fatal(err)
	}
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("event = %v, %v", decision, err)
	}
	if got := state.Snapshot(); got.Phase != ControllerMonitorPhaseRevokeRequired || got.PendingEvent || got.NextMonitorSend != 2 {
		t.Fatalf("snapshot = %#v", got)
	}
	if _, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); !errors.Is(err, ErrControllerMonitorSequence) && !errors.Is(err, ErrControllerMonitorTerminal) {
		t.Fatalf("event replay = %v", err)
	}
}

func TestControllerMonitorStateEndpointAttemptIsOneShot(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	prepareID := byteRange16(0x21)
	bindings := []credentialprotocol.HelperBindingManifestRecord{{BindingID: "ssh-binding", Mode: credentialprotocol.DeliveryModeSSHAgent}}
	begin := credentialprotocol.HelperPrepareBeginBody{Revision: 1, ExpiryUnixNano: 1_900, Bindings: bindings}
	wire, _ := EncodeControllerMonitorPrepareBeginPacket(0, prepareID, fixture.jobIdentity, begin)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 1_800); err != nil {
		t.Fatal(err)
	}
	manifest, _ := credentialprotocol.ComputeHelperManifestSHA256(bindings)
	wire, _ = EncodeControllerMonitorPrepareCommitPacket(1, prepareID, fixture.jobIdentity, credentialprotocol.HelperPrepareCommitBody{Revision: 1, ManifestSHA256: manifest})
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil {
		t.Fatal(err)
	}
	transaction := controllerMonitorEmptyPrepareTransactionDigest(t, prepareID, fixture.jobIdentity, begin, manifest)
	post, _ := ControllerMonitorPreparePostinspectionSHA256(fixture.jobIdentity, 1, fixture.ready.MonitorGeneration, fixture.ready.MountGeneration, manifest, transaction, 0, 0)
	accepted, _ := NewControllerMonitorPrepareAcceptedResponse(1, ControllerMonitorPrepareResult{MountGeneration: fixture.ready.MountGeneration, ManifestSHA256: manifest, PrepareTransactionSHA256: transaction, PreparePostinspectionSHA256: post})
	wire, _ = EncodeControllerMonitorResponsePacket(1, prepareID, fixture.jobIdentity, accepted)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil {
		t.Fatal(err)
	}

	endpointID := byteRange16(0x31)
	configDigest, _ := ControllerMonitorEndpointConfigSHA256(fixture.jobIdentity, 1, 0, "ssh-binding", "endpoint-gen", fixture.ready.MountGeneration, manifest)
	create := ControllerMonitorCreateSSHEndpointBody{Revision: 1, BindingIndex: 0, BindingID: "ssh-binding", EndpointGeneration: "endpoint-gen", ManifestSHA256: manifest, EndpointConfigSHA256: configDigest}
	wire, _ = EncodeControllerMonitorCreateSSHEndpointPacket(2, endpointID, fixture.jobIdentity, create)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil {
		t.Fatal(err)
	}
	rejected, _ := NewControllerMonitorRejectedResponse(ControllerMonitorPacketTypeCreateSSHEndpoint, 1, ControllerMonitorFailureSSHEndpointFailed)
	wire, _ = EncodeControllerMonitorResponsePacket(2, endpointID, fixture.jobIdentity, rejected)
	if _, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil {
		t.Fatal(err)
	}
	if got := state.Snapshot(); got.Phase != ControllerMonitorPhasePrepared || !got.EndpointConsumed {
		t.Fatalf("snapshot = %#v", got)
	}
	wire, _ = EncodeControllerMonitorCreateSSHEndpointPacket(3, byteRange16(0x41), fixture.jobIdentity, create)
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); !errors.Is(err, ErrControllerMonitorTransition) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("second endpoint = %v, %v", decision, err)
	}
}

func TestControllerMonitorStateCleanupRetryBound(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	for attempt := 0; attempt < 3; attempt++ {
		request := byteRange16(byte(0x51 + attempt*16))
		wire, _ := EncodeControllerMonitorRevokePacket(uint64(attempt), request, fixture.jobIdentity, credentialprotocol.HelperRevokeBody{Revision: 1, Reason: credentialprotocol.RevokeReasonRequested})
		if _, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		retry, _ := NewControllerMonitorCleanupRetryResponse(1, ControllerMonitorFailureCleanupIncomplete)
		wire, _ = EncodeControllerMonitorResponsePacket(uint64(attempt+1), request, fixture.jobIdentity, retry)
		if _, err := state.Accept(controllerMonitorMetadata(fixture.monitorCredential, ControllerMonitorDirectionMonitorToController), wire, 0); err != nil {
			t.Fatalf("response %d: %v", attempt, err)
		}
	}
	wire, _ := EncodeControllerMonitorRevokePacket(3, byteRange16(0x71), fixture.jobIdentity, credentialprotocol.HelperRevokeBody{Revision: 1, Reason: credentialprotocol.RevokeReasonRequested})
	if decision, err := state.Accept(controllerMonitorMetadata(fixture.controllerCredential, ControllerMonitorDirectionControllerToMonitor), wire, 0); !errors.Is(err, ErrControllerMonitorCleanupAttempts) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("attempt 4 = %v, %v", decision, err)
	}
}

func TestControllerMonitorStateOpaqueSerializationDoesNotMutate(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	acceptControllerMonitorReady(t, state, fixture)
	before := state.Snapshot()
	if rendered := fmt.Sprintf("%v %#v %+v", state, state, state); strings.Contains(rendered, fixture.ready.MonitorGeneration) || strings.Contains(rendered, "43") {
		t.Fatalf("format leaked state: %s", rendered)
	}
	if _, err := json.Marshal(state); !errors.Is(err, ErrControllerMonitorSerialization) {
		t.Fatalf("marshal = %v", err)
	}
	if err := state.UnmarshalJSON([]byte(`{"phase":"canary"}`)); !errors.Is(err, ErrControllerMonitorSerialization) {
		t.Fatalf("unmarshal = %v", err)
	}
	if after := state.Snapshot(); after != before {
		t.Fatalf("unmarshal mutated state: before %#v after %#v", before, after)
	}
}

func TestControllerMonitorStateHandleHasExactlyOnePrivateOwnerPointer(t *testing.T) {
	typeOf := reflect.TypeOf(ControllerMonitorState{})
	if typeOf.NumField() != 1 {
		t.Fatalf("state fields = %d, want one owner pointer", typeOf.NumField())
	}
	field := typeOf.Field(0)
	if field.Name != "owner" || field.IsExported() || field.Type.Kind() != reflect.Pointer || field.Tag != "" {
		t.Fatalf("state field = %#v", field)
	}
}

func TestControllerMonitorStateValueAndPointerFormattingSerializationAreOpaque(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	value := *state
	for _, opaque := range []any{value, &value, state} {
		for _, verb := range []string{"v", "+v", "#v", "s", "q", "x", "X", "d", "o", "O", "b", "e", "E", "f", "F", "g", "G", "c", "U"} {
			if got := fmt.Sprintf("%"+verb, opaque); got != "ControllerMonitorState" {
				t.Errorf("%T %%%s = %q", opaque, verb, got)
			}
		}
		if _, err := json.Marshal(opaque); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%T JSON marshal = %v", opaque, err)
		}
		if marshaler, ok := opaque.(encoding.TextMarshaler); !ok {
			t.Errorf("%T lacks text marshaler", opaque)
		} else if _, err := marshaler.MarshalText(); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%T text marshal = %v", opaque, err)
		}
		if marshaler, ok := opaque.(encoding.BinaryMarshaler); !ok {
			t.Errorf("%T lacks binary marshaler", opaque)
		} else if _, err := marshaler.MarshalBinary(); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%T binary marshal = %v", opaque, err)
		}
	}

	before := state.Snapshot()
	for name, target := range map[string]*ControllerMonitorState{"value": &value, "pointer": state} {
		if err := json.Unmarshal([]byte(`{"owner":null}`), target); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%s JSON unmarshal = %v", name, err)
		}
		if unmarshaler, ok := any(target).(encoding.TextUnmarshaler); !ok {
			t.Errorf("%s lacks text unmarshaler", name)
		} else if err := unmarshaler.UnmarshalText([]byte("seed")); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%s text unmarshal = %v", name, err)
		}
		if unmarshaler, ok := any(target).(encoding.BinaryUnmarshaler); !ok {
			t.Errorf("%s lacks binary unmarshaler", name)
		} else if err := unmarshaler.UnmarshalBinary([]byte("seed")); !errors.Is(err, ErrControllerMonitorSerialization) {
			t.Errorf("%s binary unmarshal = %v", name, err)
		}
	}
	if state.Snapshot() != before || value.Snapshot() != before {
		t.Fatalf("denied unmarshal mutated state = %#v/%#v, want %#v", state.Snapshot(), value.Snapshot(), before)
	}
}

func TestControllerMonitorStateValueCopiesAliasTransitionsAndLoss(t *testing.T) {
	fixture := controllerMonitorFixture(t)
	state := mustControllerMonitorState(t, fixture)
	alias := *state
	acceptControllerMonitorReady(t, &alias, fixture)
	if state.Snapshot() != alias.Snapshot() || state.Snapshot().Phase != ControllerMonitorPhaseReadyTransferred {
		t.Fatalf("transition aliases = %#v/%#v", state.Snapshot(), alias.Snapshot())
	}

	var wait sync.WaitGroup
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for attempt := 0; attempt < 100; attempt++ {
				_ = state.Decision()
				_ = alias.Snapshot()
			}
		}()
	}
	wait.Add(1)
	go func() { defer wait.Done(); _ = alias.Lost() }()
	wait.Wait()
	if state.Decision() != ControllerMonitorTransitionStopVMRequired || alias.Decision() != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("loss aliases = %v/%v", state.Decision(), alias.Decision())
	}
}

func TestControllerMonitorStateZeroOwnerAndTypedNilAreTerminal(t *testing.T) {
	var zero ControllerMonitorState
	if zero.Decision() != ControllerMonitorTransitionStopVMRequired || zero.Lost() != ControllerMonitorTransitionStopVMRequired || zero.Snapshot().Phase != ControllerMonitorPhaseTerminal {
		t.Fatalf("zero state decisions = %v/%v/%#v", zero.Decision(), zero.Lost(), zero.Snapshot())
	}
	if decision, err := zero.Accept(ControllerMonitorReceiveMetadata{}, nil, 0); !errors.Is(err, ErrControllerMonitorTerminal) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("zero accept = %v/%v", decision, err)
	}
	if decision, err := zero.Observe(ControllerMonitorLocalObservation{}); !errors.Is(err, ErrControllerMonitorTerminal) || decision != ControllerMonitorTransitionStopVMRequired {
		t.Fatalf("zero observe = %v/%v", decision, err)
	}
	var typedNil *ControllerMonitorState
	if typedNil.Decision() != ControllerMonitorTransitionStopVMRequired || typedNil.Lost() != ControllerMonitorTransitionStopVMRequired || typedNil.Snapshot().Phase != ControllerMonitorPhaseTerminal {
		t.Fatalf("typed nil state decisions = %v/%v/%#v", typedNil.Decision(), typedNil.Lost(), typedNil.Snapshot())
	}
	typedNil.SendFailed()
}

func mustControllerMonitorState(t *testing.T, fixture controllerMonitorTestFixture) *ControllerMonitorState {
	t.Helper()
	state, err := NewControllerMonitorState(ControllerMonitorExpected{MonitorCredential: fixture.monitorCredential, ControllerCredential: fixture.controllerCredential, AgentPID: fixture.agentPID, JobIdentityDigest: fixture.jobIdentity, MonitorReady: fixture.ready, AuthenticatedSessionHardExpiryUnixNano: 2_000})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func acceptControllerMonitorReady(t *testing.T, state *ControllerMonitorState, fixture controllerMonitorTestFixture) {
	t.Helper()
	decision, err := state.Accept(fixture.readyMetadata, mustControllerMonitorReadyPacket(t, fixture), 0)
	if err != nil || decision != ControllerMonitorTransitionContinue {
		t.Fatalf("ready = %v, %v", decision, err)
	}
}

func controllerMonitorMetadata(credential ControllerMonitorKernelCredential, direction ControllerMonitorDirection) ControllerMonitorReceiveMetadata {
	return ControllerMonitorReceiveMetadata{Direction: direction, CredentialCount: 1, Credential: credential}
}

func controllerMonitorEmptyPrepareTransactionDigest(t *testing.T, request [16]byte, identity [32]byte, begin credentialprotocol.HelperPrepareBeginBody, manifest [32]byte) [32]byte {
	t.Helper()
	correlation, err := credentialprotocol.NewHelperPrepareTransactionCorrelation(request, identity, begin.Revision, begin.ExpiryUnixNano)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := credentialprotocol.NewHelperPrepareTransaction(correlation, begin, manifest)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transaction.Commit(correlation, credentialprotocol.HelperPrepareCommitBody{Revision: begin.Revision, ManifestSHA256: manifest})
	if err != nil {
		t.Fatal(err)
	}
	return result.TransactionSHA256()
}
