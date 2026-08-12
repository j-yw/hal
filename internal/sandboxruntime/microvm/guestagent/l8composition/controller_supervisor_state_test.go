package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestL8ControllerSupervisorStateOrdersOutstandingResultPendingExitAndBilateralClose(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, agent := newControllerSupervisorVectorState(t, f)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorSupervisorReadyPacket(0, f.ready)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorControllerAttestationPacket(0, f.attestation)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorCompositionAcceptedPacket(1, f.accepted)), ControllerSupervisorTransitionContinue)
	createID := controllerSupervisor16(t, "101112131415161718191a1b1c1d1e1f")
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorCreateJobPacket(1, createID, f.identity, f.create)), ControllerSupervisorTransitionContinue)
	createdRights := [8]ControllerSupervisorRightMetadata{{ControllerSupervisorRightMonitorEndpoint, ControllerSupervisorAccessDuplexSeqpacket, f.created.MonitorGeneration, f.created.MonitorReadySHA256}, {ControllerSupervisorRightMonitorNamespace, ControllerSupervisorAccessNamespaceEnter, f.created.MountGeneration, f.created.MonitorReadySHA256}}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, createdRights[:2], mustControllerSupervisorWire(EncodeControllerSupervisorJobCreatedPacket(2, createID, f.identity, f.created)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, launchRights(t, f), mustControllerSupervisorWire(EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorShimStartedPacket(3, f.launchRequest, f.identity, f.started)), ControllerSupervisorTransitionContinue)
	terminateID := controllerSupervisor16(t, "202122232425262728292a2b2c2d2e2f")
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorTerminateJobPacket(3, terminateID, f.identity, f.terminate)), ControllerSupervisorTransitionContinue)
	observation, err := NewControllerSupervisorShimExitObservation(ControllerSupervisorExitExited, 0, false, ControllerSupervisorMonitorReady)
	if err != nil {
		t.Fatal(err)
	}
	if decision, err := state.ObserveActiveShimExit(observation); err != nil || decision != ControllerSupervisorTransitionSendOutstandingResultBeforePendingEvent {
		t.Fatalf("observe = %v/%v", decision, err)
	}
	terminated := ControllerSupervisorEventBody{EventCode: ControllerSupervisorEventJobTerminated, RequestType: ControllerSupervisorPacketTypeTerminateJob, Revision: 1, JobGeneration: "job-1", MonitorGeneration: "monitor-1", MountGeneration: "mount-1", CgroupGeneration: "cgroup-1", ExitCategory: ControllerSupervisorExitNotApplicable, ZeroPopulation: true, MonitorState: ControllerSupervisorMonitorReady, CleanupCategory: ControllerSupervisorCleanupNotApplicable}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorEventPacket(4, terminateID, f.identity, terminated)), ControllerSupervisorTransitionPendingEventSendable)
	pending, err := state.PendingShimExitedPacket()
	if err != nil {
		t.Fatal(err)
	}
	wantPending := mustControllerSupervisorWire(EncodeControllerSupervisorEventPacket(5, f.launchRequest, f.identity, f.event))
	if !bytes.Equal(pending, wantPending) {
		t.Fatalf("pending = %x, want %x", pending, wantPending)
	}
	pending[0] = 'X'
	again, err := state.PendingShimExitedPacket()
	if err != nil || !bytes.Equal(again, wantPending) {
		t.Fatalf("pending aliases output")
	}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, again, ControllerSupervisorTransitionContinue)
	destroyID := controllerSupervisor16(t, "303132333435363738393a3b3c3d3e3f")
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorDestroyJobPacket(4, destroyID, f.identity, ControllerSupervisorDestroyJobBody(f.terminate))), ControllerSupervisorTransitionContinue)
	destroyed := ControllerSupervisorEventBody{EventCode: ControllerSupervisorEventJobDestroyed, RequestType: ControllerSupervisorPacketTypeDestroyJob, Revision: 1, JobGeneration: "job-1", MonitorGeneration: "monitor-1", MountGeneration: "mount-1", CgroupGeneration: "cgroup-1", ExitCategory: ControllerSupervisorExitNotApplicable, ZeroPopulation: true, MonitorState: ControllerSupervisorMonitorAbsent, CleanupCategory: ControllerSupervisorCleanupComplete}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorEventPacket(6, destroyID, f.identity, destroyed)), ControllerSupervisorTransitionContinue)
	closeBody := ControllerSupervisorCloseNotifyBody{Reason: 1}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorCloseNotifyPacket(5, closeBody)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorCloseNotifyPacket(7, closeBody)), ControllerSupervisorTransitionClosedClean)
	if state.Decision() != ControllerSupervisorTransitionClosedClean {
		t.Fatalf("decision = %v", state.Decision())
	}
	_ = agent
}

func TestL8ControllerSupervisorShimStartedPreSendCommitQueuesExitAndSendLossStopsVM(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, _ := controllerSupervisorStateThroughJob(t, f)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, launchRights(t, f), mustControllerSupervisorWire(EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch)), ControllerSupervisorTransitionContinue)
	// This Accept is D4's validation/commit immediately before atomic send.
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorShimStartedPacket(3, f.launchRequest, f.identity, f.started)), ControllerSupervisorTransitionContinue)
	observation, err := NewControllerSupervisorShimExitObservation(ControllerSupervisorExitExited, 0, false, ControllerSupervisorMonitorReady)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := state.ObserveActiveShimExit(observation)
	if err != nil || decision != ControllerSupervisorTransitionPendingEventSendable {
		t.Fatalf("queued before send = %v/%v", decision, err)
	}
	if decision := state.Lost(); decision != ControllerSupervisorTransitionStopVMRequired || state.Decision() != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("send loss = %v/%v", decision, state.Decision())
	}
}

func TestL8ControllerSupervisorPendingShimExitKeepsCompletedLaunchRevisionAfterTerminateAdvancesJob(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, _ := controllerSupervisorStateThroughJob(t, f)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, launchRights(t, f), mustControllerSupervisorWire(EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorShimStartedPacket(3, f.launchRequest, f.identity, f.started)), ControllerSupervisorTransitionContinue)

	terminateID := controllerSupervisor16(t, "202122232425262728292a2b2c2d2e2f")
	terminate := f.terminate
	terminate.Revision = 2
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorTerminateJobPacket(3, terminateID, f.identity, terminate)), ControllerSupervisorTransitionContinue)
	observation, err := NewControllerSupervisorShimExitObservation(ControllerSupervisorExitExited, 0, false, ControllerSupervisorMonitorReady)
	if err != nil {
		t.Fatal(err)
	}
	if decision, err := state.ObserveActiveShimExit(observation); err != nil || decision != ControllerSupervisorTransitionSendOutstandingResultBeforePendingEvent {
		t.Fatalf("observe = %v/%v", decision, err)
	}
	terminated := ControllerSupervisorEventBody{EventCode: ControllerSupervisorEventJobTerminated, RequestType: ControllerSupervisorPacketTypeTerminateJob, Revision: 2, JobGeneration: "job-1", MonitorGeneration: "monitor-1", MountGeneration: "mount-1", CgroupGeneration: "cgroup-1", ExitCategory: ControllerSupervisorExitNotApplicable, ZeroPopulation: true, MonitorState: ControllerSupervisorMonitorReady, CleanupCategory: ControllerSupervisorCleanupNotApplicable}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorEventPacket(4, terminateID, f.identity, terminated)), ControllerSupervisorTransitionPendingEventSendable)
	pending, err := state.PendingShimExitedPacket()
	if err != nil {
		t.Fatal(err)
	}
	exit := f.event
	exit.Revision = 1
	want := mustControllerSupervisorWire(EncodeControllerSupervisorEventPacket(5, f.launchRequest, f.identity, exit))
	if !bytes.Equal(pending, want) {
		t.Fatalf("pending = %x, want %x", pending, want)
	}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, pending, ControllerSupervisorTransitionContinue)
}

func TestL8ControllerSupervisorSuccessfulTerminateDeniesFreshTerminate(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, _ := controllerSupervisorStateThroughJob(t, f)
	firstID := controllerSupervisor16(t, "202122232425262728292a2b2c2d2e2f")
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorTerminateJobPacket(2, firstID, f.identity, f.terminate)), ControllerSupervisorTransitionContinue)
	terminated := ControllerSupervisorEventBody{EventCode: ControllerSupervisorEventJobTerminated, RequestType: ControllerSupervisorPacketTypeTerminateJob, Revision: 1, JobGeneration: "job-1", MonitorGeneration: "monitor-1", MountGeneration: "mount-1", CgroupGeneration: "cgroup-1", ExitCategory: ControllerSupervisorExitNotApplicable, ZeroPopulation: true, MonitorState: ControllerSupervisorMonitorReady, CleanupCategory: ControllerSupervisorCleanupNotApplicable}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorEventPacket(3, firstID, f.identity, terminated)), ControllerSupervisorTransitionContinue)

	secondID := controllerSupervisor16(t, "303132333435363738393a3b3c3d3e3f")
	second := f.terminate
	second.Revision = 2
	metadata := ControllerSupervisorReceiveMetadata{Direction: ControllerSupervisorDirectionControllerToPID1, Credential: controller, CredentialCount: 1}
	decision, err := state.Accept(metadata, mustControllerSupervisorWire(EncodeControllerSupervisorTerminateJobPacket(3, secondID, f.identity, second)))
	if !errors.Is(err, ErrControllerSupervisorTransition) || decision != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("fresh terminate after success = %v/%v", decision, err)
	}
}

func TestL8ControllerSupervisorOneOutstandingRequestAndPendingEventOrdering(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, _ := controllerSupervisorStateThroughJob(t, f)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, launchRights(t, f), mustControllerSupervisorWire(EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch)), ControllerSupervisorTransitionContinue)
	terminateID := controllerSupervisor16(t, "707172737475767778797a7b7c7d7e7f")
	metadata := ControllerSupervisorReceiveMetadata{Direction: ControllerSupervisorDirectionControllerToPID1, Credential: controller, CredentialCount: 1}
	decision, err := state.Accept(metadata, mustControllerSupervisorWire(EncodeControllerSupervisorTerminateJobPacket(3, terminateID, f.identity, f.terminate)))
	if !errors.Is(err, ErrControllerSupervisorOutstandingRequest) || decision != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("second request = %v/%v", decision, err)
	}
	state, pid1, controller, _ = controllerSupervisorStateThroughJob(t, f)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, launchRights(t, f), mustControllerSupervisorWire(EncodeControllerSupervisorLaunchShimPacket(2, f.launchRequest, f.identity, f.launch)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorShimStartedPacket(3, f.launchRequest, f.identity, f.started)), ControllerSupervisorTransitionContinue)
	observation, _ := NewControllerSupervisorShimExitObservation(ControllerSupervisorExitExited, 0, false, ControllerSupervisorMonitorReady)
	if decision, err := state.ObserveActiveShimExit(observation); err != nil || decision != ControllerSupervisorTransitionPendingEventSendable {
		t.Fatalf("observe = %v/%v", decision, err)
	}
	metadata = ControllerSupervisorReceiveMetadata{Direction: ControllerSupervisorDirectionControllerToPID1, Credential: controller, CredentialCount: 1}
	decision, err = state.Accept(metadata, mustControllerSupervisorWire(EncodeControllerSupervisorTerminateJobPacket(3, terminateID, f.identity, f.terminate)))
	if !errors.Is(err, ErrControllerSupervisorPendingEvent) || decision != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("request before pending event = %v/%v", decision, err)
	}
}

func TestL8ControllerSupervisorFixedLedgerExactBoundsAndNoEviction(t *testing.T) {
	state := &controllerSupervisorStateOwner{}
	create := controllerSupervisor16(t, "00000000000000000000000000000001")
	if err := state.chargeRequestLocked(ControllerSupervisorPacketTypeCreateJob, create); err != nil {
		t.Fatal(err)
	}
	if err := state.chargeRequestLocked(ControllerSupervisorPacketTypeCreateJob, controllerSupervisor16(t, "00000000000000000000000000000002")); !errors.Is(err, ErrControllerSupervisorRequestReuse) {
		t.Fatalf("second create = %v", err)
	}
	for index := 0; index < MaxControllerSupervisorLaunches; index++ {
		var id [16]byte
		binary.BigEndian.PutUint64(id[8:], uint64(index+100))
		if err := state.chargeRequestLocked(ControllerSupervisorPacketTypeLaunchShim, id); err != nil {
			t.Fatalf("launch %d = %v", index, err)
		}
	}
	var plusOne [16]byte
	binary.BigEndian.PutUint64(plusOne[8:], 9999)
	if err := state.chargeRequestLocked(ControllerSupervisorPacketTypeLaunchShim, plusOne); !errors.Is(err, ErrControllerSupervisorLaunchLimit) {
		t.Fatalf("launch plus one = %v", err)
	}
	firstLaunch := state.requests.launches[0]
	if err := state.chargeRequestLocked(ControllerSupervisorPacketTypeLaunchShim, firstLaunch); !errors.Is(err, ErrControllerSupervisorRequestReuse) {
		t.Fatalf("evicted/reused launch = %v", err)
	}
	for index := 0; index < 3; index++ {
		var id [16]byte
		binary.BigEndian.PutUint64(id[8:], uint64(20000+index))
		kind := ControllerSupervisorPacketTypeTerminateJob
		if index == 2 {
			kind = ControllerSupervisorPacketTypeDestroyJob
		}
		if err := state.chargeRequestLocked(kind, id); err != nil {
			t.Fatalf("cleanup %d = %v", index, err)
		}
	}
	var cleanupPlusOne [16]byte
	binary.BigEndian.PutUint64(cleanupPlusOne[8:], 30000)
	if err := state.chargeRequestLocked(ControllerSupervisorPacketTypeDestroyJob, cleanupPlusOne); !errors.Is(err, ErrControllerSupervisorTransition) {
		t.Fatalf("shared cleanup plus one = %v", err)
	}
	if got := 1 + int(state.requests.launchCount) + int(state.requests.cleanupCount); got != 4100 {
		t.Fatalf("ledger entries = %d, want 4100", got)
	}
}

func TestL8ControllerSupervisorOperationCleanupOutcomeMatrix(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	requestID := controllerSupervisor16(t, "606162636465666768696a6b6c6d6e6f")
	tests := []struct {
		name         string
		request      ControllerSupervisorPacketType
		event        ControllerSupervisorEventCode
		failure      ControllerSupervisorFailureCode
		cleanup      ControllerSupervisorCleanupCategory
		wantPhase    controllerSupervisorPhase
		wantDecision ControllerSupervisorTransitionDecision
		denyLaunch   bool
	}{
		{"create resource final", ControllerSupervisorPacketTypeCreateJob, ControllerSupervisorEventOperationFailed, ControllerSupervisorFailureResourceLimit, ControllerSupervisorCleanupNotApplicable, controllerSupervisorPhaseStopped, ControllerSupervisorTransitionStopVMRequired, false},
		{"create rollback final", ControllerSupervisorPacketTypeCreateJob, ControllerSupervisorEventOperationFailed, ControllerSupervisorFailureCreateFailed, ControllerSupervisorCleanupComplete, controllerSupervisorPhaseStopped, ControllerSupervisorTransitionStopVMRequired, false},
		{"create retry final", ControllerSupervisorPacketTypeCreateJob, ControllerSupervisorEventCleanupObserved, ControllerSupervisorFailureCleanupIncomplete, ControllerSupervisorCleanupRetryRequired, controllerSupervisorPhaseStopped, ControllerSupervisorTransitionStopVMRequired, false},
		{"launch denial", ControllerSupervisorPacketTypeLaunchShim, ControllerSupervisorEventOperationFailed, ControllerSupervisorFailureResourceLimit, ControllerSupervisorCleanupNotApplicable, controllerSupervisorPhaseJob, ControllerSupervisorTransitionContinue, false},
		{"launch cleanup complete", ControllerSupervisorPacketTypeLaunchShim, ControllerSupervisorEventOperationFailed, ControllerSupervisorFailureLaunchFailed, ControllerSupervisorCleanupComplete, controllerSupervisorPhaseJob, ControllerSupervisorTransitionContinue, false},
		{"launch retry denies launch", ControllerSupervisorPacketTypeLaunchShim, ControllerSupervisorEventCleanupObserved, ControllerSupervisorFailureCleanupIncomplete, ControllerSupervisorCleanupRetryRequired, controllerSupervisorPhaseJob, ControllerSupervisorTransitionContinue, true},
		{"terminate complete retries only terminate", ControllerSupervisorPacketTypeTerminateJob, ControllerSupervisorEventOperationFailed, ControllerSupervisorFailureTerminateFailed, ControllerSupervisorCleanupComplete, controllerSupervisorPhaseJob, ControllerSupervisorTransitionContinue, true},
		{"terminate retry", ControllerSupervisorPacketTypeTerminateJob, ControllerSupervisorEventCleanupObserved, ControllerSupervisorFailureCleanupIncomplete, ControllerSupervisorCleanupRetryRequired, controllerSupervisorPhaseJob, ControllerSupervisorTransitionContinue, true},
		{"destroy complete retries destroy", ControllerSupervisorPacketTypeDestroyJob, ControllerSupervisorEventOperationFailed, ControllerSupervisorFailureDestroyFailed, ControllerSupervisorCleanupComplete, controllerSupervisorPhaseDestroyRetry, ControllerSupervisorTransitionContinue, true},
		{"destroy retry", ControllerSupervisorPacketTypeDestroyJob, ControllerSupervisorEventCleanupObserved, ControllerSupervisorFailureCleanupIncomplete, ControllerSupervisorCleanupRetryRequired, controllerSupervisorPhaseDestroyRetry, ControllerSupervisorTransitionContinue, true},
		{"stop", ControllerSupervisorPacketTypeLaunchShim, ControllerSupervisorEventCleanupObserved, ControllerSupervisorFailureCleanupIncomplete, ControllerSupervisorCleanupStopVMRequired, controllerSupervisorPhaseStopped, ControllerSupervisorTransitionStopVMRequired, false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			state, _, _, _ := newControllerSupervisorVectorState(t, f)
			state.owner.phase = controllerSupervisorPhaseJob
			state.owner.job = controllerSupervisorJob{revision: 1, job: "job-1", monitor: "monitor-1", mount: "mount-1", cgroup: "cgroup-1", limit: ControllerSupervisorLimitSetID}
			state.owner.outstanding = controllerSupervisorOutstanding{packetType: test.request, requestID: requestID, revision: 1}
			event := ControllerSupervisorEventBody{EventCode: test.event, RequestType: test.request, FailureCode: test.failure, Revision: 1, JobGeneration: "job-1", MonitorGeneration: "monitor-1", MountGeneration: "mount-1", CgroupGeneration: "cgroup-1", ExitCategory: ControllerSupervisorExitNotApplicable, MonitorState: ControllerSupervisorMonitorReady, CleanupCategory: test.cleanup}
			if test.request == ControllerSupervisorPacketTypeLaunchShim {
				launchID, err := ControllerSupervisorLaunchID(requestID)
				if err != nil {
					t.Fatal(err)
				}
				event.LaunchID = launchID
				state.owner.outstanding.launchID = string(event.LaunchID)
			}
			wire, err := EncodeControllerSupervisorEventPacket(0, requestID, f.identity, event)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := DecodeControllerSupervisorPacket(wire)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := state.owner.acceptEventLocked(packet)
			if err != nil || decision != test.wantDecision {
				t.Fatalf("decision = %v/%v", decision, err)
			}
			if state.owner.phase != test.wantPhase || state.owner.launchesDenied != test.denyLaunch {
				t.Fatalf("phase/deny = %v/%v", state.owner.phase, state.owner.launchesDenied)
			}
		})
	}
}

func TestL8ControllerSupervisorStateSequenceExhaustionDoesNotWrap(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, _ := newControllerSupervisorVectorState(t, f)
	state.owner.nextPID1 = MaxControllerSupervisorPacketsPerDirection - 1
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorSupervisorReadyPacket(MaxControllerSupervisorPacketsPerDirection-1, f.ready)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorControllerAttestationPacket(0, f.attestation)), ControllerSupervisorTransitionContinue)
	wire := mustControllerSupervisorWire(EncodeControllerSupervisorCompositionAcceptedPacket(MaxControllerSupervisorPacketsPerDirection-1, f.accepted))
	binary.BigEndian.PutUint64(wire[8:16], MaxControllerSupervisorPacketsPerDirection)
	metadata := ControllerSupervisorReceiveMetadata{Direction: ControllerSupervisorDirectionPID1ToController, Credential: pid1, CredentialCount: 1}
	decision, err := state.Accept(metadata, wire)
	if err == nil || decision != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("exhausted accept = %v/%v", decision, err)
	}
}

func TestL8ControllerSupervisorStateConcurrentDecisionAndLossIsRaceSafe(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, _, _, _ := newControllerSupervisorVectorState(t, f)
	var wait sync.WaitGroup
	for i := 0; i < 64; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 100; j++ {
				_ = state.Decision()
			}
		}()
	}
	wait.Add(1)
	go func() { defer wait.Done(); _ = state.Lost() }()
	wait.Wait()
	if state.Decision() != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("decision = %v", state.Decision())
	}
}

func TestL8ControllerSupervisorStateValueCopiesAliasTransitionsAndLoss(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, _ := newControllerSupervisorVectorState(t, f)
	alias := *state
	acceptControllerSupervisorState(t, &alias, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorSupervisorReadyPacket(0, f.ready)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorControllerAttestationPacket(0, f.attestation)), ControllerSupervisorTransitionContinue)
	if alias.Decision() != ControllerSupervisorTransitionContinue || state.Decision() != ControllerSupervisorTransitionContinue {
		t.Fatalf("transition alias decisions = %v/%v", alias.Decision(), state.Decision())
	}

	var wait sync.WaitGroup
	for i := 0; i < 64; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 100; j++ {
				_ = alias.Decision()
				_ = state.Decision()
			}
		}()
	}
	wait.Add(1)
	go func() { defer wait.Done(); _ = alias.Lost() }()
	wait.Wait()
	if state.Decision() != ControllerSupervisorTransitionStopVMRequired || alias.Decision() != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("loss alias decisions = %v/%v", state.Decision(), alias.Decision())
	}
}

func TestL8ControllerSupervisorStateHandleLayoutFormattingAndSerializationAreOpaque(t *testing.T) {
	typeOf := reflect.TypeOf(ControllerSupervisorState{})
	if typeOf.NumField() != 1 {
		t.Fatalf("state fields = %d, want one owner pointer", typeOf.NumField())
	}
	field := typeOf.Field(0)
	if field.Name != "owner" || field.IsExported() || field.Type.Kind() != reflect.Pointer || field.Tag != "" {
		t.Fatalf("state field = %#v", field)
	}

	f := controllerSupervisorVectorFixture(t)
	state, _, _, _ := newControllerSupervisorVectorState(t, f)
	value := *state
	for _, opaque := range []any{value, &value, state} {
		for _, verb := range []string{"v", "+v", "#v", "s", "q", "x", "X", "d", "o", "O", "b", "e", "E", "f", "F", "g", "G", "c", "U"} {
			formatted := fmt.Sprintf("%"+verb, opaque)
			if formatted != "ControllerSupervisorState" {
				t.Errorf("%T %%%s = %q", opaque, verb, formatted)
			}
			for _, seed := range []string{"boot-1", "helper-1", "supervisor-1"} {
				if strings.Contains(formatted, seed) {
					t.Fatalf("%T %%%s leaked %q", opaque, verb, seed)
				}
			}
		}
		if _, err := json.Marshal(opaque); !errors.Is(err, ErrControllerSupervisorSerialization) {
			t.Errorf("%T JSON marshal = %v", opaque, err)
		}
		if marshaler, ok := opaque.(encoding.TextMarshaler); !ok {
			t.Errorf("%T lacks text marshaler", opaque)
		} else if _, err := marshaler.MarshalText(); !errors.Is(err, ErrControllerSupervisorSerialization) {
			t.Errorf("%T text marshal = %v", opaque, err)
		}
		if marshaler, ok := opaque.(encoding.BinaryMarshaler); !ok {
			t.Errorf("%T lacks binary marshaler", opaque)
		} else if _, err := marshaler.MarshalBinary(); !errors.Is(err, ErrControllerSupervisorSerialization) {
			t.Errorf("%T binary marshal = %v", opaque, err)
		}
	}

	before := state.Decision()
	for name, target := range map[string]*ControllerSupervisorState{"value": &value, "pointer": state} {
		if err := json.Unmarshal([]byte(`{"owner":null}`), target); !errors.Is(err, ErrControllerSupervisorSerialization) {
			t.Errorf("%s JSON unmarshal = %v", name, err)
		}
		if unmarshaler, ok := any(target).(encoding.TextUnmarshaler); !ok {
			t.Errorf("%s lacks text unmarshaler", name)
		} else if err := unmarshaler.UnmarshalText([]byte("seed")); !errors.Is(err, ErrControllerSupervisorSerialization) {
			t.Errorf("%s text unmarshal = %v", name, err)
		}
		if unmarshaler, ok := any(target).(encoding.BinaryUnmarshaler); !ok {
			t.Errorf("%s lacks binary unmarshaler", name)
		} else if err := unmarshaler.UnmarshalBinary([]byte("seed")); !errors.Is(err, ErrControllerSupervisorSerialization) {
			t.Errorf("%s binary unmarshal = %v", name, err)
		}
	}
	if state.Decision() != before || value.Decision() != before {
		t.Fatalf("denied unmarshal mutated state = %v/%v, want %v", state.Decision(), value.Decision(), before)
	}

	var zero ControllerSupervisorState
	if zero.Decision() != ControllerSupervisorTransitionStopVMRequired || zero.Lost() != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("zero decisions = %v/%v", zero.Decision(), zero.Lost())
	}
}

func TestL8ControllerSupervisorStateFailClosesReplayGapReuseSecondRequestAndImpossibleExit(t *testing.T) {
	f := controllerSupervisorVectorFixture(t)
	state, pid1, controller, _ := newControllerSupervisorVectorState(t, f)
	ready := mustControllerSupervisorWire(EncodeControllerSupervisorSupervisorReadyPacket(0, f.ready))
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, ready, ControllerSupervisorTransitionContinue)
	metadata := ControllerSupervisorReceiveMetadata{Direction: ControllerSupervisorDirectionPID1ToController, Credential: pid1, CredentialCount: 1}
	if decision, err := state.Accept(metadata, ready); err == nil || decision != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("replay = %v/%v", decision, err)
	}
	if decision, err := state.Accept(metadata, ready); err != ErrControllerSupervisorTerminal || decision != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("after terminal = %v/%v", decision, err)
	}
	state, _, _, _ = newControllerSupervisorVectorState(t, f)
	bad, err := NewControllerSupervisorShimExitObservation(ControllerSupervisorExitUnknown, 1, false, ControllerSupervisorMonitorReady)
	if err == nil || bad != (ControllerSupervisorShimExitObservation{}) {
		t.Fatalf("bad observation = %v/%v", bad, err)
	}
	valid, err := NewControllerSupervisorShimExitObservation(ControllerSupervisorExitExited, 0, false, ControllerSupervisorMonitorAbsent)
	if err == nil || valid != (ControllerSupervisorShimExitObservation{}) {
		t.Fatalf("impossible monitor = %v/%v", valid, err)
	}
	if decision, err := state.ObserveActiveShimExit(ControllerSupervisorShimExitObservation{}); err == nil || decision != ControllerSupervisorTransitionStopVMRequired {
		t.Fatalf("unbound exit = %v/%v", decision, err)
	}
	_ = controller
}

func newControllerSupervisorVectorState(t *testing.T, f controllerSupervisorFixture) (*ControllerSupervisorState, ControllerSupervisorKernelCredential, ControllerSupervisorKernelCredential, ControllerSupervisorKernelCredential) {
	t.Helper()
	pid1 := ControllerSupervisorKernelCredential{PID: 1}
	controller := ControllerSupervisorKernelCredential{PID: 2147483647}
	agent := ControllerSupervisorKernelCredential{PID: 2, UID: 1000, GID: 1000}
	wire, err := EncodeProcessDescriptor(f.attestation.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewControllerSupervisorState(ControllerSupervisorExpected{PID1Credential: pid1, ControllerCredential: controller, AgentPID: agent.PID, SupervisorReady: f.ready, ControllerDescriptor: f.attestation.Descriptor, ControllerDescriptorSHA256: sha256.Sum256(wire), CompositionSHA256: f.accepted.CompositionSHA256, JobIdentityDigest: f.identity})
	if err != nil {
		t.Fatal(err)
	}
	return state, pid1, controller, agent
}
func controllerSupervisorStateThroughJob(t *testing.T, f controllerSupervisorFixture) (*ControllerSupervisorState, ControllerSupervisorKernelCredential, ControllerSupervisorKernelCredential, ControllerSupervisorKernelCredential) {
	t.Helper()
	state, pid1, controller, agent := newControllerSupervisorVectorState(t, f)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorSupervisorReadyPacket(0, f.ready)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorControllerAttestationPacket(0, f.attestation)), ControllerSupervisorTransitionContinue)
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, nil, mustControllerSupervisorWire(EncodeControllerSupervisorCompositionAcceptedPacket(1, f.accepted)), ControllerSupervisorTransitionContinue)
	requestID := controllerSupervisor16(t, "101112131415161718191a1b1c1d1e1f")
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionControllerToPID1, controller, nil, mustControllerSupervisorWire(EncodeControllerSupervisorCreateJobPacket(1, requestID, f.identity, f.create)), ControllerSupervisorTransitionContinue)
	rights := [8]ControllerSupervisorRightMetadata{{ControllerSupervisorRightMonitorEndpoint, ControllerSupervisorAccessDuplexSeqpacket, f.created.MonitorGeneration, f.created.MonitorReadySHA256}, {ControllerSupervisorRightMonitorNamespace, ControllerSupervisorAccessNamespaceEnter, f.created.MountGeneration, f.created.MonitorReadySHA256}}
	acceptControllerSupervisorState(t, state, ControllerSupervisorDirectionPID1ToController, pid1, rights[:2], mustControllerSupervisorWire(EncodeControllerSupervisorJobCreatedPacket(2, requestID, f.identity, f.created)), ControllerSupervisorTransitionContinue)
	return state, pid1, controller, agent
}
func mustControllerSupervisorWire(wire []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return wire
}
func acceptControllerSupervisorState(t *testing.T, state *ControllerSupervisorState, direction ControllerSupervisorDirection, credential ControllerSupervisorKernelCredential, rights []ControllerSupervisorRightMetadata, wire []byte, want ControllerSupervisorTransitionDecision) {
	t.Helper()
	metadata := ControllerSupervisorReceiveMetadata{Direction: direction, Credential: credential, CredentialCount: 1, RightsCount: uint32(len(rights))}
	copy(metadata.Rights[:], rights)
	decision, err := state.Accept(metadata, wire)
	if err != nil || decision != want {
		t.Fatalf("accept = %v/%v, want %v", decision, err, want)
	}
}
func launchRights(t *testing.T, f controllerSupervisorFixture) []ControllerSupervisorRightMetadata {
	t.Helper()
	digest, err := ControllerSupervisorLaunchShimSHA256(f.identity, f.launch)
	if err != nil {
		t.Fatal(err)
	}
	return []ControllerSupervisorRightMetadata{{ControllerSupervisorRightMonitorNamespace, ControllerSupervisorAccessNamespaceEnter, f.launch.MountGeneration, digest}, {ControllerSupervisorRightWorkdir, ControllerSupervisorAccessDirectoryChdir, f.launch.MountGeneration, digest}, {ControllerSupervisorRightExecutable, ControllerSupervisorAccessExecutableRead, f.launch.JobGeneration, f.launch.ExecutableSHA256}, {ControllerSupervisorRightStdinRead, ControllerSupervisorAccessPipeRead, f.launch.LaunchID, digest}, {ControllerSupervisorRightStdoutWrite, ControllerSupervisorAccessPipeWrite, f.launch.LaunchID, digest}, {ControllerSupervisorRightStderrWrite, ControllerSupervisorAccessPipeWrite, f.launch.LaunchID, digest}, {ControllerSupervisorRightStartGateRead, ControllerSupervisorAccessPipeRead, f.launch.LaunchID, digest}, {ControllerSupervisorRightLaunchBlockRead, ControllerSupervisorAccessSealedPipeRead, f.launch.LaunchID, f.launch.LaunchBlockSHA256}}
}
