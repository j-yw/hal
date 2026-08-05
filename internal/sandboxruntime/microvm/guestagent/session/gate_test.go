package session

import (
	"errors"
	"reflect"
	"testing"
)

func TestGenerationGateClaimsOnceAndRejectsConcurrentConnectionWithoutPerturbation(t *testing.T) {
	var losses []LossEvent
	gate, err := NewGenerationGate("boot-gen-1", GateHooks{NotifyLoss: func(event LossEvent) { losses = append(losses, event) }})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := gate.Begin()
	if err != nil {
		t.Fatal(err)
	}
	guest, _ := newEstablishedPair(t, ChannelControl)
	if err := attempt.Authenticate(guest); err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if !gate.Claimed() || !gate.Ready() {
		t.Fatal("authenticated generation is not claimed and ready")
	}
	if _, err := gate.Begin(); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("second Begin() error = %v, want ErrAlreadyActive", err)
	}
	if !guest.Established() || len(losses) != 0 {
		t.Fatal("rejected second connection perturbed active session")
	}
}

func TestConcurrentPreAuthWinnerRevokesLateCandidateOnly(t *testing.T) {
	gate, _ := NewGenerationGate("boot-gen-1", GateHooks{})
	first, _ := gate.Begin()
	second, _ := gate.Begin()
	winning, _ := newEstablishedPair(t, ChannelControl)
	late, _ := newEstablishedPair(t, ChannelControl)
	if err := first.Authenticate(winning); err != nil {
		t.Fatal(err)
	}
	if err := second.Authenticate(late); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("late Authenticate() = %v, want ErrAlreadyActive", err)
	}
	if !late.Revoked() || !winning.Established() || !gate.Claimed() {
		t.Fatal("late candidate rejection perturbed winner or retained candidate")
	}
}

func TestGenerationGatePreAuthFailuresDoNotClaimUntilCap(t *testing.T) {
	var losses []LossEvent
	gate, _ := NewGenerationGate("boot-gen-1", GateHooks{NotifyLoss: func(event LossEvent) { losses = append(losses, event) }})
	for index := 0; index < MaxPreAuthConnections; index++ {
		attempt, err := gate.Begin()
		if err != nil {
			t.Fatalf("Begin(%d) error: %v", index, err)
		}
		if gate.Claimed() {
			t.Fatalf("pre-auth attempt %d claimed generation", index)
		}
		attempt.Fail()
		if index+1 < MaxPreAuthConnections && !gate.Ready() {
			t.Fatalf("gate not ready before cap at attempt %d", index)
		}
	}
	if gate.Ready() || gate.Claimed() {
		t.Fatal("gate remains ready/claimed after pre-auth cap")
	}
	if _, err := gate.Begin(); !errors.Is(err, ErrReconnectRejected) {
		t.Fatalf("Begin(after cap) error = %v, want ErrReconnectRejected", err)
	}
	if len(losses) != 1 || losses[0].Reason != LossReasonPreAuthExhausted || len(losses[0].JobGenerations) != 0 {
		t.Fatalf("losses = %#v", losses)
	}
}

func TestThirdPreAuthAttemptMayClaimButThirdFailureIsTerminal(t *testing.T) {
	successGate, _ := NewGenerationGate("boot-gen-success", GateHooks{})
	for index := 0; index < MaxPreAuthConnections-1; index++ {
		attempt, err := successGate.Begin()
		if err != nil {
			t.Fatal(err)
		}
		attempt.Fail()
	}
	third, err := successGate.Begin()
	if err != nil {
		t.Fatalf("third Begin() error: %v", err)
	}
	state, _ := newEstablishedPair(t, ChannelControl)
	if err := third.Authenticate(state); err != nil {
		t.Fatalf("third Authenticate() error: %v", err)
	}
	if !successGate.Ready() || !successGate.Claimed() || !state.Established() {
		t.Fatal("successful third attempt did not claim a ready generation")
	}

	failureGate, _ := NewGenerationGate("boot-gen-failure", GateHooks{})
	for index := 0; index < MaxPreAuthConnections; index++ {
		attempt, err := failureGate.Begin()
		if err != nil {
			t.Fatal(err)
		}
		attempt.Fail()
	}
	if failureGate.Ready() || failureGate.Claimed() {
		t.Fatal("failed third attempt did not make readiness terminal")
	}
	if _, err := failureGate.Begin(); !errors.Is(err, ErrReconnectRejected) {
		t.Fatalf("Begin(after third failure) = %v, want ErrReconnectRejected", err)
	}
}

func TestGenerationLossRevokesStateJobsAndReconnect(t *testing.T) {
	var revoked []string
	var losses []LossEvent
	gate, _ := NewGenerationGate("boot-gen-1", GateHooks{
		RevokeJob:  func(job string) { revoked = append(revoked, job) },
		NotifyLoss: func(event LossEvent) { losses = append(losses, event) },
	})
	attempt, _ := gate.Begin()
	guest, _ := newEstablishedPair(t, ChannelControl)
	if err := attempt.Authenticate(guest); err != nil {
		t.Fatal(err)
	}
	if err := gate.RegisterJobGeneration("job-z"); err != nil {
		t.Fatal(err)
	}
	if err := gate.RegisterJobGeneration("job-a"); err != nil {
		t.Fatal(err)
	}
	gate.Lose(LossReasonEOF)
	if !guest.Revoked() || gate.Ready() || gate.Claimed() {
		t.Fatal("loss did not revoke active generation")
	}
	if !reflect.DeepEqual(revoked, []string{"job-a", "job-z"}) {
		t.Fatalf("revoked = %#v", revoked)
	}
	if len(losses) != 1 || losses[0].Reason != LossReasonEOF || !reflect.DeepEqual(losses[0].JobGenerations, revoked) {
		t.Fatalf("losses = %#v", losses)
	}
	if _, err := gate.Begin(); !errors.Is(err, ErrReconnectRejected) {
		t.Fatalf("Begin(after loss) = %v", err)
	}
	gate.Lose(LossReasonTimeout)
	if len(losses) != 1 || len(revoked) != 2 {
		t.Fatal("duplicate loss repeated callbacks")
	}
}

func TestGenerationGateRejectsUnauthenticatedAndUnsafeJobState(t *testing.T) {
	gate, _ := NewGenerationGate("boot-gen-1", GateHooks{})
	if err := gate.RegisterJobGeneration("job-1"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("RegisterJobGeneration(before auth) = %v", err)
	}
	attempt, _ := gate.Begin()
	guest, _ := newEstablishedPairBeforeFinished(t, ChannelControl)
	if err := attempt.Authenticate(guest); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Authenticate(before Finished) = %v", err)
	}
	if err := gate.RegisterJobGeneration("../../secret"); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("RegisterJobGeneration(unsafe) = %v", err)
	}
}

func TestLosingOneGenerationCannotAffectAnother(t *testing.T) {
	left, _ := NewGenerationGate("boot-gen-left", GateHooks{})
	right, _ := NewGenerationGate("boot-gen-right", GateHooks{})
	leftAttempt, _ := left.Begin()
	rightAttempt, _ := right.Begin()
	leftState, _ := newEstablishedPair(t, ChannelControl)
	rightState, _ := newEstablishedPair(t, ChannelControl)
	if err := leftAttempt.Authenticate(leftState); err != nil {
		t.Fatal(err)
	}
	if err := rightAttempt.Authenticate(rightState); err != nil {
		t.Fatal(err)
	}
	left.Lose(LossReasonGenerationDrift)
	if !leftState.Revoked() || !rightState.Established() || !right.Ready() || !right.Claimed() {
		t.Fatal("generation-local loss perturbed another generation")
	}
}
