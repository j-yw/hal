package l7network

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestRecoveredVMTerminationBindingRejectsMismatchAndIncompleteAbsence(t *testing.T) {
	identity := testIdentity()
	complete := RecoveredVMTerminationObservation{
		Identity: identity, ProcessGeneration: "process-generation-a",
		SupervisorGeneration: "supervisor-generation-a", Stopped: true, Reaped: true,
	}
	binding, err := NewRecoveredVMTerminationBinding(complete)
	if err != nil || binding == nil || binding.VMTerminationProofID() == "" {
		t.Fatalf("complete recovered binding = %T, %v", binding, err)
	}
	if !networkenforcement.EnforcementCorrelationsEqual(binding.VMCorrelation(), correlation(identity)) {
		t.Fatalf("recovered correlation = %#v", binding.VMCorrelation())
	}

	invalid := complete
	invalid.Identity.SandboxID = ""
	if recovered, err := NewRecoveredVMTerminationBinding(invalid); recovered != nil || !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("invalid identity = %T, %v", recovered, err)
	}

	verifier := NewRecoveredVMTerminationVerifier()
	request := VMTerminationRequest{
		Correlation: correlation(identity), TerminationProofID: binding.VMTerminationProofID(), Binding: binding,
	}
	proof, err := verifier.VerifyVMTermination(context.Background(), request)
	if err != nil || !proof.Stopped || !proof.Reaped || proof.TerminationProofID != binding.VMTerminationProofID() {
		t.Fatalf("complete verify = %#v, %v", proof, err)
	}

	var typedNil *recoveredVMTerminationBinding
	if _, err := verifier.VerifyVMTermination(context.Background(), VMTerminationRequest{
		Correlation: request.Correlation, TerminationProofID: request.TerminationProofID, Binding: typedNil,
	}); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("typed nil = %v", err)
	}
	if _, err := verifier.VerifyVMTermination(context.Background(), VMTerminationRequest{
		Correlation: request.Correlation, TerminationProofID: request.TerminationProofID, Binding: testTerminatedVMBinding(),
	}); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("foreign binding = %v", err)
	}

	mismatch := request
	mismatch.Correlation.RuleGenerationID = "other-rule-generation"
	if _, err := verifier.VerifyVMTermination(context.Background(), mismatch); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("identity mismatch = %v", err)
	}
	wrongProof := request
	wrongProof.TerminationProofID = "recovered-ffffffffffffffffffffffffffffffff"
	if _, err := verifier.VerifyVMTermination(context.Background(), wrongProof); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("proof mismatch = %v", err)
	}

	wrongGeneration := complete
	wrongGeneration.Identity.RuleGenerationID = "other-rule-generation"
	wrongBinding, err := NewRecoveredVMTerminationBinding(wrongGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyVMTermination(context.Background(), VMTerminationRequest{
		Correlation: correlation(identity), TerminationProofID: wrongBinding.VMTerminationProofID(), Binding: wrongBinding,
	}); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("wrong generation = %v", err)
	}

	running := complete
	running.Stopped = false
	runningBinding, err := NewRecoveredVMTerminationBinding(running)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyVMTermination(context.Background(), VMTerminationRequest{
		Correlation: correlation(identity), TerminationProofID: runningBinding.VMTerminationProofID(), Binding: runningBinding,
	}); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("still running = %v", err)
	}

	unreaped := complete
	unreaped.Reaped = false
	unreapedBinding, err := NewRecoveredVMTerminationBinding(unreaped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyVMTermination(context.Background(), VMTerminationRequest{
		Correlation: correlation(identity), TerminationProofID: unreapedBinding.VMTerminationProofID(), Binding: unreapedBinding,
	}); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("unreaped = %v", err)
	}
}

func TestRecoveredVMTerminationBindingDrivesCleanupAfterVMQuiesced(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), tapIfIndex: 41, ruleDigest: "old-rule-digest",
		proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	journal := &loadedJournalStore{sequence: sequence, record: record}
	topology := newFakeTopology(sequence)
	recovery := &fakeRecoveryTopology{sequence: sequence, lifecycle: topology}
	reconciler, err := NewReconciler(ReconcilerOptions{
		Recovery: recovery, TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: NewRecoveredVMTerminationVerifier(), Journal: journal, CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	binding, err := NewRecoveredVMTerminationBinding(RecoveredVMTerminationObservation{
		Identity: identity, ProcessGeneration: "process-generation-a",
		SupervisorGeneration: "supervisor-generation-a", Stopped: true, Reaped: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), identity, binding); err != nil {
		t.Fatal(err)
	}
	assertSubsequence(t, sequence.snapshot(), []string{"rules_cleanup", "tap_delete", "topology_stop", "journal_remove", "journal_release"})
}

func TestRecoveredVMTerminationVerifierRejectsForeignBindingBeforeCleanupMutation(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), tapIfIndex: 41, proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	reconciler, err := NewReconciler(ReconcilerOptions{
		Recovery: &fakeRecoveryTopology{sequence: sequence, lifecycle: newFakeTopology(sequence)},
		TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: NewRecoveredVMTerminationVerifier(),
		Journal:       &loadedJournalStore{sequence: sequence, record: record},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	if err := session.CleanupAfterVMQuiesced(context.Background(), identity, testTerminatedVMBinding()); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("foreign binding cleanup = %v", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("foreign binding mutated recovered cleanup: %#v", got)
	}
}
