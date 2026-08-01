package l7network

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestFirecrackerHostTopologyPrepareStopsAtHostPreparedWithoutGuestProof(t *testing.T) {
	sequence := &callSequence{}
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})

	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	metadata := session.Metadata()
	if metadata.Status != StatusHostPrepared || !metadata.StructuralInspected || !metadata.TAPInspected ||
		!metadata.RulesInspected || metadata.RawPacketIsolationVerified {
		t.Fatalf("Prepare() metadata = %#v, want host-only prepared proof", metadata)
	}
	want := []string{
		"journal_acquire", "journal_save_proxy_starting", "proxy_start", "proxy_endpoint", "proxy_active",
		"journal_save_topology_starting", "topology_start", "topology_borrow", "journal_save_topology_prepared",
		"tap_create", "journal_save_tap_created", "tap_inspect", "proxy_active", "rules_apply_inspect",
		"journal_save_rules_inspected", "tap_inspect", "proxy_active",
	}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Prepare() sequence = %#v, want %#v", got, want)
	}
	sequence.reset()
	if _, err := session.Inspect(context.Background(), testIdentity()); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("Inspect() before guest readiness = %v, want ErrProofMismatch", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("Inspect() before guest readiness performed live work: %#v", got)
	}
}

func TestFirecrackerHostTopologyPostReadinessProofIsLiveBoundAndOrdered(t *testing.T) {
	sequence := &callSequence{}
	session := prepareHostTopologyForGuestProof(t, sequence)
	sequence.reset()

	ready := false
	binding := &fakeRunningGuestBinding{correlation: testCorrelation(), proofID: "guest-ready-proof-a", ready: &ready}
	verifier := &readinessGatedGuestVerifier{sequence: sequence, binding: binding}
	if _, err := session.InspectAfterGuestReady(context.Background(), testIdentity(), binding, verifier); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("InspectAfterGuestReady() before readiness = %v, want ErrProofMismatch", err)
	}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, []string{"guest_raw_packet_verify", "rules_quarantine", "journal_save_quarantined"}) {
		t.Fatalf("pre-readiness sequence = %#v", got)
	}
	if session.Metadata().Status != StatusQuarantined || session.Metadata().RawPacketIsolationVerified {
		t.Fatalf("pre-readiness metadata = %#v", session.Metadata())
	}

	sequence = &callSequence{}
	session = prepareHostTopologyForGuestProof(t, sequence)
	sequence.reset()
	ready = true
	binding = &fakeRunningGuestBinding{correlation: testCorrelation(), proofID: "guest-ready-proof-b", ready: &ready}
	verifier = &readinessGatedGuestVerifier{sequence: sequence, binding: binding}
	metadata, err := session.InspectAfterGuestReady(context.Background(), testIdentity(), binding, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Status != StatusInspected || !metadata.RawPacketIsolationVerified {
		t.Fatalf("post-readiness metadata = %#v", metadata)
	}
	want := []string{
		"guest_raw_packet_verify", "proxy_active", "tap_inspect", "rules_inspect",
		"tap_inspect", "proxy_active", "journal_save_inspected",
	}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("post-readiness sequence = %#v, want %#v", got, want)
	}
	sequence.reset()
	if _, err := session.Inspect(context.Background(), testIdentity()); err != nil {
		t.Fatal(err)
	}
	want = []string{"guest_raw_packet_verify", "proxy_active", "tap_inspect", "rules_inspect", "tap_inspect", "proxy_active"}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("repeat inspection sequence = %#v, want %#v", got, want)
	}
}

func TestFirecrackerHostTopologyPostReadinessDriftQuarantinesAndMismatchIsInert(t *testing.T) {
	sequence := &callSequence{}
	proxy := newFakeProxy(sequence)
	tap := &fakeTAP{sequence: sequence}
	rules := &fakeRules{sequence: sequence}
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: proxy, Topology: newFakeTopology(sequence), TAP: tap, Rules: rules,
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	sequence.reset()
	ready := true
	binding := &fakeRunningGuestBinding{correlation: testCorrelation(), proofID: "guest-ready-proof-c", ready: &ready}
	verifier := &readinessGatedGuestVerifier{sequence: sequence, binding: binding}

	mismatch := testIdentity()
	mismatch.RuleGenerationID = "other-rule-generation"
	if _, err := session.InspectAfterGuestReady(context.Background(), mismatch, binding, verifier); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("mismatched identity = %v", err)
	}
	badBinding := &fakeRunningGuestBinding{correlation: testCorrelation(), proofID: "guest-ready-proof-d", ready: &ready}
	badBinding.correlation.RuntimeID = "other-runtime-generation"
	if _, err := session.InspectAfterGuestReady(context.Background(), testIdentity(), badBinding, verifier); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("mismatched binding = %v", err)
	}
	if got := sequence.snapshot(); len(got) != 0 {
		t.Fatalf("mismatched request performed live work: %#v", got)
	}

	tap.inspectErr = errors.New("private TAP drift")
	if _, err := session.InspectAfterGuestReady(context.Background(), testIdentity(), binding, verifier); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("drift inspection = %v, want ErrProofMismatch", err)
	}
	want := []string{"guest_raw_packet_verify", "proxy_active", "tap_inspect", "rules_quarantine", "journal_save_quarantined"}
	if got := sequence.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("drift sequence = %#v, want %#v", got, want)
	}
}

func prepareHostTopologyForGuestProof(t *testing.T, sequence *callSequence) *Session {
	t.Helper()
	coordinator := mustCoordinator(t, Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	})
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

type fakeRunningGuestBinding struct {
	correlation networkenforcement.EnforcementCorrelation
	proofID     string
	ready       *bool
}

func (b *fakeRunningGuestBinding) GuestCorrelation() networkenforcement.EnforcementCorrelation {
	return b.correlation
}

func (b *fakeRunningGuestBinding) GuestReadinessProofID() string { return b.proofID }

type readinessGatedGuestVerifier struct {
	sequence *callSequence
	binding  *fakeRunningGuestBinding
}

func (v *readinessGatedGuestVerifier) VerifyRunningGuestRawPacketIsolation(
	_ context.Context,
	request RunningGuestRawPacketIsolationRequest,
) (networkenforcement.RawPacketIsolationProof, error) {
	v.sequence.add("guest_raw_packet_verify")
	binding, ok := request.Binding.(*fakeRunningGuestBinding)
	if !ok || binding != v.binding || request.ReadinessProofID != binding.proofID ||
		!networkenforcement.EnforcementCorrelationsEqual(request.Correlation, binding.correlation) ||
		binding.ready == nil || !*binding.ready {
		return networkenforcement.RawPacketIsolationProof{}, errors.New("guest not ready")
	}
	correlation := request.Correlation
	return networkenforcement.RawPacketIsolationProof{
		ID: "raw-proof-live-guest", Status: networkenforcement.RawPacketIsolationStatusVerified,
		VerifiedAtUnixMilli: 1000, Correlation: &correlation,
		ReasonCode: networkenforcement.LifecycleReasonRawPacketIsolationVerified,
	}, nil
}
