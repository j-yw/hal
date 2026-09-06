package l7network

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

type fixedMetadataRecoveryTopology struct {
	sequence  *callSequence
	lifecycle *fakeTopology
	metadata  linuxtopology.Metadata
}

func (r *fixedMetadataRecoveryTopology) Recover(context.Context, Identity) (TopologyLifecycle, TopologySession, error) {
	r.sequence.add("recovery_open")
	return r.lifecycle, &fixedMetadataRecoverySession{sequence: r.sequence, metadata: r.metadata}, nil
}

type fixedMetadataRecoverySession struct {
	sequence *callSequence
	metadata linuxtopology.Metadata
}

func (s *fixedMetadataRecoverySession) Metadata() linuxtopology.Metadata { return s.metadata }
func (*fixedMetadataRecoverySession) Losses() <-chan linuxtopology.Loss {
	losses := make(chan linuxtopology.Loss)
	close(losses)
	return losses
}
func (s *fixedMetadataRecoverySession) BorrowNamespace() (NamespaceLease, error) {
	s.sequence.add("topology_borrow")
	return &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, nil
}

func TestRecoveryTopologyMetadataMatchesMatrix(t *testing.T) {
	identity := testIdentity()
	exact := topologyIdentity(identity)
	wrong := exact
	wrong.ExecutionID = "execution-replaced"
	for _, test := range []struct {
		name     string
		metadata linuxtopology.Metadata
		accept   bool
	}{
		{name: "exact cleanup only", metadata: linuxtopology.Metadata{Identity: exact, Status: linuxtopology.StatusRecoveryOnly}, accept: true},
		{name: "prepared proof", metadata: linuxtopology.Metadata{Identity: exact, Status: linuxtopology.StatusPrepared, StructuralInspected: true, MappingReachable: true}},
		{name: "recovery structural proof", metadata: linuxtopology.Metadata{Identity: exact, Status: linuxtopology.StatusRecoveryOnly, StructuralInspected: true}},
		{name: "recovery reachability proof", metadata: linuxtopology.Metadata{Identity: exact, Status: linuxtopology.StatusRecoveryOnly, MappingReachable: true}},
		{name: "wrong status", metadata: linuxtopology.Metadata{Identity: exact, Status: linuxtopology.StatusCleanupIncomplete}},
		{name: "wrong identity", metadata: linuxtopology.Metadata{Identity: wrong, Status: linuxtopology.StatusRecoveryOnly}},
		{name: "zero identity", metadata: linuxtopology.Metadata{Status: linuxtopology.StatusRecoveryOnly}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sequence := &callSequence{}
			spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
			record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
				tapFingerprint: spec.fingerprint(), tapIfIndex: 41, proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
			lifecycle := newFakeTopology(sequence)
			reconciler, err := NewReconciler(ReconcilerOptions{
				Recovery: &fixedMetadataRecoveryTopology{sequence: sequence, lifecycle: lifecycle, metadata: test.metadata},
				TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
				Journal:       &loadedJournalStore{sequence: sequence, record: record},
			})
			if err != nil {
				t.Fatal(err)
			}
			session, recoverErr := reconciler.Recover(context.Background(), identity)
			if test.accept {
				if recoverErr != nil || session == nil || session.Metadata().Status != StatusQuarantined {
					t.Fatalf("Recover(exact cleanup metadata) = %T, %v", session, recoverErr)
				}
				return
			}
			if session != nil || !errors.Is(recoverErr, ErrStaleTopologyUnverified) {
				t.Fatalf("Recover(invalid recovery metadata) = %T, %v", session, recoverErr)
			}
			if contains(sequence.snapshot(), "topology_borrow") || contains(sequence.snapshot(), "rules_quarantine") {
				t.Fatalf("invalid recovery metadata authorized mutation: %#v", sequence.snapshot())
			}
		})
	}
}
