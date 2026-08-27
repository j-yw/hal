package l7network

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func recoveryStageRecord(identity Identity, stage journalStage) journalRecord {
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	return journalRecord{identity: identity, stage: stage, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), tapIfIndex: 41, proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
}

func TestFirecrackerHostTopologyRecoveryJournalStageExactOrderMatrix(t *testing.T) {
	identity := testIdentity()
	for _, test := range []struct {
		stage       journalStage
		recoverWant []string
		cleanupWant []string
	}{
		{stage: journalStageTAPCreated,
			recoverWant: []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow", "rules_quarantine", "journal_save_quarantined"},
			cleanupWant: []string{"rules_cleanup", "journal_save_rules_removed", "tap_delete", "journal_save_tap_removed", "topology_stop", "journal_save_topology_removed", "journal_remove", "journal_release"}},
		{stage: journalStageRulesInspected,
			recoverWant: []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow", "rules_quarantine", "journal_save_quarantined"},
			cleanupWant: []string{"rules_cleanup", "journal_save_rules_removed", "tap_delete", "journal_save_tap_removed", "topology_stop", "journal_save_topology_removed", "journal_remove", "journal_release"}},
		{stage: journalStageInspected,
			recoverWant: []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow", "rules_quarantine", "journal_save_quarantined"},
			cleanupWant: []string{"rules_cleanup", "journal_save_rules_removed", "tap_delete", "journal_save_tap_removed", "topology_stop", "journal_save_topology_removed", "journal_remove", "journal_release"}},
		{stage: journalStageQuarantined,
			recoverWant: []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow"},
			cleanupWant: []string{"rules_cleanup", "journal_save_rules_removed", "tap_delete", "journal_save_tap_removed", "topology_stop", "journal_save_topology_removed", "journal_remove", "journal_release"}},
		{stage: journalStageRulesRemoved,
			recoverWant: []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow"},
			cleanupWant: []string{"tap_delete", "journal_save_tap_removed", "topology_stop", "journal_save_topology_removed", "journal_remove", "journal_release"}},
		{stage: journalStageTAPRemoved,
			recoverWant: []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow"},
			cleanupWant: []string{"topology_stop", "journal_save_topology_removed", "journal_remove", "journal_release"}},
		{stage: journalStageTopologyRemoved,
			recoverWant: []string{"journal_acquire", "journal_load"},
			cleanupWant: []string{"journal_remove", "journal_release"}},
	} {
		t.Run(string(test.stage), func(t *testing.T) {
			sequence := &callSequence{}
			topology := newFakeTopology(sequence)
			reconciler, err := NewReconciler(ReconcilerOptions{
				Recovery: &fakeRecoveryTopology{sequence: sequence, lifecycle: topology},
				TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
				Journal:       &loadedJournalStore{sequence: sequence, record: recoveryStageRecord(identity, test.stage)},
			})
			if err != nil {
				t.Fatal(err)
			}
			session, err := reconciler.Recover(context.Background(), identity)
			if err != nil {
				t.Fatal(err)
			}
			if got := sequence.snapshot(); !reflect.DeepEqual(got, test.recoverWant) {
				t.Fatalf("Recover sequence = %#v, want %#v", got, test.recoverWant)
			}
			sequence.reset()
			if err := session.CleanupAfterVMQuiesced(context.Background(), identity, testTerminatedVMBinding()); err != nil {
				t.Fatal(err)
			}
			if got := sequence.snapshot(); !reflect.DeepEqual(got, test.cleanupWant) {
				t.Fatalf("Cleanup sequence = %#v, want %#v", got, test.cleanupWant)
			}
		})
	}
}

type recoveryRetryJournalStore struct {
	sequence    *callSequence
	record      journalRecord
	failStage   journalStage
	failRemove  bool
	failRelease bool
	lease       *recoveryRetryJournalLease
}

func (s *recoveryRetryJournalStore) Acquire(context.Context, Identity) (JournalLease, error) {
	s.sequence.add("journal_acquire")
	s.lease = &recoveryRetryJournalLease{sequence: s.sequence, record: s.record, failStage: s.failStage,
		failRemove: s.failRemove, failRelease: s.failRelease}
	return s.lease, nil
}

type recoveryRetryJournalLease struct {
	sequence      *callSequence
	record        journalRecord
	failStage     journalStage
	failRemove    bool
	failRelease   bool
	failedStage   bool
	failedRemove  bool
	failedRelease bool
}

func (l *recoveryRetryJournalLease) Load() (journalRecord, error) {
	l.sequence.add("journal_load")
	return l.record, nil
}
func (l *recoveryRetryJournalLease) Save(_ context.Context, record journalRecord) error {
	l.sequence.add("journal_save_" + string(record.stage))
	if record.stage == l.failStage && !l.failedStage {
		l.failedStage = true
		return errors.New("private journal save failure")
	}
	l.record = record
	return nil
}
func (l *recoveryRetryJournalLease) Remove() error {
	l.sequence.add("journal_remove")
	if l.failRemove && !l.failedRemove {
		l.failedRemove = true
		return errors.New("private journal remove failure")
	}
	return nil
}
func (l *recoveryRetryJournalLease) Release() error {
	l.sequence.add("journal_release")
	if l.failRelease && !l.failedRelease {
		l.failedRelease = true
		return errors.New("private journal release failure")
	}
	return nil
}

func TestFirecrackerHostTopologyRecoveryJournalRetryOrderMatrix(t *testing.T) {
	identity := testIdentity()
	for _, test := range []struct {
		name        string
		failStage   journalStage
		failRemove  bool
		failRelease bool
		mustRepeat  string
	}{
		{name: "quarantine save", failStage: journalStageQuarantined, mustRepeat: "journal_save_quarantined"},
		{name: "rules removed save", failStage: journalStageRulesRemoved, mustRepeat: "journal_save_rules_removed"},
		{name: "tap removed save", failStage: journalStageTAPRemoved, mustRepeat: "journal_save_tap_removed"},
		{name: "topology removed save", failStage: journalStageTopologyRemoved, mustRepeat: "journal_save_topology_removed"},
		{name: "journal remove", failRemove: true, mustRepeat: "journal_remove"},
		{name: "journal release", failRelease: true, mustRepeat: "journal_release"},
	} {
		t.Run(test.name, func(t *testing.T) {
			sequence := &callSequence{}
			store := &recoveryRetryJournalStore{sequence: sequence, record: recoveryStageRecord(identity, journalStageInspected),
				failStage: test.failStage, failRemove: test.failRemove, failRelease: test.failRelease}
			topology := newFakeTopology(sequence)
			reconciler, err := NewReconciler(ReconcilerOptions{
				Recovery: &fakeRecoveryTopology{sequence: sequence, lifecycle: topology},
				TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true}, Journal: store,
			})
			if err != nil {
				t.Fatal(err)
			}
			session, recoverErr := reconciler.Recover(context.Background(), identity)
			if test.failStage == journalStageQuarantined {
				if session == nil || !errors.Is(recoverErr, ErrCleanupIncomplete) {
					t.Fatalf("Recover(quarantine save failure) = %T, %v", session, recoverErr)
				}
				sequence.reset()
				if err := session.Quarantine(context.Background(), identity); err != nil {
					t.Fatalf("retry Quarantine() = %v", err)
				}
			} else {
				if recoverErr != nil {
					t.Fatal(recoverErr)
				}
				sequence.reset()
				if err := session.CleanupAfterVMQuiesced(context.Background(), identity, testTerminatedVMBinding()); !errors.Is(err, ErrCleanupIncomplete) {
					t.Fatalf("first Cleanup() = %v, want retained journal failure", err)
				}
				sequence.reset()
				if err := session.CleanupAfterVMQuiesced(context.Background(), identity, testTerminatedVMBinding()); err != nil {
					t.Fatalf("retry Cleanup() = %v", err)
				}
			}
			if countSequence(sequence.snapshot(), test.mustRepeat) != 1 {
				t.Fatalf("retry sequence = %#v, want exact retry of %q", sequence.snapshot(), test.mustRepeat)
			}
		})
	}
}

func countSequence(sequence []string, value string) int {
	count := 0
	for _, item := range sequence {
		if item == value {
			count++
		}
	}
	return count
}
